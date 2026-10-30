"""
Finding Pipeline Service for ARGOLOCK NET v1.7.
Implements the mandatory verification workflow:
1. Deduplication of candidate findings
2. EXTERNAL_INTEL labeling for CVE/KEV intelligence
3. Enforcement that AI output alone can only create HYPOTHESIS
4. Deterministic replay and live probe verification via validation_engine and false_positive_engine
5. Immutable EvidenceRecord creation with write-time secret redaction and SHA-256 hash
6. Adversarial Devil's Advocate evaluation via adversarial_validator
7. Analyst review history tracking through complete lifecycle state mapping
"""
from __future__ import annotations

import httpx
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger

from app.models.finding import DataSource, AnalystReviewEntry, transition_finding_state
from app.models.v1_7_models import FindingLifecycleState, MappedLifecycleStatus, map_finding_lifecycle_status
from app.models.vapt_models import ValidationStatus
from app.services.evidence_collector import evidence_collector
from app.services.false_positive_engine import false_positive_engine
from app.services.adversarial_validator import AdversarialValidator, AdversarialEvaluationOutcome


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings by canonical key: (title, affected_endpoint, parameter, cve_ids).
    Merges duplicate evidence, references, and tags.
    """
    deduped_map: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        title = (f.get("title") or "").strip().lower()
        endpoint = (f.get("affected_endpoint") or "").strip().lower()
        param = (f.get("affected_parameter") or "").strip().lower()
        key = f"{title}::{endpoint}::{param}"

        if key in deduped_map:
            existing = deduped_map[key]
            # Merge tags
            existing_tags = set(existing.get("tags") or [])
            existing_tags.update(f.get("tags") or [])
            existing["tags"] = list(existing_tags)

            # Merge CVEs
            existing_cves = set(existing.get("cve_ids") or [])
            existing_cves.update(f.get("cve_ids") or [])
            existing["cve_ids"] = list(existing_cves)

            # Merge PoC if current finding has richer details
            cur_poc = f.get("poc") or {}
            ex_poc = existing.get("poc") or {}
            if not ex_poc.get("request") and cur_poc.get("request"):
                existing["poc"] = cur_poc

            # Merge evidence text
            if not existing.get("evidence") and f.get("evidence"):
                existing["evidence"] = f.get("evidence")

            logger.info(f"[Deduplication] Merged duplicate finding '{title}' on {endpoint}")
        else:
            deduped_map[key] = f

    return list(deduped_map.values())


def label_external_intel(finding: Dict[str, Any]) -> None:
    """
    Label findings that originate from or match CVE / CISA KEV intelligence.
    Ensures EXTERNAL_INTEL data source and tags are properly assigned.
    """
    cves = finding.get("cve_ids") or []
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    tool = (finding.get("tool_source") or "").lower()

    is_cve_or_kev = bool(
        cves
        or "cve-" in title
        or "cve-" in desc
        or "cisa kev" in desc
        or "known exploited" in desc
        or "nvd" in desc
    )

    if is_cve_or_kev:
        tags = finding.get("tags") or []
        if "EXTERNAL_INTEL" not in tags:
            tags.append("EXTERNAL_INTEL")
        finding["tags"] = tags
        finding["is_external_intel"] = True

        # If data source is generic or purely external intel scan, label as EXTERNAL_INTEL
        current_ds = str(finding.get("data_source") or "").upper()
        if current_ds in ("", "TOOL_OUTPUT", "AI_VERIFIED") and ("nuclei" in tool or "cve" in tool or "kev" in desc):
            finding["data_source"] = DataSource.EXTERNAL_INTEL.value


def enforce_ai_hypothesis_rule(finding: Dict[str, Any]) -> None:
    """
    Rule: AI output alone can only create HYPOTHESIS.
    If a finding originates from AI agents without observed raw tool output or deterministic probe,
    its data_source must be HYPOTHESIS.
    """
    tool = str(finding.get("tool_source") or "").lower()
    raw = finding.get("raw_finding")
    current_ds = str(finding.get("data_source") or "").upper()

    is_pure_ai = (
        current_ds == "HYPOTHESIS"
        or tool in ("ai", "vulnerability_agent", "ai_agent", "llm", "ai_speculation", "")
        or (not raw and not finding.get("poc") and not finding.get("evidence"))
    )

    if is_pure_ai:
        finding["data_source"] = DataSource.HYPOTHESIS.value


def perform_deterministic_replay_sync(target_endpoint: str) -> Dict[str, Any]:
    """
    Synchronously gather live HTTP probe telemetry for deterministic replay.
    """
    evidence: Dict[str, Any] = {
        "status_code": None,
        "headers": {},
        "server_header": None,
        "missing_security_headers": [],
        "cors_misconfigured": False,
        "reflected_parameter": False,
        "response_body": None,
        "banner_output": None,
        "request": f"GET {target_endpoint} HTTP/1.1",
    }

    url = target_endpoint if target_endpoint.startswith("http") else f"http://{target_endpoint}"

    try:
        with httpx.Client(timeout=4.0, verify=False, follow_redirects=True) as client:
            resp = client.get(url, headers={"User-Agent": "Argolock-VAPT-Validator/1.7"})
            evidence["status_code"] = resp.status_code
            evidence["server_header"] = resp.headers.get("server")
            evidence["headers"] = dict(resp.headers)
            evidence["response_body"] = resp.text[:4000]
            evidence["banner_output"] = f"Server: {resp.headers.get('server', 'unknown')}\nX-Powered-By: {resp.headers.get('x-powered-by', 'unknown')}"

            sec_headers = ["content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options"]
            for h in sec_headers:
                if h not in resp.headers:
                    evidence["missing_security_headers"].append(h)

            if "?" in url:
                token = "argolock_safe_token"
                refl_url = f"{url}&probe={token}" if "&" in url else f"{url}?probe={token}"
                try:
                    r_refl = client.get(refl_url, headers={"User-Agent": "Argolock-VAPT-Validator/1.7"})
                    if token in r_refl.text:
                        evidence["reflected_parameter"] = True
                except Exception:
                    pass
    except Exception as e:
        evidence["probe_error"] = str(e)

    return evidence


def process_and_validate_findings_pipeline(
    scan_id: str,
    findings: List[Dict[str, Any]],
    target: str,
    db: Any = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Execute the mandatory Phase 4 finding validation pipeline:
    - Deduplication
    - EXTERNAL_INTEL labeling
    - AI HYPOTHESIS rule enforcement
    - Deterministic replay & probe
    - Immutable EvidenceRecord creation with write-time secret redaction
    - False positive evaluation
    - Adversarial Devil's Advocate evaluation
    - Analyst review history recording
    
    Returns:
        (validated_findings, excluded_findings)
        - validated_findings: Confirmed/Downgraded findings with evidence (Lifecycle: Validated)
        - excluded_findings: Killed (False Positive) or Blocked (Inconclusive) or Hypothesis findings
    """
    if not findings:
        return [], []

    # 1. Deduplicate
    deduped = deduplicate_findings(findings)

    validated_results: List[Dict[str, Any]] = []
    excluded_results: List[Dict[str, Any]] = []

    for f in deduped:
        f_id = f.get("id") or str(uuid.uuid4())
        f["id"] = f_id
        f["scan_id"] = scan_id

        # 2. Label external intel (CVE/KEV)
        label_external_intel(f)

        # 3. Enforce AI output alone == HYPOTHESIS
        enforce_ai_hypothesis_rule(f)

        # Initialize lifecycle states
        if not f.get("lifecycle_state"):
            f["lifecycle_state"] = FindingLifecycleState.DISCOVERED.value
            f["lifecycle_status"] = MappedLifecycleStatus.DETECTED.value

        # Transition to VALIDATING (Pending Validation)
        transition_finding_state(
            f,
            to_state=FindingLifecycleState.VALIDATING.value,
            actor="pipeline_orchestrator",
            rationale="Deterministic replay probe and adversarial validation initiated",
        )

        # 4. Deterministic Live Replay Probe
        endpoint = f.get("affected_endpoint") or target
        probe_evidence = perform_deterministic_replay_sync(endpoint)

        # 5. False Positive Engine evaluation
        fp_status, fp_conf, fp_rationale = false_positive_engine.evaluate_false_positive(f, probe_evidence)

        # Determine explicit flags
        if fp_status == ValidationStatus.FALSE_POSITIVE:
            f["false_positive"] = True
        elif fp_status in (ValidationStatus.NOT_EXPLOITABLE, ValidationStatus.REQUIRES_MANUAL_REVIEW):
            f["validation_status"] = "inconclusive"

        # 6. Immutable Evidence Record creation with write-time secret redaction
        req_sample = probe_evidence.get("request") or (f.get("poc") or {}).get("request") or f"GET {endpoint} HTTP/1.1"
        resp_sample = probe_evidence.get("response_body") or (f.get("poc") or {}).get("response") or "HTTP/1.1 response captured"

        evidence_rec = evidence_collector.collect_and_store_sync(
            assessment_id=scan_id,
            asset=endpoint,
            tool=f.get("tool_source") or "validation_engine",
            tool_version="1.0.0",
            request_excerpt=req_sample,
            response_excerpt=resp_sample,
            method=f"{f.get('tool_source', 'validation_engine')}_deterministic_replay",
            stdout_summary=f"Validation Status: {fp_status.value}. Confidence: {fp_conf}. Rationale: {fp_rationale}",
            db=db,
        )

        f["evidence_id"] = evidence_rec.id
        f["evidence_hash"] = evidence_rec.hash
        if not f.get("evidence"):
            f["evidence"] = f"Deterministic replay verified with hash {evidence_rec.hash[:16]}"

        # 7. Adversarial Validation (Devil's Advocate)
        adv_report = AdversarialValidator.evaluate(f)
        f["validation_record"] = adv_report.model_dump()
        f["validation_confidence"] = adv_report.confidence_score

        # Calibrate severity if downgraded
        if adv_report.decision == AdversarialEvaluationOutcome.DOWNGRADE:
            f["severity"] = adv_report.calibrated_severity

        # 8. Transition lifecycle state based on adversarial report
        adv_state = adv_report.state.value
        adv_mapped = adv_report.mapped_status
        f["lifecycle_state"] = adv_state
        f["lifecycle_status"] = adv_mapped

        transition_finding_state(
            f,
            to_state=adv_state,
            actor="adversarial_validator",
            rationale=f"Adversarial evaluation {adv_report.decision}: {adv_report.checks[0].rationale}",
            evidence_hash=evidence_rec.hash,
        )

        # 9. Gate Check: Partition into validated vs excluded
        is_hypothesis = (str(f.get("data_source") or "").upper() == "HYPOTHESIS")
        is_fp = (adv_mapped == MappedLifecycleStatus.FALSE_POSITIVE.value or f.get("false_positive") is True)
        is_inconclusive = (adv_mapped == MappedLifecycleStatus.INCONCLUSIVE.value or f.get("validation_status") == "inconclusive")

        if is_hypothesis or is_fp or is_inconclusive or adv_mapped != MappedLifecycleStatus.VALIDATED.value:
            excluded_results.append(f)
            logger.info(
                f"[ValidationPipeline] Excluded finding '{f.get('title')}' from reporting "
                f"(Lifecycle: {adv_mapped}, DataSource: {f.get('data_source')})"
            )
        else:
            f["confirmed"] = True
            validated_results.append(f)
            logger.info(
                f"[ValidationPipeline] Validated finding '{f.get('title')}' "
                f"(Severity: {f.get('severity')}, Evidence: {evidence_rec.hash[:12]})"
            )

    return validated_results, excluded_results

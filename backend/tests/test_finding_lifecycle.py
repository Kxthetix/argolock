"""Tests for ARGOLOCK NET Phase 4 Finding Lifecycle and Verification Pipeline.

Verifies:
1. Lifecycle state mapping:
   - DISCOVERED / CANDIDATE -> Detected
   - REPRODUCING / VALIDATING -> Pending Validation
   - VERIFIED / CONFIRMED / DOWNGRADED / REPORTED -> Validated
   - KILLED -> False Positive
   - BLOCKED -> Inconclusive
2. Immutable EvidenceRecord creation with write-time secret redaction and deterministic SHA-256 hash.
3. Mandatory validation pipeline:
   - Deduplication of findings
   - EXTERNAL_INTEL labeling for CVE/KEV intelligence
   - AI output alone flagged as HYPOTHESIS and killed without deterministic replay
   - Analyst review history recording
4. Gate: No finding reaches REPORTED without evidence and a validation record;
   tests cover false-positive and inconclusive paths.
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from app.models.finding import (
    Finding, DataSource, Severity, AnalystReviewEntry, transition_finding_state
)
from app.models.v1_7_models import (
    FindingLifecycleState, MappedLifecycleStatus, LIFECYCLE_MAPPING, map_finding_lifecycle_status
)
from app.models.vapt_models import EvidenceRecord
from app.services.evidence_collector import EvidenceCollector
from app.services.adversarial_validator import AdversarialValidator, AdversarialEvaluationOutcome
from app.services.finding_pipeline_service import (
    deduplicate_findings, label_external_intel, enforce_ai_hypothesis_rule,
    process_and_validate_findings_pipeline
)
from reports.pdf_generator import validate_and_filter_findings


# ─── 1. Lifecycle State Mapping Tests ─────────────────────────────────────────

def test_finding_lifecycle_mapping_all_states():
    """Verify exact lifecycle mapping required by Phase 4 specification."""
    # DISCOVERED / CANDIDATE -> Detected
    assert map_finding_lifecycle_status(FindingLifecycleState.DISCOVERED) == "Detected"
    assert map_finding_lifecycle_status(FindingLifecycleState.CANDIDATE) == "Detected"
    assert map_finding_lifecycle_status("DISCOVERED") == "Detected"
    assert map_finding_lifecycle_status("candidate") == "Detected"

    # REPRODUCING / VALIDATING -> Pending Validation
    assert map_finding_lifecycle_status(FindingLifecycleState.REPRODUCING) == "Pending Validation"
    assert map_finding_lifecycle_status(FindingLifecycleState.VALIDATING) == "Pending Validation"
    assert map_finding_lifecycle_status("reproducing") == "Pending Validation"
    assert map_finding_lifecycle_status("VALIDATING") == "Pending Validation"

    # VERIFIED / CONFIRMED / DOWNGRADED / REPORTED -> Validated
    assert map_finding_lifecycle_status(FindingLifecycleState.VERIFIED) == "Validated"
    assert map_finding_lifecycle_status(FindingLifecycleState.CONFIRMED) == "Validated"
    assert map_finding_lifecycle_status(FindingLifecycleState.DOWNGRADED) == "Validated"
    assert map_finding_lifecycle_status(FindingLifecycleState.REPORTED) == "Validated"
    assert map_finding_lifecycle_status("verified") == "Validated"
    assert map_finding_lifecycle_status("confirmed") == "Validated"
    assert map_finding_lifecycle_status("DOWNGRADED") == "Validated"
    assert map_finding_lifecycle_status("REPORTED") == "Validated"

    # KILLED -> False Positive
    assert map_finding_lifecycle_status(FindingLifecycleState.KILLED) == "False Positive"
    assert map_finding_lifecycle_status("killed") == "False Positive"

    # BLOCKED -> Inconclusive
    assert map_finding_lifecycle_status(FindingLifecycleState.BLOCKED) == "Inconclusive"
    assert map_finding_lifecycle_status("blocked") == "Inconclusive"


# ─── 2. Immutable Evidence Record & Secret Redaction ──────────────────────────

def test_evidence_record_schema_and_write_time_redaction():
    """Verify evidence record schema, secret redaction at write time, and SHA-256 hash."""
    collector = EvidenceCollector()

    raw_request = (
        "POST /api/v1/admin/auth HTTP/1.1\r\n"
        "Host: target.argolock.net\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload.signature\r\n"
        "Cookie: session_token=super_confidential_session_id_999\r\n\r\n"
        '{"api_key": "AKIA1234567890ABCDEF", "password": "ProductionDatabaseMasterPassword!2026"}'
    )
    raw_response = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session=new_token_777; Secure; HttpOnly\r\n\r\n"
        '{"status": "ok", "token": "sensitive_admin_jwt_token"}'
    )

    now = datetime.now(timezone.utc)
    mock_db = MagicMock()
    mock_db["evidence_records"].insert_one = MagicMock()

    evidence = collector.collect_and_store_sync(
        assessment_id="assess-phase4-001",
        asset="https://target.argolock.net/api/v1/admin/auth",
        tool="nuclei",
        tool_version="3.2.1",
        request_excerpt=raw_request,
        response_excerpt=raw_response,
        method="post_auth_probe",
        timestamp=now,
        db=mock_db,
    )

    # 1. Field validation
    assert evidence.assessment_id == "assess-phase4-001"
    assert evidence.asset == "https://target.argolock.net/api/v1/admin/auth"
    assert evidence.tool == "nuclei"
    assert evidence.tool_version == "3.2.1"
    assert evidence.method == "post_auth_probe"
    assert evidence.redaction_flag is True

    # 2. Secret Redaction at Write Time
    assert "ProductionDatabaseMasterPassword!2026" not in evidence.request_excerpt
    assert "AKIA1234567890ABCDEF" not in evidence.request_excerpt
    assert "eyJhbGci" not in evidence.request_excerpt
    assert "[REDACTED" in evidence.request_excerpt
    assert "[REDACTED_COOKIE]" in evidence.response_excerpt

    # 3. Deterministic SHA-256 Hash
    assert len(evidence.hash) == 64
    assert evidence.hash == evidence.sha256_hash
    assert collector.verify_integrity(evidence) is True

    # Tampering test
    tampered_evidence = evidence.model_copy()
    tampered_evidence.response_excerpt = "HTTP/1.1 500 Internal Server Error (Tampered)"
    assert collector.verify_integrity(tampered_evidence) is False


# ─── 3. Deduplication, External Intel & AI Hypothesis Rule ───────────────────

def test_deduplication_of_candidate_findings():
    """Verify duplicate findings are consolidated and tags/CVEs are merged."""
    findings = [
        {
            "title": "SQL Injection in Search",
            "affected_endpoint": "https://example.com/api/search",
            "affected_parameter": "q",
            "cve_ids": ["CVE-2023-1111"],
            "tags": ["sqli", "owasp-a03"],
            "tool_source": "nuclei",
        },
        {
            "title": "SQL Injection in Search",
            "affected_endpoint": "https://example.com/api/search",
            "affected_parameter": "q",
            "cve_ids": ["CVE-2023-2222"],
            "tags": ["high-risk", "cve"],
            "tool_source": "dalfox",
            "poc": {"request": "GET /api/search?q=' OR 1=1--"},
        },
    ]

    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1
    assert set(deduped[0]["tags"]) == {"sqli", "owasp-a03", "high-risk", "cve"}
    assert set(deduped[0]["cve_ids"]) == {"CVE-2023-1111", "CVE-2023-2222"}
    assert deduped[0]["poc"]["request"] == "GET /api/search?q=' OR 1=1--"


def test_external_intel_labeling():
    """Verify CVE and CISA KEV intelligence findings are explicitly tagged."""
    f1 = {
        "title": "Apache Struts RCE",
        "description": "Listed in CISA KEV catalog as actively exploited in the wild.",
        "cve_ids": ["CVE-2017-5638"],
        "tool_source": "nuclei-cve",
        "tags": ["rce"],
    }
    label_external_intel(f1)
    assert "EXTERNAL_INTEL" in f1["tags"]
    assert f1["data_source"] == DataSource.EXTERNAL_INTEL.value
    assert f1.get("is_external_intel") is True


def test_ai_hypothesis_rule_and_adversarial_kill():
    """AI output alone can only create HYPOTHESIS, which fails adversarial checks and gets KILLED."""
    f_speculative = {
        "title": "Potential Remote Code Execution via Deserialization",
        "description": "Theoretical deserialization path based on observed framework imports.",
        "tool_source": "vulnerability_agent",
        "severity": "critical",
        "affected_endpoint": "https://example.com/api/process",
        # Missing raw output and live proof
    }

    enforce_ai_hypothesis_rule(f_speculative)
    assert f_speculative["data_source"] == DataSource.HYPOTHESIS.value

    # Adversarial validation on pure hypothesis without live replay
    report = AdversarialValidator.evaluate(f_speculative)
    assert report.decision == AdversarialEvaluationOutcome.KILL
    assert report.state == FindingLifecycleState.KILLED
    assert report.mapped_status == MappedLifecycleStatus.FALSE_POSITIVE.value


# ─── 4. Analyst Review History & State Transitions ────────────────────────────

def test_analyst_review_history_tracking():
    """Verify transition_finding_state logs every transition in review_history with rationale and hash."""
    finding = Finding(
        scan_id="scan-123",
        title="Cross-Site Scripting (Reflected)",
        description="Reflected XSS in query parameter",
        severity=Severity.HIGH,
        affected_endpoint="https://example.com/search",
        tool_source="dalfox",
    )

    assert finding.lifecycle_state == "DISCOVERED"
    assert finding.lifecycle_status == "Detected"
    assert len(finding.review_history) == 0

    # 1. Pipeline initiates validation
    finding.transition_state(
        to_state="VALIDATING",
        actor="validation_engine",
        rationale="Deterministic replay probe initiated",
    )
    assert finding.lifecycle_state == "VALIDATING"
    assert finding.lifecycle_status == "Pending Validation"
    assert len(finding.review_history) == 1
    assert finding.review_history[0].from_state == "DISCOVERED"
    assert finding.review_history[0].to_state == "VALIDATING"
    assert finding.review_history[0].mapped_status == "Pending Validation"

    # 2. Adversarial Validator confirms
    fake_hash = "a" * 64
    finding.transition_state(
        to_state="CONFIRMED",
        actor="adversarial_validator",
        rationale="Payload execution corroborated by differential HTTP probe",
        evidence_hash=fake_hash,
    )
    assert finding.lifecycle_state == "CONFIRMED"
    assert finding.lifecycle_status == "Validated"
    assert len(finding.review_history) == 2
    assert finding.review_history[1].evidence_hash == fake_hash

    # 3. Report Agent publishes finding
    finding.transition_state(
        to_state="REPORTED",
        actor="report_agent",
        rationale="Included in final executive security report",
        evidence_hash=fake_hash,
    )
    assert finding.lifecycle_state == "REPORTED"
    assert finding.lifecycle_status == "Validated"
    assert len(finding.review_history) == 3


# ─── 5. Phase 4 Gate: No Finding Reaches REPORTED Without Evidence & Validation ──

def test_phase4_gate_rejects_findings_without_evidence_or_validation():
    """
    Gate: No finding reaches REPORTED without evidence and a validation record.
    Tests missing evidence, missing validation record, false-positive path, and inconclusive path.
    """
    fake_hash = "b" * 64

    # Case A: Finding has no evidence and no validation record -> REJECTED from REPORTED
    f_unvalidated = {
        "title": "SQL Injection in User Search",
        "tool_source": "nuclei",
        "affected_endpoint": "https://example.com/users",
        "severity": "high",
        # No evidence_id, evidence_hash, or validation_record
    }
    res_unvalidated = validate_and_filter_findings([f_unvalidated], require_validation_record=True)
    assert len(res_unvalidated) == 0

    # Case B: Finding has evidence but missing validation record -> REJECTED from REPORTED
    f_missing_val = {
        "title": "SQL Injection in User Search",
        "tool_source": "nuclei",
        "affected_endpoint": "https://example.com/users",
        "evidence_id": "ev-001",
        "evidence_hash": fake_hash,
        "severity": "high",
        # Missing validation_record
    }
    res_missing_val = validate_and_filter_findings([f_missing_val], require_validation_record=True)
    assert len(res_missing_val) == 0

    # Case C: False-Positive Path (KILLED / False Positive) -> EXCLUDED from REPORTED
    f_false_positive = {
        "title": "Git Repository Exposure",
        "tool_source": "httpx_probe",
        "affected_endpoint": "https://example.com/.git/config",
        "evidence_id": "ev-002",
        "evidence_hash": fake_hash,
        "validation_record": {"decision": "KILL", "checks": []},
        "lifecycle_state": "KILLED",
        "lifecycle_status": "False Positive",
        "false_positive": True,
        "severity": "high",
    }
    res_fp = validate_and_filter_findings([f_false_positive], require_validation_record=True)
    assert len(res_fp) == 0

    # Case D: Inconclusive Path (BLOCKED / 403 / Inconclusive) -> EXCLUDED from REPORTED
    f_inconclusive = {
        "title": "Admin Console Access",
        "tool_source": "httpx_probe",
        "affected_endpoint": "https://example.com/admin",
        "evidence": "HTTP GET returned 403 Forbidden - WAF Access Denied",
        "evidence_id": "ev-003",
        "evidence_hash": fake_hash,
        "validation_record": {"decision": "BLOCK", "checks": []},
        "lifecycle_state": "BLOCKED",
        "lifecycle_status": "Inconclusive",
        "validation_status": "inconclusive",
        "severity": "medium",
    }
    res_inc = validate_and_filter_findings([f_inconclusive], require_validation_record=True)
    assert len(res_inc) == 0
    # Must be marked inconclusive
    assert f_inconclusive["lifecycle_status"] == "Inconclusive"
    assert f_inconclusive["is_exposed"] is False

    # Case E: Validated Path with Evidence Record & Validation Record -> ADVANCES to REPORTED
    f_valid = {
        "title": "Reflected Cross-Site Scripting in Search Query",
        "tool_source": "dalfox",
        "affected_endpoint": "https://example.com/search?q=test",
        "evidence_id": "ev-004",
        "evidence_hash": fake_hash,
        "validation_record": {
            "decision": "PASS",
            "confidence_score": 0.95,
            "calibrated_severity": "high",
            "checks": [{"question": "Can it be reproduced?", "passed": True}],
        },
        "lifecycle_state": "CONFIRMED",
        "lifecycle_status": "Validated",
        "severity": "high",
        "data_source": "TOOL_OUTPUT",
        "confirmed": True,
    }
    res_valid = validate_and_filter_findings([f_valid], require_validation_record=True)
    assert len(res_valid) == 1
    reported_finding = res_valid[0]
    assert reported_finding["lifecycle_state"] == "REPORTED"
    assert reported_finding["lifecycle_status"] == "Validated"
    assert reported_finding["evidence_hash"] == fake_hash
    # Check that AnalystReviewEntry was recorded for REPORTED
    assert any(
        e.get("to_state") == "REPORTED" and e.get("mapped_status") == "Validated"
        for e in reported_finding.get("review_history", [])
    )


# ─── 6. Full Pipeline Integration Test ────────────────────────────────────────

def test_process_and_validate_findings_pipeline_integration():
    """Verify end-to-end processing of a mixed set of findings through the verification pipeline."""
    mock_db = MagicMock()
    mock_db["evidence_records"].insert_one = MagicMock()

    candidate_findings = [
        # Finding 1: Real validated finding with tool output
        {
            "title": "Missing Strict-Transport-Security Header",
            "description": "HSTS header is missing from web server response.",
            "tool_source": "httpx_probe",
            "severity": "low",
            "affected_endpoint": "127.0.0.1",
            "data_source": "TOOL_OUTPUT",
            "evidence": "Server: mock-server HTTP/1.1 200 OK without HSTS",
            "poc": {"request": "GET http://127.0.0.1 HTTP/1.1", "response": "HTTP/1.1 200 OK"},
        },
        # Finding 2: Pure AI speculative hypothesis without proof
        {
            "title": "Possible Remote Code Execution via Log4j",
            "description": "Hypothetical flaw speculated by LLM without scan evidence.",
            "tool_source": "vulnerability_agent",
            "severity": "critical",
            "affected_endpoint": "127.0.0.1",
            "data_source": "HYPOTHESIS",
        },
        # Finding 3: Blocked / 403 access control endpoint
        {
            "title": "Unauthorized Internal Metrics Endpoint",
            "description": "Probed metrics endpoint returned 403 Forbidden.",
            "tool_source": "httpx_probe",
            "severity": "high",
            "affected_endpoint": "127.0.0.1/metrics",
            "evidence": "403 Forbidden - Access Denied",
            "poc": {"request": "GET /metrics HTTP/1.1", "response": "HTTP/1.1 403 Forbidden"},
        },
    ]

    # Mock live probe response
    with patch("app.services.finding_pipeline_service.httpx.Client") as mock_client:
        mock_instance = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"server": "nginx"}
        mock_resp.text = "<html><body>Welcome</body></html>"
        mock_instance.__enter__.return_value = mock_instance
        mock_instance.get.return_value = mock_resp
        mock_client.return_value = mock_instance

        validated, excluded = process_and_validate_findings_pipeline(
            scan_id="scan-pipeline-test-01",
            findings=candidate_findings,
            target="127.0.0.1",
            db=mock_db,
        )

    # Finding 1 is validated
    assert len(validated) >= 1
    valid_f = next(f for f in validated if "Strict-Transport-Security" in f["title"])
    assert valid_f["lifecycle_status"] == "Validated"
    assert valid_f["evidence_id"] is not None
    assert valid_f["evidence_hash"] is not None
    assert valid_f["validation_record"] is not None
    assert len(valid_f["review_history"]) >= 2

    # Findings 2 and 3 are excluded
    assert len(excluded) >= 2
    excluded_titles = [f["title"] for f in excluded]
    assert any("Possible Remote Code Execution" in t for t in excluded_titles)
    assert any("Unauthorized Internal Metrics" in t for t in excluded_titles)

    hypo_f = next(f for f in excluded if "Remote Code Execution" in f["title"])
    assert hypo_f["lifecycle_status"] == "False Positive"
    assert hypo_f["lifecycle_state"] == "KILLED"

    block_f = next(f for f in excluded if "Unauthorized Internal Metrics" in f["title"])
    assert block_f["lifecycle_status"] == "Inconclusive"
    assert block_f["lifecycle_state"] == "BLOCKED"

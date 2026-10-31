"""
Evaluation Harness for ARGOLOCK NET v1.7.
Benchmarks security agent accuracy against labeled vulnerable and clean targets.
Measures:
1. Precision (>= 0.85)
2. Recall (>= 0.80)
3. False-Positive Rate (<= 0.10)
4. Hallucinated-Evidence Rate (== 0.0)
Records model, prompt, and policy versions in provenance metadata.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from loguru import logger

from app.models.finding import DataSource
from app.models.v1_7_models import FindingLifecycleState, MappedLifecycleStatus
from app.models.vapt_models import ValidationStatus
from app.services.adversarial_validator import AdversarialValidator, AdversarialEvaluationOutcome
from app.services.evidence_collector import evidence_collector
from app.services.false_positive_engine import false_positive_engine
from app.services.finding_pipeline_service import (
    enforce_ai_hypothesis_rule, label_external_intel
)
from reports.pdf_generator import validate_and_filter_findings


class BenchmarkTargetType(str, Enum):
    VULNERABLE = "vulnerable"
    CLEAN = "clean"
    FALSE_POSITIVE_TRAP = "false_positive_trap"
    HALLUCINATION_TRAP = "hallucination_trap"


class BenchmarkTestCase(BaseModel):
    id: str
    target_type: BenchmarkTargetType
    expected_vulnerable: bool
    candidate_finding: Dict[str, Any]
    probe_response: Dict[str, Any]


class EvaluationProvenance(BaseModel):
    eval_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    model_version: str = "gpt-4o-2024-11-20"
    prompt_version: str = "argolock-v1.7-prompts-v2"
    policy_version: str = "deterministic-policy-engine-v1.0"
    dataset_version: str = "argolock-labeled-benchmark-v1.0"


class EvaluationMetrics(BaseModel):
    total_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    false_positive_rate: float
    hallucinated_evidence_rate: float
    thresholds_met: bool


class EvaluationReport(BaseModel):
    provenance: EvaluationProvenance
    metrics: EvaluationMetrics
    case_results: List[Dict[str, Any]] = Field(default_factory=list)


class SecurityAgentEvalHarness:
    """Automated benchmark harness assessing detection precision, recall, and hallucination rates."""

    DEFAULT_BENCHMARK_SUITE: List[BenchmarkTestCase] = [
        # ── 1. Labeled Vulnerable Targets ────────────────────────────────────────
        BenchmarkTestCase(
            id="vuln-01-sqli",
            target_type=BenchmarkTargetType.VULNERABLE,
            expected_vulnerable=True,
            candidate_finding={
                "title": "SQL Injection in Search Query Parameter",
                "affected_endpoint": "http://benchmark.local/search?q=test",
                "affected_parameter": "q",
                "tool_source": "nuclei",
                "data_source": "TOOL_OUTPUT",
                "severity": "high",
                "poc": {"request": "GET /search?q=' OR 1=1-- HTTP/1.1", "response": "syntax error in SQL query"},
            },
            probe_response={
                "status_code": 200,
                "server_header": "nginx/1.24",
                "response_body": "syntax error in SQL query: unrecognized token near OR 1=1",
                "request": "GET /search?q=' OR 1=1-- HTTP/1.1",
            },
        ),
        BenchmarkTestCase(
            id="vuln-02-xss",
            target_type=BenchmarkTargetType.VULNERABLE,
            expected_vulnerable=True,
            candidate_finding={
                "title": "Reflected Cross-Site Scripting (XSS)",
                "affected_endpoint": "http://benchmark.local/view?msg=test",
                "affected_parameter": "msg",
                "tool_source": "dalfox",
                "data_source": "TOOL_OUTPUT",
                "severity": "medium",
                "poc": {"request": "GET /view?msg=<script>alert(1)</script> HTTP/1.1", "response": "<script>alert(1)</script>"},
            },
            probe_response={
                "status_code": 200,
                "reflected_parameter": True,
                "response_body": "<div>User message: <script>alert(1)</script></div>",
                "request": "GET /view?msg=argolock_safe_token HTTP/1.1",
            },
        ),
        BenchmarkTestCase(
            id="vuln-03-missing-hsts",
            target_type=BenchmarkTargetType.VULNERABLE,
            expected_vulnerable=True,
            candidate_finding={
                "title": "Missing Strict-Transport-Security Header",
                "affected_endpoint": "http://benchmark.local/api",
                "tool_source": "httpx_probe",
                "data_source": "TOOL_OUTPUT",
                "severity": "low",
                "poc": {"request": "GET /api HTTP/1.1", "response": "HTTP/1.1 200 OK"},
            },
            probe_response={
                "status_code": 200,
                "missing_security_headers": ["strict-transport-security", "content-security-policy"],
                "response_body": "API OK",
                "request": "GET /api HTTP/1.1",
            },
        ),
        BenchmarkTestCase(
            id="vuln-04-cve-intel",
            target_type=BenchmarkTargetType.VULNERABLE,
            expected_vulnerable=True,
            candidate_finding={
                "title": "Apache Log4j Remote Code Execution (Log4Shell)",
                "affected_endpoint": "http://benchmark.local/login",
                "tool_source": "nuclei-cve",
                "cve_ids": ["CVE-2021-44228"],
                "data_source": "TOOL_OUTPUT",
                "severity": "critical",
                "poc": {"request": "GET /login HTTP/1.1\r\nX-Api-Version: ${jndi:ldap://test}", "response": "DNS callback observed"},
            },
            probe_response={
                "status_code": 200,
                "server_header": "Apache-Coyote/1.1",
                "response_body": "Login page",
                "request": "GET /login HTTP/1.1",
            },
        ),

        # ── 2. Labeled Clean Targets ─────────────────────────────────────────────
        BenchmarkTestCase(
            id="clean-01-hardened-headers",
            target_type=BenchmarkTargetType.CLEAN,
            expected_vulnerable=False,
            candidate_finding={
                "title": "Missing Security Headers",
                "affected_endpoint": "https://secure.benchmark.local",
                "tool_source": "httpx_probe",
                "severity": "low",
                "poc": {"request": "GET / HTTP/1.1"},
            },
            probe_response={
                "status_code": 200,
                "missing_security_headers": [],  # All headers present
                "response_body": "All defensive headers present",
                "request": "GET / HTTP/1.1",
            },
        ),
        BenchmarkTestCase(
            id="clean-02-api-gateway",
            target_type=BenchmarkTargetType.CLEAN,
            expected_vulnerable=False,
            candidate_finding={
                "title": "CORS Wildcard Origin Reflection",
                "affected_endpoint": "https://secure.benchmark.local/api",
                "tool_source": "httpx_probe",
                "severity": "medium",
                "poc": {"request": "GET /api HTTP/1.1\r\nOrigin: https://evil.com"},
            },
            probe_response={
                "status_code": 200,
                "cors_misconfigured": False,
                "response_body": "OK",
                "request": "GET /api HTTP/1.1",
            },
        ),

        # ── 3. False Positive Traps ──────────────────────────────────────────────
        BenchmarkTestCase(
            id="fp-trap-01-404-backup",
            target_type=BenchmarkTargetType.FALSE_POSITIVE_TRAP,
            expected_vulnerable=False,
            candidate_finding={
                "title": "Exposed Database Backup File /backup.sql",
                "affected_endpoint": "http://benchmark.local/backup.sql",
                "tool_source": "scanner",
                "severity": "high",
                "poc": {"request": "GET /backup.sql HTTP/1.1"},
            },
            probe_response={
                "status_code": 404,  # Returns 404, not exposed
                "response_body": "404 Not Found",
                "request": "GET /backup.sql HTTP/1.1",
            },
        ),
        BenchmarkTestCase(
            id="fp-trap-02-waf-403",
            target_type=BenchmarkTargetType.FALSE_POSITIVE_TRAP,
            expected_vulnerable=False,
            candidate_finding={
                "title": "Admin Dashboard Exposed",
                "affected_endpoint": "http://benchmark.local/admin",
                "tool_source": "httpx_probe",
                "severity": "high",
                "evidence": "403 Forbidden - Access Denied by WAF",
                "poc": {"request": "GET /admin HTTP/1.1"},
            },
            probe_response={
                "status_code": 403,
                "response_body": "403 Forbidden",
                "request": "GET /admin HTTP/1.1",
            },
        ),
        BenchmarkTestCase(
            id="fp-trap-03-product-mismatch",
            target_type=BenchmarkTargetType.FALSE_POSITIVE_TRAP,
            expected_vulnerable=False,
            candidate_finding={
                "title": "Apache Tomcat Remote Code Execution",
                "affected_endpoint": "http://benchmark.local",
                "tool_source": "scanner",
                "severity": "critical",
                "poc": {"request": "GET / HTTP/1.1"},
            },
            probe_response={
                "status_code": 200,
                "server_header": "nginx/1.22.0",  # Product mismatch: server is Nginx, not Apache
                "banner_output": "Server: nginx",
                "response_body": "Welcome to nginx!",
                "request": "GET / HTTP/1.1",
            },
        ),

        # ── 4. Hallucination Traps ───────────────────────────────────────────────
        BenchmarkTestCase(
            id="hallucination-trap-01-ai-speculation",
            target_type=BenchmarkTargetType.HALLUCINATION_TRAP,
            expected_vulnerable=False,
            candidate_finding={
                "title": "Speculative Remote Code Execution via Insecure Deserialization",
                "description": "Pure LLM hallucination based on assumed architecture without tool proof.",
                "affected_endpoint": "http://benchmark.local/api/eval",
                "tool_source": "vulnerability_agent",
                "data_source": "HYPOTHESIS",
                "severity": "critical",
                # No PoC request/response, fabricated finding
            },
            probe_response={
                "status_code": 200,
                "response_body": "normal response",
                "request": "GET /api/eval HTTP/1.1",
            },
        ),
    ]

    def evaluate_case(self, test_case: BenchmarkTestCase) -> Dict[str, Any]:
        """Process a benchmark test case through the full verification and reporting gate."""
        f = test_case.candidate_finding.copy()
        probe = test_case.probe_response

        # Step 1: Label external intel
        label_external_intel(f)

        # Step 2: Enforce AI hypothesis rule
        enforce_ai_hypothesis_rule(f)

        # Step 3: False Positive Engine evaluation
        fp_status, fp_conf, fp_rationale = false_positive_engine.evaluate_false_positive(f, probe)
        if fp_status == ValidationStatus.FALSE_POSITIVE:
            f["false_positive"] = True
        elif fp_status in (ValidationStatus.NOT_EXPLOITABLE, ValidationStatus.REQUIRES_MANUAL_REVIEW):
            f["validation_status"] = "inconclusive"

        # Step 4: Evidence Record creation (or simulation of missing evidence for hallucinations)
        has_hallucinated_evidence = False
        is_hypothesis = (str(f.get("data_source") or "").upper() == "HYPOTHESIS")

        if not is_hypothesis and test_case.target_type != BenchmarkTargetType.HALLUCINATION_TRAP:
            # Generate immutable evidence record
            ev = evidence_collector._prepare_evidence_record(
                assessment_id=f"eval-{test_case.id}",
                asset=f.get("affected_endpoint", "http://benchmark.local"),
                tool=f.get("tool_source", "eval_tool"),
                tool_version="1.0.0",
                request_excerpt=probe.get("request") or (f.get("poc") or {}).get("request"),
                response_excerpt=probe.get("response_body") or (f.get("poc") or {}).get("response"),
                method="eval_probe",
            )
            f["evidence_id"] = ev.id
            f["evidence_hash"] = ev.hash
            f["evidence"] = f"Corroborated by probe (hash={ev.hash[:12]})"
        else:
            # Hallucinated / speculative finding lacks valid evidence record
            has_hallucinated_evidence = True

        # Step 5: Adversarial Devil's Advocate evaluation
        adv_report = AdversarialValidator.evaluate(f)
        f["validation_record"] = adv_report.model_dump()
        f["lifecycle_state"] = adv_report.state.value
        f["lifecycle_status"] = adv_report.mapped_status

        # Step 6: Phase 4 & 5 Quality Gate Check
        reported_findings = validate_and_filter_findings([f], require_validation_record=True)
        is_reported = len(reported_findings) > 0

        # Outcome determination
        tp = (test_case.expected_vulnerable and is_reported)
        fp = (not test_case.expected_vulnerable and is_reported)
        tn = (not test_case.expected_vulnerable and not is_reported)
        fn = (test_case.expected_vulnerable and not is_reported)

        # Check for hallucinated evidence in any finding that slipped into reported
        hallucinated_in_reported = (is_reported and has_hallucinated_evidence)

        return {
            "case_id": test_case.id,
            "target_type": test_case.target_type.value,
            "expected_vulnerable": test_case.expected_vulnerable,
            "is_reported": is_reported,
            "lifecycle_state": f.get("lifecycle_state"),
            "lifecycle_status": f.get("lifecycle_status"),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "has_hallucinated_evidence": has_hallucinated_evidence,
            "hallucinated_in_reported": hallucinated_in_reported,
        }

    def run_benchmark(
        self,
        custom_suite: Optional[List[BenchmarkTestCase]] = None,
        model_version: str = "gpt-4o-2024-11-20",
        prompt_version: str = "argolock-v1.7-prompts-v2",
        policy_version: str = "deterministic-policy-engine-v1.0",
    ) -> EvaluationReport:
        """
        Execute full benchmark suite, compute precision/recall/FPR/hallucination metrics,
        and record model/prompt/policy provenance.
        """
        suite = custom_suite or self.DEFAULT_BENCHMARK_SUITE
        case_results = [self.evaluate_case(tc) for tc in suite]

        total = len(case_results)
        tp = sum(1 for r in case_results if r["tp"])
        fp = sum(1 for r in case_results if r["fp"])
        tn = sum(1 for r in case_results if r["tn"])
        fn = sum(1 for r in case_results if r["fn"])

        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
        fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

        hallucinated_count = sum(1 for r in case_results if r["hallucinated_in_reported"])
        hallucinated_rate = round(hallucinated_count / total, 4) if total > 0 else 0.0

        thresholds_met = (
            precision >= 0.85
            and recall >= 0.80
            and fpr <= 0.10
            and hallucinated_rate == 0.0
        )

        metrics = EvaluationMetrics(
            total_cases=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            false_positive_rate=fpr,
            hallucinated_evidence_rate=hallucinated_rate,
            thresholds_met=thresholds_met,
        )

        provenance = EvaluationProvenance(
            model_version=model_version,
            prompt_version=prompt_version,
            policy_version=policy_version,
        )

        logger.info(
            f"[EvalHarness] Benchmark complete: Precision={precision:.2f}, Recall={recall:.2f}, "
            f"FPR={fpr:.2f}, Hallucination={hallucinated_rate:.2f}, Met={thresholds_met}"
        )

        return EvaluationReport(
            provenance=provenance,
            metrics=metrics,
            case_results=case_results,
        )


# Global evaluation harness singleton
eval_harness = SecurityAgentEvalHarness()

"""
Unit and Integration Tests for Phase 6 Deliverables:
1. Versioned, Explainable Risk Model (v2.0.0) with stored provenance figures and uncertainty ranges.
2. Investment Optimizer audited with user costs, uncertainty intervals, and no savings claims.
3. MITRE ATT&CK Mapping grounded strictly in empirical evidence.
4. Remediation Tasks & Retest Engine with risk reduction computed ONLY from verified RESOLVED retests using the original method.
5. Longitudinal Assessment Trend Views with MTTR calculation.
6. Gate: The Four Core Business Questions answerable from stored data with sources and assumptions visible.
"""
from __future__ import annotations

import pytest
import uuid
from datetime import datetime, timezone, timedelta

from app.models.v1_7_models import (
    FigureOrigin,
    RemediationPriority,
    RemediationTaskStatus,
)
from app.models.vapt_models import RetestStatus, ValidationStatus
from app.services.cyber_risk_service import CyberRiskEngine
from app.services.investment_optimizer_service import InvestmentOptimizer
from app.services.attack_path_engine import attack_path_engine
from app.services.remediation_retest_engine import RemediationRetestEngine
from app.services.trend_service import TrendService
from app.services.business_questions_service import BusinessQuestionsService


# ─── Mock Database Helper ───────────────────────────────────────────────────────

class InMemoryCollection:
    def __init__(self, data=None):
        self.data = list(data or [])

    async def find_one(self, query, projection=None):
        for item in self.data:
            match = True
            for k, v in query.items():
                if k == "$or":
                    match = any(self._eval_subquery(item, sub) for sub in v)
                elif item.get(k) != v:
                    match = False
                    break
            if match:
                return dict(item)
        return None

    def _eval_subquery(self, item, sub):
        for k, v in sub.items():
            if isinstance(v, dict) and "$regex" in v:
                val = str(item.get(k, ""))
                if v["$regex"].lower() not in val.lower():
                    return False
            elif item.get(k) != v:
                return False
        return True

    def find(self, query=None, projection=None):
        query = query or {}
        results = []
        for item in self.data:
            match = True
            for k, v in query.items():
                if k == "$or":
                    match = any(self._eval_subquery(item, sub) for sub in v)
                elif isinstance(v, dict) and "$regex" in v:
                    val = str(item.get(k, ""))
                    if v["$regex"].lower() not in val.lower():
                        match = False
                        break
                elif item.get(k) != v:
                    match = False
                    break
            if match:
                results.append(dict(item))
        return InMemoryCursor(results)

    async def insert_one(self, doc):
        self.data.append(dict(doc))
        return doc

    async def update_one(self, query, update):
        for item in self.data:
            match = all(item.get(k) == v for k, v in query.items())
            if match:
                if "$set" in update:
                    item.update(update["$set"])
                return {"matched": 1, "modified": 1}
        return {"matched": 0, "modified": 0}

    async def update_many(self, query, update):
        matched = 0
        for item in self.data:
            match = all(item.get(k) == v for k, v in query.items())
            if match:
                matched += 1
                if "$set" in update:
                    item.update(update["$set"])
                if "$addToSet" in update:
                    for field, val in update["$addToSet"].items():
                        if field not in item:
                            item[field] = []
                        if val not in item[field]:
                            item[field].append(val)
        return {"matched": matched}


class InMemoryCursor:
    def __init__(self, data):
        self._data = list(data)

    def sort(self, key, direction=1):
        try:
            self._data.sort(key=lambda x: x.get(key, ""), reverse=(direction == -1))
        except Exception:
            pass
        return self

    def limit(self, count):
        self._data = self._data[:count]
        return self

    async def to_list(self, length=None):
        if length is not None:
            return self._data[:length]
        return self._data


class MockDB:
    def __init__(self):
        self.collections = {}

    def __getitem__(self, name):
        if name not in self.collections:
            self.collections[name] = InMemoryCollection()
        return self.collections[name]


# ─── 1. Explainable Risk Model Tests ────────────────────────────────────────────

def test_explainable_risk_model_version_and_stored_inputs():
    """Verify explainable risk model outputs version 2.0.0 and stores all 6 provenance-tagged inputs."""
    findings = [
        {
            "id": "f-1",
            "title": "SQL Injection in User Endpoint",
            "severity": "critical",
            "cvss_score": 9.2,
            "confirmed": True,
            "confidence": 0.95,
        },
        {
            "id": "f-2",
            "title": "Insecure Direct Object Reference (IDOR)",
            "severity": "high",
            "cvss_score": 7.5,
            "confirmed": True,
            "confidence": 0.90,
        },
    ]

    risk = CyberRiskEngine.calculate_scan_risk(
        scan_id="scan-exp-1",
        findings=findings,
        asset_criticality=1.6,
        exposure_factor=1.4,
        threat_relevance=1.2,
        existing_controls_discount=0.15,
        hourly_downtime_cost_usd=8000.0,
    )

    assert risk.risk_model_version == "2.0.0"
    assert 0.0 <= risk.score <= 100.0
    assert risk.controls_discount == 0.15

    # Check 6 explicit inputs stored with each score
    stored_inputs = risk.inputs
    expected_keys = ["cvss", "asset_criticality", "exposure", "exploit_evidence", "evidence_confidence", "existing_controls"]
    for k in expected_keys:
        assert k in stored_inputs
        assert stored_inputs[k].origin in [FigureOrigin.OBSERVED, FigureOrigin.ASSUMED, FigureOrigin.MODELED]
        assert stored_inputs[k].source != ""

    assert stored_inputs["cvss"].origin == FigureOrigin.OBSERVED
    assert stored_inputs["asset_criticality"].origin == FigureOrigin.ASSUMED
    assert stored_inputs["asset_criticality"].value == 1.6
    assert stored_inputs["exploit_evidence"].origin == FigureOrigin.OBSERVED
    assert stored_inputs["exploit_evidence"].value == 1.0  # 2/2 confirmed
    assert stored_inputs["existing_controls"].value == 0.15

    # Uncertainty range verification
    unc = risk.uncertainty_range
    assert unc["min_score"] <= unc["expected_score"] <= unc["max_score"]
    assert unc["confidence_interval"] == 0.90
    assert unc["figure_origin"] == FigureOrigin.MODELED.value

    # Loss exposure verification (user-supplied downtime cost)
    loss = risk.loss_exposure
    assert loss["hourly_downtime_cost_usd"] == 8000.0
    assert loss["min_usd"] < loss["expected_usd"] < loss["max_usd"]
    assert loss["figure_origins"]["hourly_downtime_cost_usd"] == FigureOrigin.ASSUMED.value
    assert loss["figure_origins"]["loss_usd_range"] == FigureOrigin.MODELED.value


def test_empty_findings_risk_score():
    """Verify empty scan yields 0.0 score without crashing and documents zero loss."""
    risk = CyberRiskEngine.calculate_scan_risk("scan-empty", [])
    assert risk.score == 0.0
    assert risk.rating == "INFORMATIONAL"
    assert risk.loss_exposure["expected_usd"] == 0.0
    assert "cvss" in risk.inputs


# ─── 2. Investment Optimizer Audit & No Savings Claims ─────────────────────────

def test_investment_optimizer_costs_and_no_savings():
    """Verify investment optimizer uses user hourly rate, shows uncertainty ranges, and makes no savings claims."""
    findings = [
        {"id": "f-1", "title": "SQL Injection in User Search", "severity": "critical"},
        {"id": "f-2", "title": "Insecure Direct Object Reference", "severity": "high"},
        {"id": "f-3", "title": "Missing DMARC Record", "severity": "medium"},
    ]

    user_rate = 175.0
    plan = InvestmentOptimizer.generate_plan(
        scan_id="scan-inv-test",
        initial_risk_score=85.0,
        findings=findings,
        user_hourly_rate=user_rate,
        hourly_downtime_cost_usd=6000.0,
    )

    assert plan.user_hourly_rate == 175.0
    assert plan.projected_residual_risk < plan.initial_risk_score
    assert plan.total_risk_reduction > 0

    # Verify uncertainty ranges on total effort and costs
    assert plan.total_effort_range["min_hours"] < plan.total_effort_range["expected_hours"] < plan.total_effort_range["max_hours"]
    assert plan.total_cost_range["min_usd"] == round(plan.total_effort_range["min_hours"] * user_rate, 2)
    assert plan.total_cost_range["expected_usd"] == round(plan.total_effort_range["expected_hours"] * user_rate, 2)
    assert plan.total_cost_range["max_usd"] == round(plan.total_effort_range["max_hours"] * user_rate, 2)

    # Strictly NO savings claims: verify notice disclaims financial savings
    assert "No direct financial savings claimed" in plan.savings_claim_notice
    assert "loss_reduction" not in plan.savings_claim_notice.lower() or "modeled" in plan.savings_claim_notice.lower()
    for a in plan.actions:
        assert a.user_hourly_rate == user_rate
        assert a.cost_range["min_cost_usd"] < a.cost_range["expected_cost_usd"] < a.cost_range["max_cost_usd"]
        assert a.figure_provenance["cost_range"] == FigureOrigin.MODELED
        assert a.figure_provenance["user_hourly_rate"] == FigureOrigin.ASSUMED


# ─── 3. Ground MITRE ATT&CK Mapping in Evidence ─────────────────────────────────

def test_mitre_mapping_rejects_hypothesis_and_missing_evidence():
    """Verify MITRE ATT&CK mapping rejects HYPOTHESIS and findings lacking technical proof."""
    # 1. Speculative HYPOTHESIS is rejected
    hypothesis_finding = {
        "id": "f-hypo",
        "title": "SQL Injection in Search Query",
        "source_type": "HYPOTHESIS",
        "affected_endpoint": "https://target.com/search",
        "evidence": "Speculative AI conjecture",
    }
    mapping_hypo = attack_path_engine.map_mitre(hypothesis_finding)
    assert mapping_hypo is None

    # 2. Finding lacking evidence is rejected when evidence is required
    unsupported_finding = {
        "id": "f-no-proof",
        "title": "Remote Code Execution via File Upload",
        "source_type": "REAL",
        "affected_endpoint": "https://target.com/upload",
        # No evidence_id, evidence_hash, evidence, or poc
    }
    mapping_unsupported = attack_path_engine.map_finding_to_mitre(unsupported_finding)
    assert mapping_unsupported is None

    # 3. Finding with empirical technical proof succeeds
    verified_finding = {
        "id": "f-verified",
        "title": "SQL Injection in Search Query",
        "source_type": "OBSERVED",
        "affected_endpoint": "https://target.com/search",
        "evidence": "HTTP 500 with MariaDB syntax error payload returned",
        "evidence_hash": "sha256-abc123456789",
        "poc": {"payload": "' OR 1=1 --"},
    }
    mapping_valid = attack_path_engine.map_finding_to_mitre(verified_finding)
    assert mapping_valid is not None
    assert mapping_valid.technique_id == "T1190"
    assert mapping_valid.confidence >= 0.90


def test_mitre_mapping_rejects_unknown_patterns_without_speculative_fallback():
    """Verify that unclassified patterns are not assigned speculative fallback techniques."""
    unknown_finding = {
        "id": "f-unknown",
        "title": "Obscure Unmatched Architecture Anomaly",
        "evidence": "Raw hex 0xdeadbeef",
    }
    mapping = attack_path_engine.map_mitre(unknown_finding)
    assert mapping is None


# ─── 4. Remediation Tasks & Retest Engine ───────────────────────────────────────

@pytest.mark.asyncio
async def test_remediation_task_creation_and_retest_verified_reduction():
    """Verify remediation task workflow and risk reduction computation ONLY on verified RESOLVED retest."""
    mock_db = MockDB()

    finding = {
        "id": "f-task-1",
        "scan_id": "scan-100",
        "title": "SQL Injection in User Search",
        "severity": "critical",
        "cvss_score": 9.5,
        "affected_endpoint": "https://api.example.com/search",
        "tool": "sqlmap_adapter",
        "evidence_id": "ev-100",
        "confirmed": True,
    }
    await mock_db["findings"].insert_one(finding)

    engine = RemediationRetestEngine(db_getter=lambda: mock_db)

    # 1. Create remediation task
    task = await engine.create_remediation_task(
        finding=finding,
        scan_id="scan-100",
        user_hourly_rate=150.0,
        assignee="alice@security.org",
        priority=RemediationPriority.P1,
        sla_days=7,
    )

    assert task.status == RemediationTaskStatus.PENDING
    assert task.original_test_method == "sqlmap_adapter"
    assert task.verified_risk_reduction == 0.0  # Zero initially
    assert task.estimated_cost_range["expected"] == 12 * 150.0

    # 2. Mock execute_retest where finding is STILL_VULNERABLE -> risk reduction must be 0.0
    from unittest.mock import patch, AsyncMock

    with patch("app.services.remediation_retest_engine.validation_engine.validate_finding", new_callable=AsyncMock) as mock_val:
        mock_val.return_value = {
            "validation_status": "confirmed",
            "confirmed": True,
            "evidence_hash": "hash-still-vulnerable",
        }

        retest_fail = await engine.execute_retest("f-task-1", actor="alice")
        assert retest_fail.retest_status == RetestStatus.STILL_VULNERABLE
        assert retest_fail.verified_risk_reduction == 0.0

        refreshed_task_fail = await engine.get_remediation_task(task.id)
        assert refreshed_task_fail.status == RemediationTaskStatus.REOPENED
        assert refreshed_task_fail.verified_risk_reduction == 0.0

    # 3. Mock execute_retest where finding is RESOLVED -> risk reduction strictly awarded
    with patch("app.services.remediation_retest_engine.validation_engine.validate_finding", new_callable=AsyncMock) as mock_val_success:
        mock_val_success.return_value = {
            "validation_status": "not_exploitable",
            "confirmed": False,
            "evidence_hash": "hash-secure-response",
        }

        retest_success = await engine.execute_retest("f-task-1", actor="alice")
        assert retest_success.retest_status == RetestStatus.RESOLVED
        assert retest_success.verified_risk_reduction > 0.0

        refreshed_task_success = await engine.get_remediation_task(task.id)
        assert refreshed_task_success.status == RemediationTaskStatus.RESOLVED
        assert refreshed_task_success.verified_risk_reduction == retest_success.verified_risk_reduction


# ─── 5. Assessment Trends & MTTR ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_assessment_trend_view_and_mttr():
    """Verify trend service computes chronological history, MTTR, and verified risk reduction."""
    mock_db = MockDB()

    # Seed 2 historical scans
    t0 = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    t1 = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    t1_resolved = datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")  # 48 hours later

    await mock_db["scans"].insert_one({"id": "scan-1", "target": "api.example.com", "created_at": t0})
    await mock_db["scans"].insert_one({"id": "scan-2", "target": "api.example.com", "created_at": t1})

    # Scan 1 finding
    await mock_db["findings"].insert_one({
        "id": "f-1", "scan_id": "scan-1", "title": "SQLi", "severity": "critical", "confirmed": True, "created_at": t0
    })

    # Scan 2 finding (resolved)
    await mock_db["findings"].insert_one({
        "id": "f-2",
        "scan_id": "scan-2",
        "title": "SQLi Fixed",
        "severity": "critical",
        "retest_status": "resolved",
        "validation_status": "not_exploitable",
        "verified_risk_reduction": 20.0,
        "created_at": t1,
        "resolved_at": t1_resolved,
    })

    trend_svc = TrendService(db_getter=lambda: mock_db)
    trend_view = await trend_svc.get_target_trend_view("api.example.com")

    assert trend_view.target == "api.example.com"
    assert len(trend_view.history_points) == 2
    assert trend_view.total_verified_risk_reduction == 20.0
    assert trend_view.mttr_hours_average == 48.0
    assert trend_view.posture_trend_direction in ["improving", "stable", "deteriorating"]
    assert "sources" in trend_view.data_provenance


# ─── 6. Phase 6 Gate: Four Core Business Questions ─────────────────────────────

@pytest.mark.asyncio
async def test_gate_four_business_questions_answerable_with_sources_and_assumptions():
    """
    Gate: All four business questions in the master doc are answerable from stored data
    with sources and assumptions visible.
    - Q1: Current cyber risk exposure and financial loss range.
    - Q2: Most critical verified vulnerabilities and attack paths to crown jewels.
    - Q3: Prioritized remediation investment with user costs, uncertainty ranges, and no savings claims.
    - Q4: Historical risk posture trend, MTTR, and verified risk reduction over time.
    """
    mock_db = MockDB()

    scan_id = "scan-gate-ph6"
    target = "https://checkout.enterprise.com"
    t_now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    await mock_db["scans"].insert_one({
        "id": scan_id,
        "target": target,
        "scope": {"target": target},
        "created_at": t_now,
    })

    finding_1 = {
        "id": "f-gate-1",
        "scan_id": scan_id,
        "title": "SQL Injection in Checkout Form",
        "severity": "critical",
        "cvss_score": 9.4,
        "source_type": "OBSERVED",
        "affected_endpoint": f"{target}/pay",
        "evidence": "Extracted database banner MariaDB 10.6",
        "evidence_hash": "hash-proof-sqli",
        "poc": {"payload": "' OR 1=1 --"},
        "confirmed": True,
    }
    finding_2 = {
        "id": "f-gate-2",
        "scan_id": scan_id,
        "title": "Insecure Direct Object Reference (IDOR)",
        "severity": "high",
        "cvss_score": 7.8,
        "source_type": "OBSERVED",
        "affected_endpoint": f"{target}/orders/99",
        "evidence": "Accessed unauthorized order profile",
        "evidence_hash": "hash-proof-idor",
        "poc": {"payload": "GET /orders/99"},
        "confirmed": True,
    }
    await mock_db["findings"].insert_one(finding_1)
    await mock_db["findings"].insert_one(finding_2)

    svc = BusinessQuestionsService(db_getter=lambda: mock_db)

    # ── Q1 Check: Current cyber risk exposure & loss range ─────────────────────
    q1 = await svc.answer_question_1_current_risk(
        scan_id=scan_id,
        asset_criticality=1.8,
        hourly_downtime_cost_usd=10000.0,
    )
    assert q1["question_id"] == "Q1"
    assert q1["cyber_risk_score"]["score"] > 0
    assert q1["financial_loss_exposure"]["hourly_downtime_cost_usd"] == 10000.0
    assert q1["financial_loss_exposure"]["min_usd"] < q1["financial_loss_exposure"]["expected_usd"]
    assert len(q1["sources"]) > 0
    assert len(q1["assumptions"]) > 0
    assert q1["figure_provenance"]["calibrated_score"] == FigureOrigin.MODELED.value
    assert q1["figure_provenance"]["asset_criticality"] == FigureOrigin.ASSUMED.value

    # ── Q2 Check: Most critical verified vulnerabilities & attack paths ────────
    q2 = await svc.answer_question_2_critical_attack_paths(
        scan_id=scan_id,
        target=target,
    )
    assert q2["question_id"] == "Q2"
    assert q2["total_verified_findings_count"] == 2
    assert len(q2["critical_verified_vulnerabilities"]) > 0
    assert len(q2["crown_jewels"]) > 0
    assert len(q2["sources"]) > 0
    assert len(q2["assumptions"]) > 0
    # Technical proof must be attached
    top_vuln = q2["critical_verified_vulnerabilities"][0]
    assert top_vuln["evidence"] != ""
    assert "mitre_technique" in top_vuln

    # ── Q3 Check: Prioritized remediation investment & NO savings claims ───────
    q3 = await svc.answer_question_3_prioritized_investments(
        scan_id=scan_id,
        user_hourly_rate=140.0,
        hourly_downtime_cost_usd=10000.0,
    )
    assert q3["question_id"] == "Q3"
    assert q3["user_hourly_rate"] == 140.0
    assert len(q3["prioritized_actions"]) > 0
    assert q3["total_cost_range_usd"]["min_usd"] < q3["total_cost_range_usd"]["max_usd"]
    assert q3["total_effort_range_hours"]["min_hours"] < q3["total_effort_range_hours"]["max_hours"]
    assert "No direct financial savings claimed" in q3["savings_claims_disclaimer"]
    assert len(q3["sources"]) > 0
    assert len(q3["assumptions"]) > 0

    # ── Q4 Check: Historical risk posture trend, MTTR, verified reduction ──────
    # Seed a resolved retest to test MTTR and verified reduction
    retest_record = {
        "id": "ret-gate-1",
        "finding_id": "f-gate-1",
        "retest_status": "resolved",
        "verified_risk_reduction": 25.0,
        "completed_at": t_now,
    }
    await mock_db["retests"].insert_one(retest_record)
    await mock_db["remediation_tasks"].insert_one({
        "id": "task-gate-1",
        "finding_id": "f-gate-1",
        "scan_id": scan_id,
        "status": "resolved",
        "verified_risk_reduction": 25.0,
        "created_at": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat().replace("+00:00", "Z"),
        "updated_at": t_now,
    })

    q4 = await svc.answer_question_4_posture_trends(target=target)
    assert q4["question_id"] == "Q4"
    assert q4["total_verified_risk_reduction_points"] == 25.0
    assert q4["mttr_hours_average"] is not None
    assert q4["mttr_hours_average"] > 0
    assert len(q4["sources"]) > 0
    assert len(q4["assumptions"]) > 0


# ─── 7. REST API Endpoints End-to-End Tests ─────────────────────────────────────

@pytest.mark.asyncio
async def test_api_business_questions_endpoints(client):
    """Verify FastAPI routes for all 4 business questions."""
    from app.database import get_db
    db = get_db()

    scan_id = f"scan-api-{uuid.uuid4().hex[:6]}"
    target = "https://api.v17.example.com"

    await db["scans"].insert_one({
        "id": scan_id,
        "target": target,
        "scope": {"target": target},
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    await db["findings"].insert_one({
        "id": f"f-{scan_id}-1",
        "scan_id": scan_id,
        "title": "SQL Injection in User Endpoint",
        "severity": "critical",
        "cvss_score": 9.2,
        "source_type": "OBSERVED",
        "affected_endpoint": f"{target}/users",
        "evidence": "Observed MariaDB error syntax",
        "evidence_hash": "hash-sqli-ev",
        "poc": {"payload": "' OR 1=1"},
        "confirmed": True,
    })

    # Test master business questions endpoint
    resp = await client.get(f"/api/v1/business-questions/{scan_id}?target={target}&user_hourly_rate=150.0")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"] == scan_id
    assert "questions" in data
    assert "Q1_cyber_risk_and_financial_loss" in data["questions"]
    assert "Q2_critical_findings_and_attack_paths" in data["questions"]
    assert "Q3_remediation_investments_and_effort" in data["questions"]
    assert "Q4_posture_trends_and_mttr" in data["questions"]

    # Test individual sub-endpoints
    r_q1 = await client.get(f"/api/v1/business-questions/{scan_id}/q1?hourly_downtime_cost_usd=7500.0")
    assert r_q1.status_code == 200
    assert r_q1.json()["question_id"] == "Q1"

    r_q2 = await client.get(f"/api/v1/business-questions/{scan_id}/q2?target={target}")
    assert r_q2.status_code == 200
    assert r_q2.json()["question_id"] == "Q2"

    r_q3 = await client.get(f"/api/v1/business-questions/{scan_id}/q3?user_hourly_rate=150.0")
    assert r_q3.status_code == 200
    assert r_q3.json()["question_id"] == "Q3"
    assert "No direct financial savings claimed" in r_q3.json()["savings_claims_disclaimer"]

    r_q4 = await client.get(f"/api/v1/business-questions/{scan_id}/q4?target={target}")
    assert r_q4.status_code == 200
    assert r_q4.json()["question_id"] == "Q4"


@pytest.mark.asyncio
async def test_api_remediation_tasks_crud_and_retest(client):
    """Verify REST API CRUD for remediation tasks and retest execution."""
    from app.database import get_db
    db = get_db()

    f_id = f"f-rem-{uuid.uuid4().hex[:6]}"
    s_id = f"scan-rem-{uuid.uuid4().hex[:6]}"

    await db["findings"].insert_one({
        "id": f_id,
        "scan_id": s_id,
        "title": "Cross-Site Scripting (Reflected)",
        "severity": "high",
        "cvss_score": 7.5,
        "tool": "nuclei_xss",
        "evidence": "<script>alert(1)</script>",
        "confirmed": True,
    })

    # 1. Create remediation task via POST
    create_payload = {
        "finding_id": f_id,
        "scan_id": s_id,
        "user_hourly_rate": 130.0,
        "assignee": "bob@security.corp",
        "priority": "P2",
        "sla_days": 10,
    }
    post_res = await client.post("/api/v1/remediation-tasks", json=create_payload)
    assert post_res.status_code == 200
    task_data = post_res.json()
    task_id = task_data["id"]
    assert task_data["status"] == "pending"
    assert task_data["original_test_method"] == "nuclei_xss"
    assert task_data["user_hourly_rate"] == 130.0

    # 2. Get task via GET
    get_res = await client.get(f"/api/v1/remediation-tasks/{task_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == task_id

    # 3. List tasks
    list_res = await client.get(f"/api/v1/remediation-tasks?scan_id={s_id}")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # 4. Patch task
    patch_res = await client.patch(
        f"/api/v1/remediation-tasks/{task_id}",
        json={"status": "in_progress", "assignee": "lead_engineer@corp.com"}
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "in_progress"
    assert patch_res.json()["assignee"] == "lead_engineer@corp.com"

    # 5. Trigger retest for task
    from unittest.mock import patch, AsyncMock
    with patch("app.services.remediation_retest_engine.validation_engine.validate_finding", new_callable=AsyncMock) as mock_val:
        mock_val.return_value = {
            "validation_status": "not_exploitable",
            "confirmed": False,
            "evidence_hash": "hash-retest-fixed",
        }
        retest_res = await client.post(f"/api/v1/remediation-tasks/{task_id}/retest")
        assert retest_res.status_code == 200
        retest_body = retest_res.json()
        assert retest_body["retest"]["retest_status"] == "resolved"
        assert retest_body["retest"]["verified_risk_reduction"] > 0
        assert retest_body["task"]["status"] == "resolved"
        assert retest_body["task"]["verified_risk_reduction"] == retest_body["retest"]["verified_risk_reduction"]

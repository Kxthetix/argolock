"""
Unit and Integration Tests for ARGOLOCK V1.7 Core Platform
Validates:
- Security Control Plane (Scope Gate, Action Classification, Safe Minimum-Impact, Kill Switch)
- 60-Agent Logical Registry across 9 categories
- Adversarial Validation Engine (Devil's Advocate)
- Capability Graph & Attack Path Engine
- Cyber Risk Quantification Engine
- Investment Optimization & Remediation ROI Engine
"""
import pytest
from app.models.v1_7_models import ActionClassification, FindingLifecycleState, MissionMode
from app.services.security_control_plane import SecurityControlPlane
from app.services.agent_registry import AgentRegistry
from app.services.adversarial_validator import AdversarialValidator, AdversarialEvaluationOutcome
from app.services.capability_graph_service import CapabilityGraphService
from app.services.cyber_risk_service import CyberRiskEngine
from app.services.investment_optimizer_service import InvestmentOptimizer, RemediationPriority


# ─── 1. Security Control Plane Tests ─────────────────────────────────────────────

def test_scope_gate_whitelist():
    """Verify that targets matching scope whitelist are permitted and others blocked."""
    res_valid = SecurityControlPlane.evaluate_scope_gate(
        target_url_or_host="https://api.example.com/v1",
        whitelist=["*.example.com", "example.com"]
    )
    assert res_valid.allowed is True
    assert "verified in authorized scope" in res_valid.reason

    res_blocked = SecurityControlPlane.evaluate_scope_gate(
        target_url_or_host="https://malicious-out-of-scope.com",
        whitelist=["example.com"]
    )
    assert res_blocked.allowed is False
    assert "OUT OF SCOPE" in res_blocked.reason


def test_scope_gate_blacklist():
    """Verify that blacklisted targets are blocked even if inside wildcard."""
    res = SecurityControlPlane.evaluate_scope_gate(
        target_url_or_host="https://prod-db.example.com",
        whitelist=["*.example.com"],
        blacklist=["prod-db.example.com"]
    )
    assert res.allowed is False
    assert "blacklisted by policy" in res.reason


def test_action_gate_destructive_blocking():
    """Verify that destructive SQL or system commands are unconditionally blocked."""
    res = SecurityControlPlane.evaluate_action_gate(
        tool="sqlmap",
        command_or_action="DROP TABLE users;",
        target="example.com"
    )
    assert res.allowed is False
    assert res.action_class == ActionClassification.DESTRUCTIVE

    res_forkbomb = SecurityControlPlane.evaluate_action_gate(
        tool="bash",
        command_or_action=":(){ :|:& };:",
        target="example.com"
    )
    assert res_forkbomb.allowed is False
    assert res_forkbomb.action_class == ActionClassification.DESTRUCTIVE


def test_emergency_kill_switch():
    """Verify that emergency kill switch blocks all subsequent gate evaluations."""
    mission_id = "test-mission-99"
    SecurityControlPlane.activate_emergency_kill_switch(mission_id)
    assert SecurityControlPlane.is_killed(mission_id) is True

    res = SecurityControlPlane.evaluate_scope_gate("https://example.com", ["example.com"], mission_id=mission_id)
    assert res.allowed is False
    assert "Emergency kill switch is active" in res.reason

    SecurityControlPlane.reset_kill_switch(mission_id)
    assert SecurityControlPlane.is_killed(mission_id) is False


# ─── 2. 60-Agent Registry Tests ──────────────────────────────────────────────────

def test_agent_registry_count_and_categories():
    """Verify that exactly 60 logical agents are defined across all 9 required categories."""
    assert AgentRegistry.total_count() == 60
    categories = AgentRegistry.get_categories()
    
    expected_categories = [
        "Orchestration", "Recon", "Web/API", "Infrastructure",
        "Code", "Exploitation", "Validation", "Risk", "Reporting"
    ]
    for cat in expected_categories:
        assert cat in categories
        agents = AgentRegistry.list_agents(cat)
        assert len(agents) > 0


def test_key_agents_exist():
    """Verify existence of critical flagship agents."""
    mc = AgentRegistry.get_agent("mission-controller")
    assert mc is not None
    assert mc.id == "01"

    devil = AgentRegistry.get_agent("devil-advocate")
    assert devil is not None
    assert devil.id == "50"

    invest = AgentRegistry.get_agent("investment-optimizer")
    assert invest is not None
    assert invest.id == "57"


# ─── 3. Adversarial Validation Tests ────────────────────────────────────────────

def test_adversarial_validator_pass():
    """Valid finding with PoC and evidence passes Devil's Advocate evaluation."""
    finding = {
        "id": "f-101",
        "title": "SQL Injection in User Search Parameter",
        "severity": "high",
        "cvss_score": 8.5,
        "affected_endpoint": "https://example.com/api/users?q=test",
        "poc": {"payload": "' OR '1'='1", "request": "GET /api/users?q=%27+OR+%271%27=%271"},
        "evidence": "HTTP/1.1 200 OK with differential response",
        "confirmed": True
    }
    report = AdversarialValidator.evaluate(finding)
    assert report.decision == AdversarialEvaluationOutcome.PASS
    assert report.state == FindingLifecycleState.CONFIRMED
    assert report.confidence_score >= 0.8


def test_adversarial_validator_downgrade_inflation():
    """Inflated finding (e.g. DMARC rated as Critical) is calibrated and downgraded."""
    inflated_finding = {
        "id": "f-102",
        "title": "Missing DMARC Record",
        "severity": "critical",
        "cvss_score": 9.5,
        "affected_endpoint": "example.com",
        "poc": {"payload": "dig TXT _dmarc.example.com"},
        "evidence": "NXDOMAIN",
    }
    report = AdversarialValidator.evaluate(inflated_finding)
    assert report.decision == AdversarialEvaluationOutcome.DOWNGRADE
    assert report.calibrated_severity == "medium"
    assert report.state == FindingLifecycleState.DOWNGRADED


# ─── 4. Capability Graph & Attack Paths ──────────────────────────────────────────

def test_capability_graph_generation():
    """Verify that findings are transformed into capability nodes and attack chains."""
    findings = [
        {"id": "f-1", "title": "Insecure Direct Object Reference (IDOR)", "severity": "high", "cvss_score": 7.5, "affected_endpoint": "https://example.com/profile"},
        {"id": "f-2", "title": "Administrative Authentication Bypass", "severity": "critical", "cvss_score": 9.8, "affected_endpoint": "https://example.com/admin/login"},
    ]
    graph = CapabilityGraphService.generate_graph("scan-test-1", findings, "example.com")
    assert graph["total_nodes"] == 2
    assert graph["total_edges"] == 1
    assert len(graph["attack_chains"]) == 1
    chain = graph["attack_chains"][0]
    assert chain["severity"] == "critical"
    assert "Attack Path:" in chain["title"]


# ─── 5. Cyber Risk Quantification Tests ─────────────────────────────────────────

def test_cyber_risk_score_calculation():
    """Verify multi-variable risk score computation."""
    findings = [
        {"id": "f-1", "title": "SQL Injection", "severity": "critical", "cvss_score": 9.2, "confirmed": True},
        {"id": "f-2", "title": "Missing DMARC", "severity": "medium", "cvss_score": 5.5, "confirmed": True},
    ]
    risk = CyberRiskEngine.calculate_scan_risk(
        scan_id="scan-risk-1",
        findings=findings,
        asset_criticality=1.5,
        exposure_factor=1.4,
    )
    assert 0.0 <= risk.score <= 100.0
    assert risk.rating in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    assert risk.exploitability_factor == 1.0


# ─── 6. Investment Optimization (Remediation ROI) Tests ─────────────────────────

def test_investment_optimizer_plan():
    """Verify that remediation actions are assigned ROI and P1-P4 priorities."""
    findings = [
        {"id": "f-1", "title": "SQL Injection in User Search", "severity": "critical"},
        {"id": "f-2", "title": "Missing DMARC Record", "severity": "medium"},
    ]
    plan = InvestmentOptimizer.generate_plan(
        scan_id="scan-inv-1",
        initial_risk_score=75.0,
        findings=findings,
    )
    assert plan.initial_risk_score == 75.0
    assert plan.projected_residual_risk < plan.initial_risk_score
    assert len(plan.actions) == 2

    # SQLi should be higher priority (P1) than DMARC (P3/P4)
    priorities = [a.priority for a in plan.actions]
    assert RemediationPriority.P1 in priorities
    assert plan.actions[0].roi_score > 0

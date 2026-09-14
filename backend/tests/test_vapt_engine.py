"""Comprehensive Unit and Integration Tests for ARGOLOCK NET v1.6 VAPT Engine."""
from __future__ import annotations

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

from app.models.vapt_models import (
    TargetAuthorization, AuthorizationStatus, TestingMode,
    TestingApproval, TestingLevel, ApprovalStatus,
    ValidationStatus, RetestStatus, ExploitabilityLevel
)
from app.services.target_authorization_service import TargetAuthorizationService
from app.services.exploit_safety_gate import ExploitSafetyGate, GateDecision
from app.services.evidence_collector import EvidenceCollector
from app.services.false_positive_engine import FalsePositiveEngine
from app.services.exploitability_engine import ExploitabilityAssessmentEngine
from app.services.contextual_risk_engine import ContextualRiskEngine
from app.services.attack_path_engine import AttackPathEngine
from app.services.remediation_retest_engine import RemediationRetestEngine
from app.services.audit_logger import AuditLogger
from tools.adapters.adapter_registry import ToolAdapterRegistry


# ── Target Authorization & Scope Gate Tests ──────────────────────────────────

@pytest.mark.asyncio
async def test_target_authorization_and_window_check():
    mock_db = MagicMock()
    service = TargetAuthorizationService(db_getter=lambda: mock_db)

    now = datetime.now(timezone.utc)
    auth = TargetAuthorization(
        asset_id="asset-prod-01",
        hostname_or_ip="192.168.1.50",
        owner="Security Team",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        scope=["192.168.1.0/24"],
        permitted_ports=[80, 443, 8080],
        permitted_services=["http", "https"],
        testing_window_start=now - timedelta(hours=1),
        testing_window_end=now + timedelta(hours=2),
        assessment_id="assess-001",
        approval_reference="CISO-AUTH-2026",
    )

    # Mock get_authorization_by_target
    service.get_authorization_by_target = AsyncMock(return_value=auth)

    # 1. Valid authorized target & port
    is_valid, reason, rec = await service.verify_target_authorization("192.168.1.50", port=443, service="https")
    assert is_valid is True
    assert rec.asset_id == "asset-prod-01"

    # 2. Block unpermitted port (e.g. 22)
    is_valid, reason, rec = await service.verify_target_authorization("192.168.1.50", port=22)
    assert is_valid is False
    assert "BLOCK: Port 22 is not in permitted ports" in reason

    # 3. Block unpermitted service
    is_valid, reason, rec = await service.verify_target_authorization("192.168.1.50", service="ssh")
    assert is_valid is False
    assert "BLOCK: Service 'ssh' is not permitted" in reason

    # 4. Block expired window
    auth.testing_window_end = now - timedelta(minutes=5)
    is_valid, reason, rec = await service.verify_target_authorization("192.168.1.50", port=80)
    assert is_valid is False
    assert "expired" in reason.lower()

    # 5. Block unregistered target
    service.get_authorization_by_target = AsyncMock(return_value=None)
    is_valid, reason, rec = await service.verify_target_authorization("arbitrary-target.com")
    assert is_valid is False
    assert "not registered" in reason.lower()


# ── Safety Gate & Testing Levels Tests ────────────────────────────────────────

@pytest.mark.asyncio
async def test_safety_gate_levels_and_approvals():
    mock_db = MagicMock()
    gate = ExploitSafetyGate(db_getter=lambda: mock_db)

    now = datetime.now(timezone.utc)
    auth = TargetAuthorization(
        asset_id="asset-web-01",
        hostname_or_ip="test.example.com",
        owner="AppSec",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        assessment_id="assess-01",
        approval_reference="REF-01",
    )

    with patch("app.services.exploit_safety_gate.target_auth_service.verify_target_authorization", new=AsyncMock(return_value=(True, "OK", auth))):
        # 1. Level 4 (Destructive) must be permanently blocked
        decision, reason, _, _ = await gate.evaluate_safety("test.example.com", "find-1", TestingLevel.LEVEL_4_DESTRUCTIVE)
        assert decision == GateDecision.BLOCKED
        assert "Destructive testing is permanently disabled" in reason

        # 2. Level 0 & Level 1 are safe non-invasive
        decision, reason, _, _ = await gate.evaluate_safety("test.example.com", "find-1", TestingLevel.LEVEL_1_NON_INVASIVE)
        assert decision == GateDecision.SAFE_TO_VALIDATE

        # 3. Level 2 requires approval
        decision, reason, _, _ = await gate.evaluate_safety("test.example.com", "find-1", TestingLevel.LEVEL_2_CONTROLLED_PROOF)
        assert decision == GateDecision.REQUIRES_APPROVAL

        # 4. Level 2 with valid approved record
        valid_approval = TestingApproval(
            id="appr-123",
            assessment_id="assess-01",
            finding_id="find-1",
            asset_id="asset-web-01",
            requested_by="engineer@argolock.net",
            approved_by="lead@argolock.net",
            testing_level=TestingLevel.LEVEL_2_CONTROLLED_PROOF,
            expiration=now + timedelta(hours=1),
            status=ApprovalStatus.APPROVED,
        )
        mock_db["testing_approvals"].find_one = AsyncMock(return_value=valid_approval.model_dump())

        decision, reason, _, appr = await gate.evaluate_safety(
            "test.example.com", "find-1", TestingLevel.LEVEL_2_CONTROLLED_PROOF, approval_id="appr-123"
        )
        assert decision == GateDecision.SAFE_TO_VALIDATE
        assert appr is not None
        assert appr.id == "appr-123"


# ── Evidence Collector & Redaction Tests ─────────────────────────────────────

def test_evidence_redaction_and_sha256_hash():
    collector = EvidenceCollector()

    raw_request = (
        "POST /api/login HTTP/1.1\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token\r\n"
        "Cookie: session=secret_session_token_12345\r\n\r\n"
        "{\"username\": \"admin\", \"password\": \"SuperSecretPass!123\"}"
    )

    redacted_text, fields = collector.redact_sensitive_data(raw_request)
    assert "[REDACTED" in redacted_text
    assert "SuperSecretPass!123" not in redacted_text
    assert "eyJhbGci" not in redacted_text

    # SHA-256 calculation
    record = {
        "finding_id": "f-1",
        "asset_id": "a-1",
        "tool_source": "nuclei",
        "technique": "safe_probe",
        "request_sample": redacted_text,
        "response_sample": "HTTP 200 OK",
        "banner_output": "Server: nginx",
        "config_snippet": None,
    }
    hash1 = collector.calculate_sha256(record)
    hash2 = collector.calculate_sha256(record)
    assert len(hash1) == 64
    assert hash1 == hash2  # Deterministic hash


# ── False Positive Engine Tests ──────────────────────────────────────────────

def test_false_positive_evaluations():
    fp_engine = FalsePositiveEngine()

    # 1. Product mismatch: Scanner flagged Apache vulnerability on an Nginx server
    finding_apache = {"title": "Apache HTTP Server Path Traversal", "affected_endpoint": "https://example.com"}
    live_evidence_nginx = {"server_header": "nginx/1.24.0", "status_code": 404}
    status, conf, rationale = fp_engine.evaluate_false_positive(finding_apache, live_evidence_nginx)
    assert status == ValidationStatus.FALSE_POSITIVE
    assert "Product Mismatch" in rationale

    # 2. File not found: 404 on backup.sql exposure
    finding_backup = {"title": "Exposed Database Backup File (backup.sql)", "affected_endpoint": "https://example.com/backup.sql"}
    live_evidence_404 = {"status_code": 404}
    status, conf, rationale = fp_engine.evaluate_false_positive(finding_backup, live_evidence_404)
    assert status == ValidationStatus.FALSE_POSITIVE
    assert "File/Path Not Found" in rationale

    # 3. Confirmed CORS Misconfiguration
    finding_cors = {"title": "CORS Misconfiguration Origin Reflection", "affected_endpoint": "https://example.com/api"}
    live_evidence_cors = {"cors_misconfigured": True, "cors_acao": "https://evil-test.com", "status_code": 200}
    status, conf, rationale = fp_engine.evaluate_false_positive(finding_cors, live_evidence_cors)
    assert status == ValidationStatus.CONFIRMED
    assert "CORS Misconfiguration verified" in rationale


# ── Exploitability & Contextual Risk Engine Tests ─────────────────────────────

def test_exploitability_and_contextual_risk():
    exploit_engine = ExploitabilityAssessmentEngine()
    risk_engine = ContextualRiskEngine()

    finding = {
        "id": "find-log4j",
        "title": "Log4j Remote Code Execution",
        "cve_ids": ["CVE-2021-44228"],
        "cvss_score": 10.0,
        "validation_status": "confirmed",
        "validation_confidence": 0.98,
    }

    # Evaluate exploitability
    assessment = exploit_engine.assess_exploitability(finding, {"network_exposure": "external"})
    assert assessment.cisa_kev_listed is True
    assert assessment.public_exploit_available is True
    assert assessment.exploitability_level in (ExploitabilityLevel.CRITICAL, ExploitabilityLevel.HIGH)

    # Evaluate Contextual Cyber Risk
    risk = risk_engine.calculate_risk(
        finding=finding,
        exploit_assessment=assessment,
        asset_context={"asset_criticality": "critical", "network_exposure": "external"},
        attack_path_multiplier=1.2
    )

    assert risk.risk_tier == "critical"
    assert risk.final_risk_score >= 85.0
    assert "summary" in risk.explanation
    assert "attack_path_multiplier" in risk.explanation


# ── Attack Path & MITRE ATT&CK Engine Tests ──────────────────────────────────

def test_attack_path_and_mitre_mapping():
    engine = AttackPathEngine()

    # 1. MITRE ATT&CK Mapping
    finding_sqli = {"id": "f-1", "title": "SQL Injection in Search Form", "affected_endpoint": "https://app.local/search"}
    mapping = engine.map_mitre(finding_sqli)
    assert mapping.technique_id == "T1190"
    assert mapping.tactic == "Initial Access"

    # 2. Attack Path Topology Graph
    graph = engine.generate_attack_path_graph(
        assessment_id="assess-999",
        target="web.prod.internal",
        findings=[finding_sqli],
        critical_assets=["Customer Database (PII)"]
    )
    assert len(graph.nodes) >= 3
    assert len(graph.edges) >= 2
    assert any(n.name == "Customer Database (PII)" for n in graph.nodes)


# ── Tool Registry & Health Check Tests ───────────────────────────────────────

def test_adapter_registry():
    registry = ToolAdapterRegistry()
    adapters = registry.list_adapters()
    assert len(adapters) >= 6

    # Verify adapter lookup
    sql_adapter = registry.find_adapter_for_vulnerability("SQL Injection")
    assert sql_adapter is not None
    assert sql_adapter.tool_id == "sqlmap"

    # Health check should return valid status dictionaries
    health_reports = registry.get_all_health_statuses()
    assert len(health_reports) == len(adapters)
    for report in health_reports:
        assert "tool_id" in report
        assert "health_status" in report
        assert "capabilities" in report


# ── VAPT API Endpoints Integration Tests ─────────────────────────────────────

@pytest.mark.asyncio
async def test_vapt_api_endpoints(client):
    # 1. Login to obtain JWT
    email = "vapt_tester@argolock.net"
    login_resp = await client.post("/api/auth/login", json={"email": email, "password": "VaptPassword123!"})
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Check Tool Adapters Health API
    health_resp = await client.get("/api/vapt/tools/health", headers=headers)
    assert health_resp.status_code == 200
    tools = health_resp.json()
    assert isinstance(tools, list)
    assert len(tools) >= 6

    # 3. Create Target Authorization
    auth_payload = {
        "asset_id": "asset-api-test-01",
        "hostname_or_ip": "testapp.local",
        "owner": "QA Lead",
        "authorization_status": "authorized",
        "scope": ["testapp.local"],
        "permitted_ports": [80, 443],
        "permitted_services": ["http", "https"],
        "assessment_id": "assess-api-101",
        "approval_reference": "REF-API-101",
    }
    create_auth_resp = await client.post("/api/vapt/authorizations", json=auth_payload, headers=headers)
    assert create_auth_resp.status_code == 201
    assert create_auth_resp.json()["asset_id"] == "asset-api-test-01"

    # List Authorizations
    list_auth_resp = await client.get("/api/vapt/authorizations", headers=headers)
    assert list_auth_resp.status_code == 200
    assert any(a["asset_id"] == "asset-api-test-01" for a in list_auth_resp.json())

    # 4. Insert finding in DB for testing
    from app.database import get_db
    db = get_db()
    finding_id = "find-api-test-001"
    await db["findings"].insert_one({
        "id": finding_id,
        "scan_id": "scan-123",
        "asset_id": "asset-api-test-01",
        "title": "Missing Security Headers",
        "description": "Content-Security-Policy header is missing from responses",
        "severity": "medium",
        "affected_endpoint": "https://testapp.local",
        "cve_ids": [],
        "cvss_score": 5.0,
        "confirmed": False,
        "validation_status": "detected",
    })

    # 5. Exploitability API
    exp_resp = await client.get(f"/api/vapt/findings/{finding_id}/exploitability", headers=headers)
    assert exp_resp.status_code == 200
    exp_data = exp_resp.json()
    assert "exploitability_level" in exp_data
    assert "confidence" in exp_data

    # 6. Contextual Risk API
    risk_resp = await client.get(f"/api/vapt/risk/{finding_id}", headers=headers)
    assert risk_resp.status_code == 200
    risk_data = risk_resp.json()
    assert "final_risk_score" in risk_data
    assert "explanation" in risk_data

    # 7. Remediation Plan API
    rem_resp = await client.get(f"/api/vapt/findings/{finding_id}/remediation", headers=headers)
    assert rem_resp.status_code == 200
    assert "root_cause" in rem_resp.json()

    # 8. Testing Approval Request & Approval Flow
    approval_payload = {
        "assessment_id": "assess-api-101",
        "finding_id": finding_id,
        "asset_id": "asset-api-test-01",
        "requested_by": email,
        "testing_level": "level_2",
        "scope_justification": "Controlled proof of missing header misconfiguration",
        "expiration": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        "status": "pending",
    }
    appr_req_resp = await client.post("/api/vapt/approvals", json=approval_payload, headers=headers)
    assert appr_req_resp.status_code == 201
    approval_id = appr_req_resp.json()["id"]

    # Approve request
    approve_resp = await client.post(f"/api/vapt/approvals/{approval_id}/approve", headers=headers)
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"

    # 9. Attack Paths API
    attack_paths_resp = await client.get("/api/vapt/attack-paths", headers=headers)
    assert attack_paths_resp.status_code == 200
    assert "nodes" in attack_paths_resp.json()
    assert "edges" in attack_paths_resp.json()

    # 10. Audit Trail API
    audit_resp = await client.get("/api/vapt/audit", headers=headers)
    assert audit_resp.status_code == 200
    assert isinstance(audit_resp.json(), list)
    assert len(audit_resp.json()) >= 1

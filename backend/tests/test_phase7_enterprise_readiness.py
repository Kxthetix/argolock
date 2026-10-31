"""
Unit and Integration Tests for Phase 7 Deliverables:
1. Multi-Tenant Isolation & Horizontal Access Boundary Enforcement.
2. Database Backup, Checksum-Verified Restore, and Rollback.
3. Secret Scanning (verifying no committed secrets exist in repository).
4. Rate Limiting Throttling (verifying HTTP 429 on breach).
5. Observability, Metrics & Security Alert Dispatch.
6. Gate Checks: Security Review Passed, Backup/Restore Tested, Runbook Written.
"""
from __future__ import annotations

import os
import pytest
import uuid
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from app.models.v1_7_models import (
    FigureOrigin,
    RemediationPriority,
    RemediationTaskStatus,
)
from app.models.scan import ScanDocument, ScanScope, ScanConfig, ScanStatus
from app.models.finding import Finding, Severity, DataSource
from app.routers.auth import _create_jwt, verify_tenant_access
from app.services.migration_backup_service import DatabaseMigrationBackupService
from app.services.secret_scanner import SecretScanner
from app.services.rate_limiter import SlidingWindowRateLimiter
from app.services.alerting_service import AlertingService, AlertSeverity, AlertCategory


# ── Mock Database Helper ─────────────────────────────────────────────────────────

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
            if isinstance(v, dict) and "$exists" in v:
                exists = k in item and item[k] is not None
                if exists != v["$exists"]:
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
            match = all(item.get(k) == v for k, v in query.items() if k != "$or")
            if match:
                if "$set" in update:
                    item.update(update["$set"])
                return {"matched": 1, "modified": 1}
        return {"matched": 0, "modified": 0}

    async def update_many(self, query, update):
        matched = 0
        for item in self.data:
            match = True
            for k, v in query.items():
                if k == "tenant_id" and isinstance(v, dict) and "$exists" in v:
                    exists = "tenant_id" in item and item["tenant_id"] is not None
                    if exists != v["$exists"]:
                        match = False
                        break
                elif item.get(k) != v:
                    match = False
                    break
            if match:
                matched += 1
                if "$set" in update:
                    item.update(update["$set"])
        return {"matched": matched}

    async def delete_many(self, query):
        if not query:
            count = len(self.data)
            self.data = []
            return {"deleted": count}
        remaining = [item for item in self.data if not all(item.get(k) == v for k, v in query.items())]
        deleted = len(self.data) - len(remaining)
        self.data = remaining
        return {"deleted": deleted}


class InMemoryCursor:
    def __init__(self, data):
        self._data = list(data)

    def sort(self, key, direction=1):
        try:
            self._data.sort(key=lambda x: x.get(key, ""), reverse=(direction == -1))
        except Exception:
            pass
        return self

    def skip(self, count):
        self._data = self._data[count:]
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


# ─── 1. Tenant Isolation Unit & Logic Tests ─────────────────────────────────────

def test_tenant_jwt_creation_and_verification():
    """Verify that JWT tokens encode tenant_id and verify_tenant_access fails closed on mismatch."""
    from jose import jwt
    from app.config import settings
    from fastapi import HTTPException

    token = _create_jwt("user@corp.com", role="analyst", tenant_id="tenant_omega")
    payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    assert payload["tenant_id"] == "tenant_omega"

    current_user = {"email": "user@corp.com", "tenant_id": "tenant_omega"}

    # Same tenant access allowed
    verify_tenant_access("tenant_omega", current_user)

    # Cross-tenant access rejected
    with pytest.raises(HTTPException) as exc_info:
        verify_tenant_access("tenant_other", current_user)
    assert exc_info.value.status_code == 403
    assert "Tenant access denied" in exc_info.value.detail


# ─── 2. Database Backup, Restore, and Rollback Tests ────────────────────────────

@pytest.mark.asyncio
async def test_database_backup_restore_and_rollback(tmp_path):
    """
    Verify complete database backup snapshot creation, tamper-evident checksumming,
    data wiping, and full point-in-time restore (Gate test).
    """
    mock_db = MockDB()

    # Seed mock data
    await mock_db["scans"].insert_one({"id": "scan-bk-1", "target": "https://example.com", "tenant_id": "tenant_alpha"})
    await mock_db["findings"].insert_one({"id": "find-bk-1", "title": "SQL Injection", "tenant_id": "tenant_alpha"})
    await mock_db["remediation_tasks"].insert_one({"id": "task-bk-1", "status": "pending", "tenant_id": "tenant_alpha"})

    service = DatabaseMigrationBackupService(db_getter=lambda: mock_db, backup_dir=tmp_path)

    # 1. Create backup snapshot
    meta = await service.create_backup(backup_id="test-backup-01", description="Test snapshot")
    assert meta["backup_id"] == "test-backup-01"
    assert meta["counts"]["scans"] == 1
    assert meta["counts"]["findings"] == 1
    assert meta["counts"]["remediation_tasks"] == 1
    assert len(meta["sha256_checksum"]) == 64

    # 2. Modify / drop data in database (simulate loss/corruption)
    await mock_db["scans"].delete_many({})
    await mock_db["findings"].delete_many({})
    assert len(mock_db["scans"].data) == 0
    assert len(mock_db["findings"].data) == 0

    # 3. Restore from backup
    restore_summary = await service.restore_backup("test-backup-01", wipe_existing=True)
    assert restore_summary["integrity_verified"] is True
    assert restore_summary["restored_counts"]["scans"] == 1
    assert restore_summary["restored_counts"]["findings"] == 1

    # Verify records restored accurately
    restored_scan = await mock_db["scans"].find_one({"id": "scan-bk-1"})
    assert restored_scan is not None
    assert restored_scan["target"] == "https://example.com"
    assert restored_scan["tenant_id"] == "tenant_alpha"

    restored_finding = await mock_db["findings"].find_one({"id": "find-bk-1"})
    assert restored_finding is not None
    assert restored_finding["title"] == "SQL Injection"


@pytest.mark.asyncio
async def test_tenant_isolation_migration():
    """Verify database migration backfills tenant_id on unpartitioned legacy records."""
    mock_db = MockDB()

    # Seed unpartitioned records (missing tenant_id)
    await mock_db["scans"].insert_one({"id": "scan-legacy-1", "target": "https://legacy.com"})
    await mock_db["findings"].insert_one({"id": "find-legacy-1", "title": "Legacy Issue"})

    service = DatabaseMigrationBackupService(db_getter=lambda: mock_db)
    result = await service.migrate_tenant_isolation(default_tenant_id="tenant_migrated")

    assert result["status"] == "applied"
    assert result["documents_migrated"]["scans"] >= 1
    assert result["documents_migrated"]["findings"] >= 1

    # Verify records now contain tenant_id
    updated_scan = await mock_db["scans"].find_one({"id": "scan-legacy-1"})
    assert updated_scan["tenant_id"] == "tenant_migrated"


# ─── 3. Secrets Scanning Tests ──────────────────────────────────────────────────

def test_secret_scanner_detects_credentials_and_confirms_clean_repo():
    """Verify secret scanner detects secrets in test buffers and confirms tracked repo is clean."""
    # 1. Detection test on simulated secret string
    simulated_buffer = "AWS_KEY = AKIAIOSFODNN7EXAMPLE\nAPI_TOKEN = ghp_1234567890abcdefghijklmnopqrstuvwxyzAB\n"
    findings = SecretScanner.scan_content(simulated_buffer, filename="simulated.py")
    assert len(findings) == 2
    types = [f["type"] for f in findings]
    assert "AWS Access Key ID" in types
    assert "GitHub Token" in types

    # 2. Repository scan: ensure repository has zero committed live secrets
    repo_root = Path(__file__).resolve().parent.parent.parent
    repo_scan = SecretScanner.scan_git_tracked_files(repo_root)
    assert repo_scan["clean"] is True
    assert repo_scan["secret_findings_count"] == 0
    assert repo_scan["files_scanned"] > 50


# ─── 4. Rate Limiter Tests ──────────────────────────────────────────────────────

def test_sliding_window_rate_limiter():
    """Verify rate limiter permits requests up to limit and rejects subsequent requests with HTTP 429."""
    from fastapi import HTTPException

    limiter = SlidingWindowRateLimiter()
    key = "tenant_test_limiter"

    # Make 5 requests within limit of 5
    for i in range(5):
        allowed, limit, remaining, reset_sec = limiter.is_allowed(key, max_requests=5, window_seconds=10)
        assert allowed is True
        assert remaining == 5 - (i + 1)

    # 6th request must be rejected
    allowed, limit, remaining, reset_sec = limiter.is_allowed(key, max_requests=5, window_seconds=10)
    assert allowed is False
    assert remaining == 0
    assert reset_sec > 0

    # check_rate_limit raises 429 on breach
    with pytest.raises(HTTPException) as exc_info:
        limiter.check_rate_limit(key, max_requests=5, window_seconds=10)
    assert exc_info.value.status_code == 429
    assert "Retry-After" in exc_info.value.headers


# ─── 5. Observability & Alerting Tests ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_alerting_service_emit_and_metrics():
    """Verify security alert emission, metric compilation, and operator acknowledgment."""
    mock_db = MockDB()
    svc = AlertingService(db_getter=lambda: mock_db)

    # 1. Emit security alert
    alert = await svc.emit_alert(
        title="Cross-Tenant Access Attempt Detected",
        description="User bob attempted to view scan of tenant_alpha",
        severity=AlertSeverity.CRITICAL,
        category=AlertCategory.SECURITY,
        tenant_id="tenant_alpha",
        actor="bob@corp.com",
    )

    assert alert.title == "Cross-Tenant Access Attempt Detected"
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.acknowledged is False

    # 2. List alerts
    alerts = await svc.list_alerts(tenant_id="tenant_alpha")
    assert len(alerts) == 1
    assert alerts[0].id == alert.id

    # 3. Acknowledge alert
    ack = await svc.acknowledge_alert(alert.id, acknowledged_by="lead_sec@corp.com")
    assert ack is not None
    assert ack.acknowledged is True
    assert ack.acknowledged_by == "lead_sec@corp.com"

    # 4. Check metrics aggregation
    metrics = await svc.get_observability_metrics()
    assert "metrics" in metrics
    assert "total_scans" in metrics["metrics"]


# ─── 6. End-to-End API Multi-Tenant Isolation Tests ─────────────────────────────

@pytest.mark.asyncio
async def test_api_tenant_boundary_isolation_end_to_end(client):
    """
    Verify complete tenant isolation via API:
    - User in Tenant Alpha creates a scan.
    - User in Tenant Beta queries scans -> Tenant Alpha's scan is NOT returned.
    - User in Tenant Beta attempts direct GET /scans/{id} -> fails closed with HTTP 403.
    - User in Tenant Beta attempts GET /findings/{id} -> fails closed with HTTP 403.
    """
    from app.database import get_db
    db = get_db()

    scan_id_alpha = f"scan-alpha-{uuid.uuid4().hex[:6]}"
    finding_id_alpha = f"find-alpha-{uuid.uuid4().hex[:6]}"

    # Seed Tenant Alpha scan and finding directly into DB
    await db["scans"].insert_one({
        "id": scan_id_alpha,
        "name": "Scan of Alpha Infrastructure",
        "scope": {"target": "https://alpha.example.com"},
        "tenant_id": "tenant_alpha",
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    })
    await db["findings"].insert_one({
        "id": finding_id_alpha,
        "scan_id": scan_id_alpha,
        "title": "Alpha Confidential Flaw",
        "severity": "critical",
        "tenant_id": "tenant_alpha",
    })

    # Create users in different tenants
    suffix = uuid.uuid4().hex[:6]
    user_alpha = {
        "email": f"alice_{suffix}@tenant-alpha.com",
        "role": "analyst",
        "tenant_id": "tenant_alpha",
        "password_hash": "hash",
    }
    user_beta = {
        "email": f"bob_{suffix}@tenant-beta.com",
        "role": "analyst",
        "tenant_id": "tenant_beta",
        "password_hash": "hash",
    }
    await db["users"].insert_one(user_alpha)
    await db["users"].insert_one(user_beta)

    token_alpha = _create_jwt(user_alpha["email"], role="analyst", tenant_id="tenant_alpha")
    token_beta = _create_jwt(user_beta["email"], role="analyst", tenant_id="tenant_beta")

    # 1. Tenant Alpha user can see their scan
    res_alpha = await client.get("/api/scans", headers={"Authorization": f"Bearer {token_alpha}"})
    assert res_alpha.status_code == 200
    alpha_ids = [s["id"] for s in res_alpha.json().get("scans", [])]
    assert scan_id_alpha in alpha_ids

    # 2. Tenant Beta user queries scans -> must NOT see Tenant Alpha's scan
    res_beta = await client.get("/api/scans", headers={"Authorization": f"Bearer {token_beta}"})
    assert res_beta.status_code == 200
    beta_ids = [s["id"] for s in res_beta.json().get("scans", [])]
    assert scan_id_alpha not in beta_ids

    # 3. Tenant Beta user attempts horizontal privilege escalation via direct GET /scans/{scan_id_alpha}
    direct_scan_res = await client.get(f"/api/scans/{scan_id_alpha}", headers={"Authorization": f"Bearer {token_beta}"})
    assert direct_scan_res.status_code == 403
    assert "Tenant access denied" in direct_scan_res.json()["detail"]

    # 4. Tenant Beta user attempts horizontal privilege escalation via direct GET /findings/{finding_id_alpha}
    direct_find_res = await client.get(f"/api/findings/{finding_id_alpha}", headers={"Authorization": f"Bearer {token_beta}"})
    assert direct_find_res.status_code == 403
    assert "Tenant access denied" in direct_find_res.json()["detail"]


# ─── 7. Gate Checks: Security Review & Runbook Verification ─────────────────────

def test_gate_artifacts_exist_and_verified():
    """Verify that required Phase 7 governance artifacts exist with required sections."""
    root = Path(__file__).resolve().parent.parent.parent

    # 1. Security Review artifact
    sec_review_path = root / "docs" / "SECURITY_REVIEW.md"
    assert sec_review_path.is_file(), "SECURITY_REVIEW.md must exist"
    sec_content = sec_review_path.read_text(encoding="utf-8")
    assert "PASSED" in sec_content
    assert "STRIDE" in sec_content
    assert "Multi-Tenant Boundary Isolation" in sec_content

    # 2. Runbook artifact
    runbook_path = root / "docs" / "RUNBOOK.md"
    assert runbook_path.is_file(), "RUNBOOK.md must exist"
    runbook_content = runbook_path.read_text(encoding="utf-8")
    assert "Service Lifecycle Management" in runbook_content
    assert "Backup" in runbook_content
    assert "Alert Triage" in runbook_content

    # 3. Terms of Use artifact
    terms_path = root / "docs" / "TERMS_OF_USE.md"
    assert terms_path.is_file(), "TERMS_OF_USE.md must exist"
    terms_content = terms_path.read_text(encoding="utf-8")
    assert "Authorization and Legal Scope Mandate" in terms_content

    # 4. Acceptable Use Policy artifact
    aup_path = root / "docs" / "ACCEPTABLE_USE_POLICY.md"
    assert aup_path.is_file(), "ACCEPTABLE_USE_POLICY.md must exist"
    aup_content = aup_path.read_text(encoding="utf-8")
    assert "Strictly Prohibited Targets" in aup_content
    assert "Safe Minimum-Impact Standard" in aup_content

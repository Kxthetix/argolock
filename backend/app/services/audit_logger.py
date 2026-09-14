"""Immutable VAPT Audit Logger with Chained SHA-256 Hashing for ARGOLOCK NET v1.6."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.vapt_models import VAPTAuditRecord


class AuditLogger:
    """Provides tamper-evident, append-only audit logging for all VAPT activities."""

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        from app.database import get_db
        return get_db()

    async def log_action(
        self,
        actor: str,
        action: str,
        assessment_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        tool: Optional[str] = None,
        tool_version: Optional[str] = None,
        test_level: Optional[str] = None,
        approval_id: Optional[str] = None,
        result_summary: str = "",
        evidence_hash: Optional[str] = None,
        cleanup_verified: bool = True,
    ) -> VAPTAuditRecord:
        """Create and append an immutable audit record with cryptographic hash chaining."""
        db = self._get_db()

        # Find the latest audit record hash for chaining
        latest = await db["vapt_audit_logs"].find_one(
            {},
            sort=[("started_at", -1)]
        )
        prev_hash = latest.get("record_hash") if latest else "GENESIS_ROOT_ARGOLOCK_1.6"

        audit = VAPTAuditRecord(
            actor=actor,
            action=action,
            assessment_id=assessment_id,
            asset_id=asset_id,
            finding_id=finding_id,
            tool=tool,
            tool_version=tool_version,
            test_level=test_level,
            approval_id=approval_id,
            result_summary=result_summary,
            evidence_hash=evidence_hash,
            cleanup_verified=cleanup_verified,
            previous_record_hash=prev_hash,
            completed_at=datetime.now(timezone.utc),
        )

        # Compute tamper-evident record hash
        content = json.dumps({
            "actor": audit.actor,
            "action": audit.action,
            "assessment_id": audit.assessment_id,
            "asset_id": audit.asset_id,
            "finding_id": audit.finding_id,
            "tool": audit.tool,
            "test_level": audit.test_level,
            "approval_id": audit.approval_id,
            "result_summary": audit.result_summary,
            "evidence_hash": audit.evidence_hash,
            "previous_record_hash": audit.previous_record_hash,
            "started_at": audit.started_at.isoformat(),
        }, sort_keys=True)

        audit.record_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        await db["vapt_audit_logs"].insert_one(audit.model_dump())
        logger.info(f"[AuditLogger] Logged VAPT action '{action}' by {actor} on asset {asset_id} (Hash={audit.record_hash[:10]}...)")
        return audit

    async def list_audit_logs(
        self,
        asset_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        limit: int = 100
    ) -> List[VAPTAuditRecord]:
        db = self._get_db()
        query: Dict[str, Any] = {}
        if asset_id:
            query["asset_id"] = asset_id
        if finding_id:
            query["finding_id"] = finding_id

        cursor = db["vapt_audit_logs"].find(query, {"_id": 0}).sort("started_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [VAPTAuditRecord(**d) for d in docs]


audit_logger = AuditLogger()

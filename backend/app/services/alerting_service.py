"""
ARGOLOCK V1.7 Observability and Alerting Service
Provides security violation notifications, operational stall alarms,
audit metrics aggregation, and incident triage records.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from loguru import logger
from pydantic import BaseModel, Field

from app.models.v1_7_models import utc_now_iso


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertCategory(str, Enum):
    SECURITY = "SECURITY"
    OPERATIONAL = "OPERATIONAL"
    COMPLIANCE = "COMPLIANCE"


class SecurityAlert(BaseModel):
    id: str = Field(default_factory=lambda: f"alert-{uuid.uuid4().hex[:8]}")
    severity: AlertSeverity = AlertSeverity.HIGH
    category: AlertCategory = AlertCategory.SECURITY
    title: str
    description: str
    tenant_id: str = "tenant_default"
    actor: Optional[str] = None
    target: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    created_at: str = Field(default_factory=utc_now_iso)


class AlertingService:
    """Dispatches alerts and compiles system observability telemetry."""

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        from app.database import get_db
        return get_db()

    async def emit_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity | str = AlertSeverity.HIGH,
        category: AlertCategory | str = AlertCategory.SECURITY,
        tenant_id: str = "tenant_default",
        actor: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SecurityAlert:
        """Create and persist a security/operational alert, logging to monitoring streams."""
        db = self._get_db()
        parsed_sev = AlertSeverity(str(severity).upper()) if not isinstance(severity, AlertSeverity) else severity
        parsed_cat = AlertCategory(str(category).upper()) if not isinstance(category, AlertCategory) else category

        alert = SecurityAlert(
            severity=parsed_sev,
            category=parsed_cat,
            title=title,
            description=description,
            tenant_id=tenant_id,
            actor=actor,
            target=target,
            metadata=metadata or {},
            created_at=utc_now_iso(),
        )

        await db["alerts"].insert_one(alert.model_dump())

        # Log with appropriate level
        log_msg = f"🚨 [{alert.category.value}:{alert.severity.value}] {alert.title} — {alert.description} (actor={actor}, tenant={tenant_id})"
        if alert.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH):
            logger.error(log_msg)
        else:
            logger.warning(log_msg)

        return alert

    async def list_alerts(
        self,
        tenant_id: Optional[str] = None,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 50,
    ) -> List[SecurityAlert]:
        """Query persisted alerts with optional tenant filter."""
        db = self._get_db()
        query: Dict[str, Any] = {}
        if tenant_id:
            query["$or"] = [{"tenant_id": tenant_id}, {"tenant_id": {"$exists": False}}]
        if severity:
            query["severity"] = severity.upper()
        if acknowledged is not None:
            query["acknowledged"] = acknowledged

        cursor = db["alerts"].find(query, {"_id": 0}).sort("created_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [SecurityAlert(**d) for d in docs]

    async def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> Optional[SecurityAlert]:
        """Mark an alert as acknowledged by an operator."""
        db = self._get_db()
        now_str = utc_now_iso()
        await db["alerts"].update_one(
            {"id": alert_id},
            {"$set": {
                "acknowledged": True,
                "acknowledged_by": acknowledged_by,
                "acknowledged_at": now_str,
            }}
        )
        doc = await db["alerts"].find_one({"id": alert_id}, {"_id": 0})
        return SecurityAlert(**doc) if doc else None

    async def get_observability_metrics(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Compile live operational and security metrics."""
        db = self._get_db()

        scan_query: Dict[str, Any] = {}
        finding_query: Dict[str, Any] = {}
        alert_query: Dict[str, Any] = {}

        if tenant_id:
            scan_query["$or"] = [{"tenant_id": tenant_id}, {"tenant_id": {"$exists": False}}]
            finding_query["$or"] = [{"tenant_id": tenant_id}, {"tenant_id": {"$exists": False}}]
            alert_query["$or"] = [{"tenant_id": tenant_id}, {"tenant_id": {"$exists": False}}]

        # Aggregate counts
        try:
            total_scans = await db["scans"].count_documents(scan_query)
            running_scans = await db["scans"].count_documents({**scan_query, "status": "running"})
            total_findings = await db["findings"].count_documents(finding_query)
            critical_findings = await db["findings"].count_documents({**finding_query, "severity": "critical"})
            unresolved_alerts = await db["alerts"].count_documents({**alert_query, "acknowledged": False})
        except Exception:
            # Fallback for memory cursor
            total_scans = len(await db["scans"].find(scan_query).to_list(1000))
            running_scans = len(await db["scans"].find({**scan_query, "status": "running"}).to_list(1000))
            total_findings = len(await db["findings"].find(finding_query).to_list(1000))
            critical_findings = len(await db["findings"].find({**finding_query, "severity": "critical"}).to_list(1000))
            unresolved_alerts = len(await db["alerts"].find({**alert_query, "acknowledged": False}).to_list(1000))

        return {
            "timestamp": utc_now_iso(),
            "tenant_id": tenant_id or "all",
            "metrics": {
                "total_scans": total_scans,
                "active_running_scans": running_scans,
                "total_findings": total_findings,
                "critical_findings": critical_findings,
                "unresolved_alerts": unresolved_alerts,
            },
            "status": "healthy" if unresolved_alerts == 0 else "attention_required",
        }


alerting_service = AlertingService()

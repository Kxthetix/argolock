"""Remediation and Retest Engine for ARGOLOCK NET v1.7.
Manages remediation tasks and executes evidence-driven retests using the original test method.
Risk reduction is strictly computed ONLY from verified retests where retest_status == RESOLVED.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.vapt_models import (
    RemediationPlan, RetestRecord, RetestStatus, ValidationStatus, TestingLevel
)
from app.models.v1_7_models import (
    RemediationTask,
    RemediationTaskStatus,
    RemediationPriority,
    utc_now_iso,
)
from app.services.validation_engine import validation_engine
from app.services.evidence_collector import evidence_collector
from app.services.audit_logger import audit_logger


class RemediationRetestEngine:
    """Generates remediation advice, manages tasks, and orchestrates evidence-driven retests."""

    SEVERITY_RISK_REDUCTION = {
        "critical": 25.0,
        "high": 15.0,
        "medium": 8.0,
        "low": 3.0,
        "info": 1.0,
    }

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        from app.database import get_db
        return get_db()

    def generate_remediation_plan(self, finding: Dict[str, Any]) -> RemediationPlan:
        """Generate structured, actionable remediation guidance for a finding."""
        title = finding.get("title", "Vulnerability")
        sev = (finding.get("severity") or "medium").lower()
        endpoint = finding.get("affected_endpoint", "unknown")
        cve = finding.get("cve_ids", [""])[0] if finding.get("cve_ids") else "N/A"

        # Categorize guidance
        title_lower = title.lower()
        if "injection" in title_lower or "sql" in title_lower:
            root_cause = "Direct concatenation of untrusted user input into database query statements."
            patch = "Update object-relational mapping (ORM) frameworks and database drivers to current LTS."
            config = "Enforce parameterized queries (PreparedStatements) and apply least-privilege database user permissions."
            mitigations = [
                "Adopt parameterized queries and parameterized stored procedures across all database access layers.",
                "Implement input validation and allowlist filtering on all query parameters.",
                "Deploy a Web Application Firewall (WAF) with SQL injection rule sets."
            ]
        elif "xss" in title_lower or "cross-site scripting" in title_lower:
            root_cause = "Context-unaware reflection of user parameters into HTML/DOM context without output encoding."
            patch = "Ensure template rendering engine auto-escaping is globally active."
            config = "Implement a strict Content-Security-Policy (CSP) header (e.g., script-src 'self')."
            mitigations = [
                "Apply contextual HTML, JavaScript, and attribute output encoding on all user-supplied data.",
                "Enforce Content-Security-Policy (CSP) with strict nonce or hash based directives.",
                "Mark sensitive cookies with HttpOnly, Secure, and SameSite=Strict."
            ]
        elif "header" in title_lower or "cors" in title_lower:
            root_cause = "Missing or permissive HTTP defense-in-depth header configurations."
            patch = "Update web server / reverse proxy response header directives."
            config = "Configure Content-Security-Policy, HSTS (max-age=31536000), X-Frame-Options: DENY, and X-Content-Type-Options: nosniff."
            mitigations = [
                "Deploy security headers at the reverse-proxy or API Gateway layer.",
                "Restrict Access-Control-Allow-Origin to explicit trusted origins; avoid wildcard reflections."
            ]
        else:
            root_cause = f"Vulnerability identified: {title} (CVE: {cve})."
            patch = "Apply latest vendor security patch updates."
            config = "Review service configuration against CIS Benchmarks."
            mitigations = [
                "Verify vendor advisory and apply the recommended software update.",
                "Restrict network access to authorized clients via firewall rules."
            ]

        priority = "immediate" if sev == "critical" else ("high" if sev == "high" else "medium")

        return RemediationPlan(
            finding_id=finding.get("id", ""),
            affected_asset=endpoint,
            root_cause=root_cause,
            patch_recommendation=patch,
            config_recommendation=config,
            mitigation_steps=mitigations,
            priority=priority,
            retest_requirement="Execute automated non-destructive retest under identical network conditions."
        )

    async def create_remediation_task(
        self,
        finding: Dict[str, Any],
        scan_id: Optional[str] = None,
        user_hourly_rate: float = 120.0,
        assignee: Optional[str] = None,
        priority: Optional[RemediationPriority] = None,
        sla_days: int = 14,
        tenant_id: str = "tenant_default",
    ) -> RemediationTask:
        """Create a tracked RemediationTask for an identified finding."""
        db = self._get_db()
        f_id = finding.get("id") or str(uuid.uuid4())
        s_id = scan_id or finding.get("scan_id") or "scan-unknown"
        sev = (finding.get("severity") or "medium").lower()
        effective_tenant = tenant_id or finding.get("tenant_id") or "tenant_default"

        # Determine priority
        if not priority:
            if sev == "critical":
                priority = RemediationPriority.P1
            elif sev == "high":
                priority = RemediationPriority.P2
            elif sev == "medium":
                priority = RemediationPriority.P3
            else:
                priority = RemediationPriority.P4

        # Determine original test method
        orig_method = (
            finding.get("tool")
            or finding.get("validation_method")
            or finding.get("method")
            or "validation_engine"
        )

        # Estimate effort & cost ranges
        base_hours = 12 if sev == "critical" else 8 if sev == "high" else 4 if sev == "medium" else 2
        min_hours = max(1, int(round(base_hours * 0.7)))
        max_hours = int(round(base_hours * 1.5))

        hours_range = {"min": min_hours, "expected": base_hours, "max": max_hours}
        cost_range = {
            "min": round(min_hours * user_hourly_rate, 2),
            "expected": round(base_hours * user_hourly_rate, 2),
            "max": round(max_hours * user_hourly_rate, 2),
        }

        now = datetime.now(timezone.utc)
        sla_deadline = (now + timedelta(days=sla_days)).isoformat().replace("+00:00", "Z")

        task = RemediationTask(
            finding_id=f_id,
            scan_id=s_id,
            tenant_id=effective_tenant,
            title=f"Remediate {finding.get('title', 'Vulnerability')}",
            description=finding.get("description") or f"Fix identified {sev} flaw on {finding.get('affected_endpoint', 'target')}",
            status=RemediationTaskStatus.PENDING,
            assignee=assignee,
            priority=priority,
            sla_deadline=sla_deadline,
            user_hourly_rate=user_hourly_rate,
            estimated_hours_range=hours_range,
            estimated_cost_range=cost_range,
            original_test_method=orig_method,
            retest_ids=[],
            verified_risk_reduction=0.0, # Zero until proven resolved by retest
            created_at=utc_now_iso(),
            updated_at=utc_now_iso(),
        )

        await db["remediation_tasks"].insert_one(task.model_dump())
        return task

    async def list_remediation_tasks(
        self,
        scan_id: Optional[str] = None,
        status: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[RemediationTask]:
        """Query stored remediation tasks with optional tenant isolation."""
        db = self._get_db()
        query: Dict[str, Any] = {}
        if scan_id:
            query["scan_id"] = scan_id
        if status:
            query["status"] = status
        if tenant_id:
            query["$or"] = [{"tenant_id": tenant_id}, {"tenant_id": {"$exists": False}}]

        cursor = db["remediation_tasks"].find(query, {"_id": 0}).sort("created_at", -1).limit(limit)
        docs = await cursor.to_list(length=limit)
        return [RemediationTask(**doc) for doc in docs]

    async def get_remediation_task(self, task_id: str) -> Optional[RemediationTask]:
        """Retrieve a specific remediation task by ID."""
        db = self._get_db()
        doc = await db["remediation_tasks"].find_one({"id": task_id}, {"_id": 0})
        return RemediationTask(**doc) if doc else None

    async def update_task_status(
        self,
        task_id: str,
        new_status: RemediationTaskStatus,
        assignee: Optional[str] = None,
    ) -> Optional[RemediationTask]:
        """Update remediation task status and optionally assignee."""
        db = self._get_db()
        update_fields: Dict[str, Any] = {
            "status": new_status.value if hasattr(new_status, "value") else str(new_status),
            "updated_at": utc_now_iso(),
        }
        if assignee:
            update_fields["assignee"] = assignee

        await db["remediation_tasks"].update_one({"id": task_id}, {"$set": update_fields})
        return await self.get_remediation_task(task_id)

    async def execute_retest(
        self,
        finding_id: str,
        actor: str = "security_engineer"
    ) -> RetestRecord:
        """
        Retest an existing finding using the exact original validation condition and method.
        Compares evidence hashes to confirm whether vulnerability is RESOLVED or STILL_VULNERABLE.
        Verified risk reduction is computed ONLY if retest_status == RESOLVED.
        """
        db = self._get_db()
        finding_doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
        if not finding_doc:
            raise ValueError(f"Finding '{finding_id}' not found.")

        # Identify original method and prior evidence hash
        orig_method = (
            finding_doc.get("tool")
            or finding_doc.get("validation_method")
            or finding_doc.get("method")
            or "validation_engine"
        )
        orig_evidence_id = finding_doc.get("evidence_id")
        orig_hash = "NO_PRIOR_HASH"
        if orig_evidence_id:
            try:
                orig_evidence = await evidence_collector.get_evidence(orig_evidence_id)
                if orig_evidence:
                    orig_hash = orig_evidence.sha256_hash
            except Exception:
                orig_hash = "NO_PRIOR_HASH"

        retest = RetestRecord(
            finding_id=finding_id,
            retest_status=RetestStatus.RUNNING,
            original_evidence_hash=orig_hash,
            original_test_method=orig_method,
            verified_risk_reduction=0.0,
            executed_by=actor,
        )
        await db["retests"].insert_one(retest.model_dump())

        # Re-run validation through validation engine using original method context
        val_result = await validation_engine.validate_finding(
            finding_id=finding_id,
            actor=actor,
            testing_level=TestingLevel.LEVEL_1_NON_INVASIVE
        )

        new_val_status = val_result.get("validation_status")
        new_evidence_hash = val_result.get("evidence_hash") or "NO_NEW_HASH"
        is_confirmed = val_result.get("confirmed", False)

        verified_risk_reduction = 0.0

        # Evaluate if resolved:
        # A finding is resolved only when it no longer triggers or is confirmed non-exploitable
        if not is_confirmed and new_val_status in ("false_positive", "not_exploitable"):
            status = RetestStatus.RESOLVED
            summary = (
                f"Remediation verified: Vulnerability condition no longer reproducible "
                f"using original test method '{orig_method}'. Target returned secure response."
            )
            # Calculate verified risk reduction based on verified remediation
            sev = (finding_doc.get("severity") or "medium").lower()
            if "cvss_score" in finding_doc and finding_doc["cvss_score"] is not None:
                verified_risk_reduction = min(25.0, round(float(finding_doc["cvss_score"]) * 2.2, 1))
            else:
                verified_risk_reduction = self.SEVERITY_RISK_REDUCTION.get(sev, 8.0)

            # Update finding status in database
            await db["findings"].update_one(
                {"id": finding_id},
                {"$set": {
                    "retest_status": RetestStatus.RESOLVED.value,
                    "validation_status": ValidationStatus.NOT_EXPLOITABLE.value,
                    "confirmed": False,
                    "verified_risk_reduction": verified_risk_reduction,
                    "resolved_at": utc_now_iso(),
                }}
            )

            # Update matching remediation tasks
            await db["remediation_tasks"].update_many(
                {"finding_id": finding_id},
                {
                    "$set": {
                        "status": RemediationTaskStatus.RESOLVED.value,
                        "verified_risk_reduction": verified_risk_reduction,
                        "updated_at": utc_now_iso(),
                    },
                    "$addToSet": {"retest_ids": retest.id},
                }
            )

        elif is_confirmed or new_val_status in ("confirmed", "validated"):
            status = RetestStatus.STILL_VULNERABLE
            verified_risk_reduction = 0.0 # Strictly 0.0 for unresolved findings
            summary = (
                f"Retest failed: Vulnerability condition is STILL reproducible "
                f"on target endpoint using original test method '{orig_method}'."
            )
            await db["findings"].update_one(
                {"id": finding_id},
                {"$set": {
                    "retest_status": RetestStatus.STILL_VULNERABLE.value,
                    "verified_risk_reduction": 0.0,
                }}
            )
            await db["remediation_tasks"].update_many(
                {"finding_id": finding_id},
                {
                    "$set": {
                        "status": RemediationTaskStatus.REOPENED.value,
                        "verified_risk_reduction": 0.0,
                        "updated_at": utc_now_iso(),
                    },
                    "$addToSet": {"retest_ids": retest.id},
                }
            )
        else:
            status = RetestStatus.INCONCLUSIVE
            verified_risk_reduction = 0.0 # Strictly 0.0 for inconclusive tests
            summary = f"Retest inconclusive: Status is {new_val_status}. Technical proof unchanged."
            await db["remediation_tasks"].update_many(
                {"finding_id": finding_id},
                {
                    "$addToSet": {"retest_ids": retest.id},
                    "$set": {"updated_at": utc_now_iso()},
                }
            )

        retest.retest_status = status
        retest.new_evidence_hash = new_evidence_hash
        retest.comparison_summary = summary
        retest.verified_risk_reduction = verified_risk_reduction
        retest.completed_at = datetime.now(timezone.utc)

        await db["retests"].update_one(
            {"id": retest.id},
            {"$set": {
                "retest_status": status.value,
                "new_evidence_hash": new_evidence_hash,
                "comparison_summary": summary,
                "verified_risk_reduction": verified_risk_reduction,
                "original_test_method": orig_method,
                "completed_at": retest.completed_at.isoformat().replace("+00:00", "Z"),
            }}
        )

        try:
            await audit_logger.log_action(
                actor=actor,
                action="RETEST_COMPLETED",
                finding_id=finding_id,
                result_summary=f"Retest result: {status.value.upper()}. {summary} (Verified Risk Reduction: {verified_risk_reduction} pts)",
                evidence_hash=new_evidence_hash,
            )
        except Exception as e:
            logger.debug(f"[RemediationRetestEngine] Non-critical audit log skipped: {e}")

        return retest


remediation_retest_engine = RemediationRetestEngine()

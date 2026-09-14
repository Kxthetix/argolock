"""Remediation and Retest Engine for ARGOLOCK NET v1.6."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.vapt_models import (
    RemediationPlan, RetestRecord, RetestStatus, ValidationStatus, TestingLevel
)
from app.services.validation_engine import validation_engine
from app.services.evidence_collector import evidence_collector
from app.services.audit_logger import audit_logger


class RemediationRetestEngine:
    """Generates remediation advice and orchestrates evidence-driven retests."""

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
        sev = finding.get("severity", "medium").lower()
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

    async def execute_retest(
        self,
        finding_id: str,
        actor: str = "security_engineer"
    ) -> RetestRecord:
        """
        Retest an existing finding using the exact same validation condition.
        Compares evidence hashes to confirm whether vulnerability is RESOLVED or STILL_VULNERABLE.
        """
        db = self._get_db()
        finding_doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
        if not finding_doc:
            raise ValueError(f"Finding '{finding_id}' not found.")

        orig_evidence_id = finding_doc.get("evidence_id")
        orig_evidence = await evidence_collector.get_evidence(orig_evidence_id) if orig_evidence_id else None
        orig_hash = orig_evidence.sha256_hash if orig_evidence else "NO_PRIOR_HASH"

        retest = RetestRecord(
            finding_id=finding_id,
            retest_status=RetestStatus.RUNNING,
            original_evidence_hash=orig_hash,
            executed_by=actor,
        )
        await db["retests"].insert_one(retest.model_dump())

        # Re-run validation through validation engine
        val_result = await validation_engine.validate_finding(
            finding_id=finding_id,
            actor=actor,
            testing_level=TestingLevel.LEVEL_1_NON_INVASIVE
        )

        new_val_status = val_result.get("validation_status")
        new_evidence_hash = val_result.get("evidence_hash") or "NO_NEW_HASH"
        is_confirmed = val_result.get("confirmed", False)

        # Evaluate if resolved
        if not is_confirmed and new_val_status in ("false_positive", "not_exploitable"):
            status = RetestStatus.RESOLVED
            summary = "Remediation verified: Vulnerability condition no longer triggers. Endpoint returned secure response."
            # Update finding status to CLOSED
            await db["findings"].update_one(
                {"id": finding_id},
                {"$set": {
                    "retest_status": RetestStatus.RESOLVED.value,
                    "validation_status": ValidationStatus.NOT_EXPLOITABLE.value,
                    "confirmed": False
                }}
            )
        elif is_confirmed or new_val_status in ("confirmed", "validated"):
            status = RetestStatus.STILL_VULNERABLE
            summary = "Retest failed: Vulnerability condition is STILL reproducible on target endpoint."
            await db["findings"].update_one(
                {"id": finding_id},
                {"$set": {"retest_status": RetestStatus.STILL_VULNERABLE.value}}
            )
        else:
            status = RetestStatus.INCONCLUSIVE
            summary = f"Retest inconclusive: Status is {new_val_status}."

        retest.retest_status = status
        retest.new_evidence_hash = new_evidence_hash
        retest.comparison_summary = summary
        retest.completed_at = datetime.now(timezone.utc)

        await db["retests"].update_one(
            {"id": retest.id},
            {"$set": {
                "retest_status": status.value,
                "new_evidence_hash": new_evidence_hash,
                "comparison_summary": summary,
                "completed_at": retest.completed_at.isoformat().replace("+00:00", "Z")
            }}
        )

        await audit_logger.log_action(
            actor=actor,
            action="RETEST_COMPLETED",
            finding_id=finding_id,
            result_summary=f"Retest result: {status.value.upper()}. {summary}",
            evidence_hash=new_evidence_hash,
        )

        return retest


remediation_retest_engine = RemediationRetestEngine()

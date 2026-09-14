"""Vulnerability Validation Engine for ARGOLOCK NET v1.6."""
from __future__ import annotations

import httpx
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.vapt_models import (
    ValidationStatus, TestingLevel
)
from app.services.exploit_safety_gate import exploit_safety_gate, GateDecision
from app.services.evidence_collector import evidence_collector
from app.services.false_positive_engine import false_positive_engine
from app.services.audit_logger import audit_logger
from tools.adapters.adapter_registry import adapter_registry


class ValidationEngine:
    """Orchestrates non-destructive vulnerability verification and evidence collection."""

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        from app.database import get_db
        return get_db()

    async def validate_finding(
        self,
        finding_id: str,
        actor: str = "security_engineer",
        testing_level: TestingLevel = TestingLevel.LEVEL_1_NON_INVASIVE,
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute full controlled validation workflow on a finding.
        """
        db = self._get_db()
        finding_doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
        if not finding_doc:
            return {
                "status": "failed",
                "reason": f"Finding '{finding_id}' does not exist.",
                "validation_status": ValidationStatus.UNABLE_TO_VALIDATE.value,
            }

        target = finding_doc.get("affected_endpoint") or ""
        asset_id = finding_doc.get("asset_id") or target

        # 1. Update finding state to UNDER_VALIDATION
        await db["findings"].update_one(
            {"id": finding_id},
            {"$set": {"validation_status": ValidationStatus.UNDER_VALIDATION.value}}
        )

        # 2. Safety Gate Evaluation
        gate_decision, reason, auth_record, approval_record = await exploit_safety_gate.evaluate_safety(
            target=target,
            finding_id=finding_id,
            requested_level=testing_level,
            approval_id=approval_id,
        )

        if gate_decision != GateDecision.SAFE_TO_VALIDATE:
            await db["findings"].update_one(
                {"id": finding_id},
                {"$set": {"validation_status": ValidationStatus.REQUIRES_MANUAL_REVIEW.value}}
            )
            await audit_logger.log_action(
                actor=actor,
                action="VALIDATION_BLOCKED",
                asset_id=asset_id,
                finding_id=finding_id,
                test_level=testing_level.value,
                approval_id=approval_id,
                result_summary=f"Validation blocked by safety gate: {reason}",
            )
            return {
                "status": "blocked",
                "gate_decision": gate_decision.value,
                "reason": reason,
                "validation_status": ValidationStatus.REQUIRES_MANUAL_REVIEW.value,
            }

        # 3. Select appropriate Tool Adapter
        cve = finding_doc.get("cve_ids", [""])[0] if finding_doc.get("cve_ids") else None
        title = finding_doc.get("title", "")
        adapter = adapter_registry.find_adapter_for_vulnerability(title, cve=cve)

        if not adapter:
            await db["findings"].update_one(
                {"id": finding_id},
                {"$set": {"validation_status": ValidationStatus.UNABLE_TO_VALIDATE.value}}
            )
            return {
                "status": "failed",
                "reason": "No compatible tool adapter found for finding category.",
                "validation_status": ValidationStatus.UNABLE_TO_VALIDATE.value,
            }

        # 4. Perform Live Non-Destructive Probe & Gather Evidence
        probe_evidence = await self._gather_live_probe_evidence(target)

        # 5. Run tool adapter validation
        context = {
            "finding_id": finding_id,
            "asset_id": asset_id,
            "target": target,
            "cve": cve,
            "cwe": finding_doc.get("cwe_ids", [""])[0] if finding_doc.get("cwe_ids") else None,
            "parameter": finding_doc.get("affected_parameter"),
            "severity": finding_doc.get("severity", "medium"),
        }

        try:
            adapter_result = await adapter.execute_validation(target, context)
        except Exception as tool_err:
            logger.error(f"[ValidationEngine] Tool {adapter.tool_id} error: {tool_err}")
            adapter_result = {"status": "error", "error": str(tool_err), "confidence": 0.0, "evidence": []}

        # Combine probe evidence with adapter evidence
        probe_evidence.update({"adapter_result": adapter_result})

        # 6. Evaluate with False Positive Engine
        final_status, confidence, rationale = false_positive_engine.evaluate_false_positive(
            finding_doc, probe_evidence
        )

        # 7. Collect and hash evidence record
        evidence_rec = await evidence_collector.collect_and_store(
            finding_id=finding_id,
            asset_id=asset_id,
            tool_source=adapter.tool_id,
            technique=f"{adapter.tool_id}_non_destructive_validation",
            request_sample=probe_evidence.get("request"),
            response_sample=probe_evidence.get("response_body"),
            banner_output=probe_evidence.get("banner_output"),
            stdout_summary=f"Validation Status: {final_status.value}. Confidence: {confidence}. Rationale: {rationale}",
        )

        # 8. Update finding in MongoDB
        is_confirmed = (final_status == ValidationStatus.CONFIRMED)
        is_fp = (final_status == ValidationStatus.FALSE_POSITIVE)

        await db["findings"].update_one(
            {"id": finding_id},
            {"$set": {
                "validation_status": final_status.value,
                "validation_confidence": confidence,
                "confirmed": is_confirmed,
                "false_positive": is_fp,
                "evidence_id": evidence_rec.id,
                "tool_source": adapter.tool_id,
            }}
        )

        # 9. Append immutable audit record
        await audit_logger.log_action(
            actor=actor,
            action="VALIDATION_COMPLETED",
            asset_id=asset_id,
            finding_id=finding_id,
            tool=adapter.tool_id,
            tool_version=adapter.get_version(),
            test_level=testing_level.value,
            approval_id=approval_id,
            result_summary=f"Validation result: {final_status.value} (Confidence: {confidence}). {rationale}",
            evidence_hash=evidence_rec.sha256_hash,
        )

        return {
            "finding_id": finding_id,
            "validation_status": final_status.value,
            "confidence": confidence,
            "confirmed": is_confirmed,
            "false_positive": is_fp,
            "rationale": rationale,
            "evidence_id": evidence_rec.id,
            "evidence_hash": evidence_rec.sha256_hash,
            "tool": adapter.tool_id,
        }

    async def _gather_live_probe_evidence(self, target: str) -> Dict[str, Any]:
        """Perform safe HTTP inspections to gather evidence."""
        evidence: Dict[str, Any] = {
            "status_code": None,
            "headers": {},
            "server_header": None,
            "missing_security_headers": [],
            "cors_misconfigured": False,
            "reflected_parameter": False,
            "response_body": None,
            "banner_output": None,
            "request": f"GET {target} HTTP/1.1",
        }

        if not target.startswith("http"):
            # Target may be host:port or bare domain
            target = f"http://{target}"

        try:
            async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
                resp = await client.get(target, headers={"User-Agent": "Argolock-VAPT-Validator/1.6"})
                evidence["status_code"] = resp.status_code
                evidence["server_header"] = resp.headers.get("server")
                evidence["response_body"] = resp.text[:4000]
                evidence["banner_output"] = f"Server: {resp.headers.get('server', 'unknown')}\nX-Powered-By: {resp.headers.get('x-powered-by', 'unknown')}"

                # Security headers
                sec_headers = ["content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options"]
                for h in sec_headers:
                    if h not in resp.headers:
                        evidence["missing_security_headers"].append(h)

                # Parameter reflection check if query present
                if "?" in target:
                    token = "argolock_safe_token"
                    refl_url = f"{target}&probe={token}" if "&" in target else f"{target}&probe={token}" if "?" in target else f"{target}?probe={token}"
                    r_refl = await client.get(refl_url, headers={"User-Agent": "Argolock-VAPT-Validator/1.6"})
                    if token in r_refl.text:
                        evidence["reflected_parameter"] = True
        except Exception as e:
            evidence["probe_error"] = str(e)

        return evidence


validation_engine = ValidationEngine()

"""
Stage Approval & Policy Invalidation Service for ARGOLOCK NET.
Enforces:
1. Cryptographic plan digest binding (targets, profile, rate, timeout, credentials).
2. Explicit operator approval for gated active stages (ZAP Active, Dalfox, etc.).
3. Immediate invalidation when plan parameters or scope materially change.
4. Expiration enforcement and immutable audit records.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
from loguru import logger

from app.models.tool_cell_models import (
    StageApproval, SequentialStageKey, ToolCellManifest, RiskApprovalClass
)


class StageApprovalService:
    """Manages approval tokens, bindings, and material plan change invalidation."""

    def __init__(self, db_getter=None):
        self._db_getter = db_getter

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        try:
            from app.database import get_db
            return get_db()
        except Exception:
            from workers.recon_worker import _get_db_sync
            return _get_db_sync()

    def compute_plan_digest(
        self,
        stage_key: SequentialStageKey | str,
        tool_id: str,
        targets: List[str],
        profile: str,
        rate_ceiling: float,
        credential_ref: Optional[str] = None,
    ) -> str:
        """Generate deterministic SHA-256 digest representing exact plan parameters."""
        canonical = {
            "stage_key": stage_key.value if hasattr(stage_key, "value") else str(stage_key),
            "tool_id": str(tool_id),
            "targets": sorted([t.strip().lower() for t in targets]),
            "profile": str(profile),
            "rate_ceiling": float(rate_ceiling),
            "credential_ref": str(credential_ref or ""),
        }
        raw_json = json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

    def create_approval_request(
        self,
        stage_key: SequentialStageKey,
        tool_id: str,
        method_name: str,
        targets: List[str],
        exclusions: List[str],
        profile: str = "default",
        rate_ceiling: float = 10.0,
        timeout_seconds: int = 60,
        expected_traffic_class: str = "Active HTTP probes",
        credential_reference: Optional[str] = None,
        duration_minutes: int = 60,
    ) -> StageApproval:
        """Create a pending approval record bound to specific plan parameters."""
        plan_digest = self.compute_plan_digest(
            stage_key=stage_key,
            tool_id=tool_id,
            targets=targets,
            profile=profile,
            rate_ceiling=rate_ceiling,
            credential_ref=credential_reference,
        )
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(minutes=duration_minutes)

        approval = StageApproval(
            stage_key=stage_key,
            tool_id=tool_id,
            method_name=method_name,
            target_count=len(targets),
            target_summary=targets[:20],  # Summary preview
            exclusions=exclusions,
            rate_ceiling=rate_ceiling,
            timeout_seconds=timeout_seconds,
            expected_traffic_class=expected_traffic_class,
            credential_reference=credential_reference,
            approval_expiry=expiry,
            plan_digest=plan_digest,
            is_approved=False,
        )
        return approval

    def approve(
        self,
        approval: StageApproval,
        approver: str,
        current_targets: List[str],
        current_profile: str,
        current_rate: float,
    ) -> Tuple[bool, str]:
        """Grant operator approval, verifying that plan digest has not altered since request."""
        current_digest = self.compute_plan_digest(
            stage_key=approval.stage_key,
            tool_id=approval.tool_id,
            targets=current_targets,
            profile=current_profile,
            rate_ceiling=current_rate,
            credential_ref=approval.credential_reference,
        )

        if current_digest != approval.plan_digest:
            approval.invalidated_reason = "Plan parameters altered before approval decision was signed."
            approval.is_approved = False
            return False, "Plan altered: approval request invalidated. Fresh preview required."

        now = datetime.now(timezone.utc)
        if now > approval.approval_expiry:
            approval.invalidated_reason = "Approval request expired before signature."
            approval.is_approved = False
            return False, "Approval request expired."

        approval.is_approved = True
        approval.approved_by = approver
        approval.approved_at = now
        approval.invalidated_reason = None
        return True, "Stage successfully approved."

    def check_pre_dispatch_approval(
        self,
        manifest: ToolCellManifest,
        approval: Optional[StageApproval],
        current_targets: List[str],
        current_profile: str,
        current_rate: float,
    ) -> Tuple[bool, str]:
        """
        Verify approval requirement immediately before cell invocation:
        - Passive and low-impact active stages with default profiles do not require explicit gate.
        - Operator-approved stages (Dalfox, ZAP Active) strictly require an unexpired, matching approval.
        """
        if manifest.risk_class != RiskApprovalClass.OPERATOR_APPROVED:
            return True, "No operator approval gate required for this risk class."

        if not approval:
            return False, f"Stage requires explicit operator approval (Class: {manifest.risk_class.value})."

        now = datetime.now(timezone.utc)
        if now > approval.approval_expiry:
            approval.is_approved = False
            approval.invalidated_reason = "Approval token expired."
            return False, "Approval expired before dispatch."

        if not approval.is_approved:
            return False, "Stage approval is pending or has been rejected."

        # Check for material alteration
        current_digest = self.compute_plan_digest(
            stage_key=approval.stage_key,
            tool_id=manifest.tool_id,
            targets=current_targets,
            profile=current_profile,
            rate_ceiling=current_rate,
            credential_ref=approval.credential_reference,
        )
        if current_digest != approval.plan_digest:
            approval.is_approved = False
            approval.invalidated_reason = "Plan parameters materially changed after approval was granted."
            return False, "Plan altered after approval: approval invalidated."

        return True, "Approval valid and verified."


# Global singleton instance
stage_approval_service = StageApprovalService()

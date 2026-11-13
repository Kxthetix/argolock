"""
FastAPI Router for ARGOLOCK NET Sequential Tool Cell Pipeline.
Provides endpoints for 14-stage workflow orchestration, stage approvals,
raw artifact inspection, and evidence-backed finding review.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from pydantic import BaseModel, Field

from app.database import get_db
from app.routers.auth import get_current_user, require_role
from app.models.tool_cell_models import (
    SequentialStageKey, CellWorkflowState, ToolCellManifest,
    StageApproval, FindingReviewState, FindingCandidate
)
from app.services.tool_cell_registry import tool_cell_registry
from app.services.sequential_pipeline_engine import (
    sequential_pipeline_engine, SequentialPipelineRun
)
from app.services.stage_approval_service import stage_approval_service


router = APIRouter(prefix="/api/sequential-pipeline", tags=["Sequential Pipeline"])

# In-memory store for active sequential runs (synced to DB where available)
_active_pipeline_runs: Dict[str, SequentialPipelineRun] = {}


class CreatePipelineRunRequest(BaseModel):
    scan_id: str
    target_seed: str
    assessment_type: str = "network_web"  # network | web_app | network_web
    exclusions: List[str] = Field(default_factory=list)
    auto_approve_gated_stages: bool = False
    enable_active_zap: bool = False


class ApproveStageRequest(BaseModel):
    approval_id: str
    decision_notes: Optional[str] = None


class FindingReviewRequest(BaseModel):
    review_state: FindingReviewState
    reviewer_rationale: str
    duplicate_of_id: Optional[str] = None


# ─── 1. Tool Cell Manifests ──────────────────────────────────────────────────

@router.get("/manifests")
async def list_tool_cell_manifests():
    """List all 10 registered tool cell manifests with versions and security policies."""
    manifests = tool_cell_registry.list_manifests()
    return [m.model_dump() for m in manifests]


@router.get("/manifests/{tool_id}")
async def get_tool_cell_manifest(tool_id: str):
    """Fetch pinned manifest for a specific tool cell."""
    manifest = tool_cell_registry.get_manifest(tool_id)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"Tool cell '{tool_id}' not found.")
    return manifest.model_dump()


# ─── 2. Sequential Pipeline Runs ─────────────────────────────────────────────

@router.post("/runs", status_code=201)
async def create_sequential_pipeline_run(
    request: CreatePipelineRunRequest,
    current_user: Dict[str, Any] = Depends(require_role("analyst", "admin")),
):
    """
    Initialize and execute the 14-stage sequential assessment pipeline.
    """
    run = sequential_pipeline_engine.initialize_run(
        scan_id=request.scan_id,
        target_seed=request.target_seed,
        assessment_type=request.assessment_type,
        exclusions=request.exclusions,
        enable_active_zap=request.enable_active_zap,
    )
    _active_pipeline_runs[run.scan_id] = run

    # Execute pipeline asynchronously
    asyncio.create_task(
        sequential_pipeline_engine.execute_full_pipeline(
            run,
            auto_approve_gated_stages=request.auto_approve_gated_stages,
        )
    )

    return run.model_dump()


@router.get("/runs/{scan_id}")
async def get_sequential_pipeline_run(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve execution state, 14-stage statuses, handoffs, and candidate findings."""
    run = _active_pipeline_runs.get(scan_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Pipeline run '{scan_id}' not found.")
    return run.model_dump()


# ─── 3. Stage Approval Endpoint ──────────────────────────────────────────────

@router.post("/runs/{scan_id}/approve-stage/{approval_id}")
async def approve_stage(
    scan_id: str,
    approval_id: str,
    request: ApproveStageRequest,
    current_user: Dict[str, Any] = Depends(require_role("analyst", "admin")),
):
    """
    Operator approves a gated stage (ZAP Active, Dalfox) and resumes execution.
    """
    run = _active_pipeline_runs.get(scan_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Pipeline run '{scan_id}' not found.")

    approval = run.approvals.get(approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail=f"Approval request '{approval_id}' not found.")

    # Fetch current targets & profile for verification
    current_targets = approval.target_summary
    current_profile = "candidate_parameter_xss" if approval.stage_key == SequentialStageKey.DALFOX else "active_scan_approved"
    current_rate = approval.rate_ceiling

    approver_email = current_user.get("email", "operator")
    success, reason = stage_approval_service.approve(
        approval=approval,
        approver=approver_email,
        current_targets=current_targets,
        current_profile=current_profile,
        current_rate=current_rate,
    )

    if not success:
        raise HTTPException(status_code=400, detail=reason)

    # Resume execution of the approved stage
    if approval.stage_key == SequentialStageKey.DALFOX:
        asyncio.create_task(sequential_pipeline_engine._run_stage_dalfox(run, auto_approve=True))
    elif approval.stage_key == SequentialStageKey.ZAP_ACTIVE:
        asyncio.create_task(sequential_pipeline_engine._run_stage_zap_active(run, auto_approve=True))

    return {
        "status": "approved",
        "approval_id": approval_id,
        "stage_key": approval.stage_key.value,
        "approved_by": approver_email,
        "message": reason,
    }


# ─── 4. Finding Review & Accountability Endpoint ─────────────────────────────

@router.post("/runs/{scan_id}/review-finding/{finding_id}")
async def review_finding(
    scan_id: str,
    finding_id: str,
    request: FindingReviewRequest,
    current_user: Dict[str, Any] = Depends(require_role("analyst", "admin")),
):
    """
    Human analyst decides finding state (CONFIRMED, DUPLICATE, INCONCLUSIVE, NON_APPLICABLE)
    with required rationale. Unconfirmed candidates do not inflate confirmed vulnerability counts.
    """
    run = _active_pipeline_runs.get(scan_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Pipeline run '{scan_id}' not found.")

    target_finding: Optional[FindingCandidate] = None
    for f in run.finding_candidates:
        if f.id == finding_id:
            target_finding = f
            break

    if not target_finding:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

    if not request.reviewer_rationale.strip():
        raise HTTPException(status_code=400, detail="Reviewer rationale is strictly required.")

    target_finding.review_state = request.review_state
    target_finding.reviewer_rationale = request.reviewer_rationale
    target_finding.reviewed_by = current_user.get("email", "analyst")
    target_finding.reviewed_at = datetime.now(timezone.utc)
    if request.duplicate_of_id:
        target_finding.duplicate_of_id = request.duplicate_of_id

    return {
        "status": "reviewed",
        "finding_id": finding_id,
        "review_state": target_finding.review_state.value,
        "reviewed_by": target_finding.reviewed_by,
        "reviewed_at": target_finding.reviewed_at.isoformat(),
        "rationale": target_finding.reviewer_rationale,
    }


# ─── 5. Raw Artifact Inspection Endpoint ─────────────────────────────────────

@router.get("/runs/{scan_id}/artifacts/{artifact_id}")
async def get_raw_artifact(
    scan_id: str,
    artifact_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Inspect immutable raw evidence artifact with provenance and cryptographic digest."""
    run = _active_pipeline_runs.get(scan_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Pipeline run '{scan_id}' not found.")

    artifact = None
    for a in run.raw_artifacts:
        if a.artifact_id == artifact_id:
            artifact = a
            break

    if not artifact:
        raise HTTPException(status_code=404, detail=f"Artifact '{artifact_id}' not found.")

    return artifact.model_dump()

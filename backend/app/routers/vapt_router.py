"""VAPT Orchestration & Validation API Router for ARGOLOCK NET v1.6."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger

from app.database import get_db
from app.routers.auth import get_current_user
from app.models.vapt_models import (
    TargetAuthorization, TestingApproval, TestingLevel, ApprovalStatus,
    RetestStatus, ValidationStatus
)
from app.services.target_authorization_service import target_auth_service
from app.services.validation_engine import validation_engine
from app.services.exploitability_engine import exploitability_engine
from app.services.contextual_risk_engine import contextual_risk_engine
from app.services.attack_path_engine import attack_path_engine
from app.services.remediation_retest_engine import remediation_retest_engine
from app.services.evidence_collector import evidence_collector
from app.services.audit_logger import audit_logger
from tools.adapters.adapter_registry import adapter_registry

router = APIRouter()


# ── Target Authorizations ────────────────────────────────────────────────────

@router.post("/authorizations", status_code=201)
async def create_target_authorization(
    auth_data: TargetAuthorization,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Register an explicitly authorized asset target into ARGOLOCK inventory."""
    created = await target_auth_service.create_authorization(auth_data)
    await audit_logger.log_action(
        actor=current_user.get("email", "operator"),
        action="TARGET_AUTHORIZED",
        asset_id=auth_data.asset_id,
        result_summary=f"Authorized target {auth_data.hostname_or_ip} with scope {auth_data.scope}",
    )
    return created.model_dump()


@router.get("/authorizations")
async def list_target_authorizations(
    limit: int = 100,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """List all authorized target assets."""
    auths = await target_auth_service.list_authorizations(limit=limit)
    return [a.model_dump() for a in auths]


# ── Testing Approvals ────────────────────────────────────────────────────────

@router.post("/approvals", status_code=201)
async def request_testing_approval(
    approval: TestingApproval,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Request operator approval for Level 2 or Level 3 testing."""
    db = get_db()
    approval.requested_by = current_user.get("email", "engineer")
    await db["testing_approvals"].insert_one(approval.model_dump())

    lvl = approval.testing_level.value if hasattr(approval.testing_level, "value") else str(approval.testing_level)
    await audit_logger.log_action(
        actor=approval.requested_by,
        action="APPROVAL_REQUESTED",
        asset_id=approval.asset_id,
        finding_id=approval.finding_id,
        test_level=lvl,
        approval_id=approval.id,
        result_summary=f"Requested {lvl} approval for finding {approval.finding_id}",
    )
    return approval.model_dump()


@router.get("/approvals")
async def list_testing_approvals(
    status: Optional[str] = None,
    limit: int = 100,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    db = get_db()
    query = {}
    if status:
        query["status"] = status
    cursor = db["testing_approvals"].find(query, {"_id": 0}).sort("created_at", -1).limit(limit)
    docs = await cursor.to_list(length=limit)
    return docs


@router.post("/approvals/{approval_id}/approve")
async def approve_testing_request(
    approval_id: str,
    decision_notes: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Operator authorizes a pending testing approval."""
    db = get_db()
    doc = await db["testing_approvals"].find_one({"id": approval_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Approval request not found.")

    approver = current_user.get("email", "lead_operator")
    now = datetime.now(timezone.utc)

    await db["testing_approvals"].update_one(
        {"id": approval_id},
        {"$set": {
            "status": ApprovalStatus.APPROVED.value,
            "approved_by": approver,
            "decision_notes": decision_notes,
            "decided_at": now.isoformat().replace("+00:00", "Z"),
        }}
    )

    await audit_logger.log_action(
        actor=approver,
        action="APPROVAL_GRANTED",
        asset_id=doc.get("asset_id"),
        finding_id=doc.get("finding_id"),
        test_level=doc.get("testing_level"),
        approval_id=approval_id,
        result_summary=f"Approved test request {approval_id}: {decision_notes or 'Operator approved.'}",
    )
    return {"status": "approved", "approval_id": approval_id, "approved_by": approver}


@router.post("/approvals/{approval_id}/reject")
async def reject_testing_request(
    approval_id: str,
    decision_notes: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Operator rejects a pending testing approval."""
    db = get_db()
    doc = await db["testing_approvals"].find_one({"id": approval_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Approval request not found.")

    approver = current_user.get("email", "lead_operator")
    now = datetime.now(timezone.utc)

    await db["testing_approvals"].update_one(
        {"id": approval_id},
        {"$set": {
            "status": ApprovalStatus.REJECTED.value,
            "approved_by": approver,
            "decision_notes": decision_notes,
            "decided_at": now.isoformat().replace("+00:00", "Z"),
        }}
    )

    await audit_logger.log_action(
        actor=approver,
        action="APPROVAL_REJECTED",
        asset_id=doc.get("asset_id"),
        finding_id=doc.get("finding_id"),
        test_level=doc.get("testing_level"),
        approval_id=approval_id,
        result_summary=f"Rejected test request {approval_id}: {decision_notes or 'Operator rejected.'}",
    )
    return {"status": "rejected", "approval_id": approval_id, "rejected_by": approver}


# ── Vulnerability Validation ─────────────────────────────────────────────────

@router.post("/findings/{finding_id}/validate")
async def validate_finding(
    finding_id: str,
    testing_level: TestingLevel = TestingLevel.LEVEL_1_NON_INVASIVE,
    approval_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Perform controlled non-destructive validation through the Safety Gate."""
    actor = current_user.get("email", "security_engineer")
    result = await validation_engine.validate_finding(
        finding_id=finding_id,
        actor=actor,
        testing_level=testing_level,
        approval_id=approval_id,
    )
    return result


@router.get("/findings/{finding_id}/exploitability")
async def get_exploitability(
    finding_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Evaluate multi-signal exploitability without executing attacks."""
    db = get_db()
    finding_doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
    if not finding_doc:
        raise HTTPException(status_code=404, detail="Finding not found")

    assessment = exploitability_engine.assess_exploitability(finding_doc)
    return assessment.model_dump()


@router.get("/findings/{finding_id}/evidence")
async def get_finding_evidence(
    finding_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve technical evidence with cryptographic SHA-256 verification."""
    db = get_db()
    finding_doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
    if not finding_doc:
        raise HTTPException(status_code=404, detail="Finding not found")

    evidence_id = finding_doc.get("evidence_id")
    if not evidence_id:
        return {"status": "no_evidence", "message": "No validation evidence captured yet."}

    evidence = await evidence_collector.get_evidence(evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    is_valid = evidence_collector.verify_integrity(evidence)

    return {
        "evidence": evidence.model_dump(),
        "integrity_verified": is_valid,
        "sha256_hash": evidence.sha256_hash,
        "redacted_fields": evidence.redacted_fields,
    }


@router.get("/findings/{finding_id}/remediation")
async def get_remediation_plan(
    finding_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve structured remediation steps and patch guidance."""
    db = get_db()
    finding_doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
    if not finding_doc:
        raise HTTPException(status_code=404, detail="Finding not found")

    plan = remediation_retest_engine.generate_remediation_plan(finding_doc)
    return plan.model_dump()


@router.post("/findings/{finding_id}/retest")
async def retest_finding(
    finding_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Execute evidence-driven retest under identical validation condition."""
    actor = current_user.get("email", "security_engineer")
    try:
        record = await remediation_retest_engine.execute_retest(finding_id, actor=actor)
        return record.model_dump()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/risk/{finding_id}")
async def get_contextual_risk(
    finding_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve explainable cyber risk calculation for a finding."""
    db = get_db()
    finding_doc = await db["findings"].find_one({"id": finding_id}, {"_id": 0})
    if not finding_doc:
        raise HTTPException(status_code=404, detail="Finding not found")

    assessment = exploitability_engine.assess_exploitability(finding_doc)
    risk_score = contextual_risk_engine.calculate_risk(finding_doc, assessment)
    return risk_score.model_dump()


# ── Attack Paths & MITRE ─────────────────────────────────────────────────────

@router.get("/attack-paths")
async def get_attack_paths(
    assessment_id: str = "default_assessment",
    target: str = "target.local",
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve generated attack path topologies and crown jewel impact paths."""
    db = get_db()
    cursor = db["findings"].find({"confirmed": True}, {"_id": 0}).limit(10)
    confirmed = await cursor.to_list(length=10)

    graph = attack_path_engine.generate_attack_path_graph(
        assessment_id=assessment_id,
        target=target,
        findings=confirmed,
    )
    return graph.model_dump()


@router.get("/mitre-mappings")
async def get_mitre_mappings(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Retrieve MITRE ATT&CK technique mappings for confirmed findings."""
    db = get_db()
    cursor = db["findings"].find({"confirmed": True}, {"_id": 0}).limit(50)
    confirmed = await cursor.to_list(length=50)

    mappings = [attack_path_engine.map_mitre(f).model_dump() for f in confirmed]
    return mappings


# ── Tool Health & Adapter Registry ───────────────────────────────────────────

@router.get("/tools/health")
async def get_tool_adapters_health(
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Return health status, versions, and capabilities of all tool adapters."""
    statuses = adapter_registry.get_all_health_statuses()
    return statuses


# ── Audit Trail ──────────────────────────────────────────────────────────────

@router.get("/audit")
async def get_audit_trail(
    asset_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    limit: int = 100,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Query immutable, tamper-evident VAPT audit records."""
    logs = await audit_logger.list_audit_logs(asset_id=asset_id, finding_id=finding_id, limit=limit)
    return [l.model_dump() for l in logs]

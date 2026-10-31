"""
ARGOLOCK V1.7 Core REST API Router (/api/v1)
Exposes Mission Controller, 60-Agent Operations, Capability Graphs,
Adversarial Validation, Cyber Risk Quantification, Investment Optimization,
Remediation Tasks & Retests, Assessment Trends, and Executive Business Questions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.database import get_db
from app.models.v1_7_models import (
    Mission,
    MissionMode,
    RemediationPriority,
    RemediationTask,
    RemediationTaskStatus,
    utc_now_iso,
)
from app.services.adversarial_validator import AdversarialValidator
from app.services.agent_registry import AgentRegistry
from app.services.capability_graph_service import CapabilityGraphService
from app.services.cyber_risk_service import CyberRiskEngine
from app.services.investment_optimizer_service import InvestmentOptimizer
from app.services.security_control_plane import SecurityControlPlane
from app.services.remediation_retest_engine import remediation_retest_engine
from app.services.trend_service import trend_service
from app.services.business_questions_service import business_questions_service

router = APIRouter(prefix="/api/v1", tags=["v1.7"])


class CreateMissionRequest(BaseModel):
    name: Optional[str] = None
    target: str
    mode: MissionMode = MissionMode.ASSESSMENT
    budget_seconds: int = 600
    scope_whitelist: Optional[List[str]] = None
    scope_blacklist: Optional[List[str]] = None


class KillSwitchRequest(BaseModel):
    mission_id: Optional[str] = None
    activate: bool = True


class CreateRemediationTaskRequest(BaseModel):
    finding_id: str
    scan_id: Optional[str] = None
    user_hourly_rate: float = 120.0
    assignee: Optional[str] = None
    priority: Optional[RemediationPriority] = None
    sla_days: int = 14


class UpdateRemediationTaskRequest(BaseModel):
    status: Optional[RemediationTaskStatus] = None
    assignee: Optional[str] = None


# ─── 1. Mission Controller ──────────────────────────────────────────────────────

@router.post("/missions", response_model=Mission)
async def create_mission(req: CreateMissionRequest):
    """Launch a new VAPT mission in Discovery, Assessment, Validation, or Continuous mode."""
    db = get_db()

    # Scope gate pre-check
    whitelist = req.scope_whitelist or [req.target]
    gate_res = SecurityControlPlane.evaluate_scope_gate(
        target_url_or_host=req.target,
        whitelist=whitelist,
        blacklist=req.scope_blacklist,
    )
    if not gate_res.allowed:
        raise HTTPException(status_code=400, detail=f"Scope Gate violation: {gate_res.reason}")

    mission_name = req.name or f"{req.mode.value} Mission: {req.target}"
    mission = Mission(
        name=mission_name,
        target=req.target,
        mode=req.mode,
        budget_seconds=req.budget_seconds,
        scope_whitelist=whitelist,
        scope_blacklist=req.scope_blacklist or [],
        status="running",
        current_phase="Reconnaissance" if req.mode != MissionMode.VALIDATION else "Validation",
        progress_percent=15,
        active_agent_count=7 if req.mode == MissionMode.ASSESSMENT else 3,
    )

    doc = mission.model_dump()
    await db["v1_7_missions"].insert_one(doc)
    return mission


@router.get("/missions")
async def list_missions(limit: int = 20):
    """List all VAPT missions."""
    db = get_db()
    cursor = db["v1_7_missions"].find({}, {"_id": 0}).sort("created_at", -1).limit(limit)
    return await cursor.to_list(length=limit)


@router.get("/missions/{mission_id}")
async def get_mission(mission_id: str):
    """Get mission details and live telemetry."""
    db = get_db()
    mission = await db["v1_7_missions"].find_one({"id": mission_id}, {"_id": 0})
    if not mission:
        raise HTTPException(status_code=404, detail="Mission not found")
    return mission


# ─── 2. 60-Agent Operations Matrix ──────────────────────────────────────────────

@router.get("/agents")
async def list_agents(category: Optional[str] = Query(None, description="Filter by category")):
    """List logical specialist agents across the 9 operational groups."""
    agents = AgentRegistry.list_agents(category)
    return {
        "total_agents": AgentRegistry.total_count(),
        "categories": AgentRegistry.get_categories(),
        "agents": [a.model_dump() for a in agents],
    }


@router.get("/agents/{code_or_id}")
async def get_agent_profile(code_or_id: str):
    """Get detailed specification for a specialist agent."""
    agent = AgentRegistry.get_agent(code_or_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent profile not found in registry")
    return agent.model_dump()


# ─── 3. Capability Graph & Attack Chains ────────────────────────────────────────

@router.get("/capability-graph/{scan_id}")
async def get_capability_graph(scan_id: str):
    """Generate and return the Attacker Capability Graph & Attack Chains for a scan."""
    db = get_db()
    scan = await db["scans"].find_one({"id": scan_id}, {"_id": 0})
    target = scan.get("scope", {}).get("target", "") if scan else ""

    cursor = db["findings"].find({"scan_id": scan_id}, {"_id": 0}).limit(50)
    findings = await cursor.to_list(length=50)

    graph = CapabilityGraphService.generate_graph(scan_id=scan_id, findings=findings, target=target)
    return graph


# ─── 4. Adversarial Validation (Devil's Advocate) ────────────────────────────────

@router.post("/adversarial-validate")
async def adversarial_validate_finding(finding: Dict[str, Any]):
    """Subject a candidate finding to 10-point Devil's Advocate adversarial evaluation."""
    report = AdversarialValidator.evaluate(finding)
    return report.model_dump()


# ─── 5. Cyber Risk Quantification ───────────────────────────────────────────────

@router.get("/risk/{scan_id}")
async def get_scan_cyber_risk(
    scan_id: str,
    asset_criticality: float = 1.2,
    exposure: float = 1.3,
    hourly_downtime_cost_usd: float = 5000.0,
    controls_discount: float = 0.0,
):
    """Calculate versioned, explainable Cyber Risk score (v2.0.0) with stored provenance."""
    db = get_db()
    cursor = db["findings"].find({"scan_id": scan_id}, {"_id": 0}).limit(100)
    findings = await cursor.to_list(length=100)

    risk_score = CyberRiskEngine.calculate_scan_risk(
        scan_id=scan_id,
        findings=findings,
        asset_criticality=asset_criticality,
        exposure_factor=exposure,
        existing_controls_discount=controls_discount,
        hourly_downtime_cost_usd=hourly_downtime_cost_usd,
    )
    return risk_score.model_dump()


# ─── 6. Investment Optimization (Remediation Prioritization) ───────────────────

@router.get("/investment/{scan_id}")
async def get_investment_plan(
    scan_id: str,
    user_hourly_rate: float = 120.0,
    hourly_downtime_cost_usd: float = 5000.0,
):
    """Generate Remediation Prioritization plan with user-supplied rates, uncertainty intervals, and zero savings claims."""
    db = get_db()
    cursor = db["findings"].find({"scan_id": scan_id}, {"_id": 0}).limit(100)
    findings = await cursor.to_list(length=100)

    risk = CyberRiskEngine.calculate_scan_risk(scan_id=scan_id, findings=findings)
    plan = InvestmentOptimizer.generate_plan(
        scan_id=scan_id,
        initial_risk_score=risk.score,
        findings=findings,
        user_hourly_rate=user_hourly_rate,
        hourly_downtime_cost_usd=hourly_downtime_cost_usd,
    )
    return plan.model_dump()


# ─── 7. Remediation Tasks & Retests ──────────────────────────────────────────────

@router.post("/remediation-tasks", response_model=RemediationTask)
async def create_remediation_task(req: CreateRemediationTaskRequest):
    """Create a tracked Remediation Task from an identified finding."""
    db = get_db()
    finding = await db["findings"].find_one({"id": req.finding_id}, {"_id": 0})
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{req.finding_id}' not found.")

    task = await remediation_retest_engine.create_remediation_task(
        finding=finding,
        scan_id=req.scan_id or finding.get("scan_id"),
        user_hourly_rate=req.user_hourly_rate,
        assignee=req.assignee,
        priority=req.priority,
        sla_days=req.sla_days,
    )
    return task


@router.get("/remediation-tasks")
async def list_remediation_tasks(
    scan_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
):
    """List all tracked remediation tasks."""
    tasks = await remediation_retest_engine.list_remediation_tasks(
        scan_id=scan_id,
        status=status,
        limit=limit,
    )
    return [t.model_dump() for t in tasks]


@router.get("/remediation-tasks/{task_id}")
async def get_remediation_task(task_id: str):
    """Get remediation task details."""
    task = await remediation_retest_engine.get_remediation_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found.")
    return task.model_dump()


@router.patch("/remediation-tasks/{task_id}")
async def update_remediation_task(task_id: str, req: UpdateRemediationTaskRequest):
    """Update status or assignee on a remediation task."""
    task = await remediation_retest_engine.get_remediation_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found.")

    updated = await remediation_retest_engine.update_task_status(
        task_id=task_id,
        new_status=req.status or task.status,
        assignee=req.assignee,
    )
    return updated.model_dump() if updated else None


@router.post("/remediation-tasks/{task_id}/retest")
async def retest_remediation_task(task_id: str, actor: str = "security_engineer"):
    """Trigger an automated retest for a task's finding using the original test method."""
    task = await remediation_retest_engine.get_remediation_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found.")

    retest_record = await remediation_retest_engine.execute_retest(
        finding_id=task.finding_id,
        actor=actor,
    )
    refreshed_task = await remediation_retest_engine.get_remediation_task(task_id)
    return {
        "retest": retest_record.model_dump(),
        "task": refreshed_task.model_dump() if refreshed_task else None,
    }


# ─── 8. Assessment Trends ────────────────────────────────────────────────────────

@router.get("/trends/{target}")
async def get_assessment_trends(target: str, limit: int = 10):
    """Return historical risk posture trend, MTTR, and verified risk reduction for a target."""
    view = await trend_service.get_target_trend_view(target=target, limit=limit)
    return view.model_dump()


# ─── 9. Executive Business Questions ────────────────────────────────────────────

@router.get("/business-questions/{scan_id}")
async def answer_all_business_questions(
    scan_id: str,
    target: Optional[str] = None,
    user_hourly_rate: float = 120.0,
    hourly_downtime_cost_usd: float = 5000.0,
):
    """Answer all four master doc executive business questions from stored telemetry."""
    q1 = await business_questions_service.answer_question_1_current_risk(
        scan_id=scan_id,
        hourly_downtime_cost_usd=hourly_downtime_cost_usd,
    )
    q2 = await business_questions_service.answer_question_2_critical_attack_paths(
        scan_id=scan_id,
        target=target,
    )
    q3 = await business_questions_service.answer_question_3_prioritized_investments(
        scan_id=scan_id,
        user_hourly_rate=user_hourly_rate,
        hourly_downtime_cost_usd=hourly_downtime_cost_usd,
    )
    q4 = await business_questions_service.answer_question_4_posture_trends(
        target=target or "*",
    )
    return {
        "scan_id": scan_id,
        "executive_summary": "ARGOLOCK V1.7 Core Business Decisions Telemetry",
        "questions": {
            "Q1_cyber_risk_and_financial_loss": q1,
            "Q2_critical_findings_and_attack_paths": q2,
            "Q3_remediation_investments_and_effort": q3,
            "Q4_posture_trends_and_mttr": q4,
        },
    }


@router.get("/business-questions/{scan_id}/q1")
async def answer_q1(scan_id: str, hourly_downtime_cost_usd: float = 5000.0):
    """Q1: What is our current cyber risk exposure and financial loss range?"""
    return await business_questions_service.answer_question_1_current_risk(
        scan_id=scan_id,
        hourly_downtime_cost_usd=hourly_downtime_cost_usd,
    )


@router.get("/business-questions/{scan_id}/q2")
async def answer_q2(scan_id: str, target: Optional[str] = None):
    """Q2: What are our most critical verified vulnerabilities and attack paths to crown jewels?"""
    return await business_questions_service.answer_question_2_critical_attack_paths(
        scan_id=scan_id,
        target=target,
    )


@router.get("/business-questions/{scan_id}/q3")
async def answer_q3(
    scan_id: str,
    user_hourly_rate: float = 120.0,
    hourly_downtime_cost_usd: float = 5000.0,
):
    """Q3: What is our prioritized remediation investment plan with user costs, uncertainty ranges, and no savings claims?"""
    return await business_questions_service.answer_question_3_prioritized_investments(
        scan_id=scan_id,
        user_hourly_rate=user_hourly_rate,
        hourly_downtime_cost_usd=hourly_downtime_cost_usd,
    )


@router.get("/business-questions/{scan_id}/q4")
async def answer_q4(scan_id: str, target: str = "*"):
    """Q4: What is our historical risk posture trend, MTTR, and verified risk reduction over time?"""
    return await business_questions_service.answer_question_4_posture_trends(target=target)


# ─── 10. Security Control Plane ──────────────────────────────────────────────────

@router.post("/security-control-plane/kill-switch")
async def toggle_kill_switch(req: KillSwitchRequest):
    """Activate or deactivate emergency kill switch."""
    if req.activate:
        res = SecurityControlPlane.activate_emergency_kill_switch(req.mission_id)
    else:
        SecurityControlPlane.reset_kill_switch(req.mission_id)
        res = {"status": "kill_switch_deactivated", "mission_id": req.mission_id, "active": False}
    return res


@router.get("/security-control-plane/status")
async def get_control_plane_status():
    """Get live security gate policies and kill switch status."""
    return {
        "global_kill_switch_active": SecurityControlPlane._kill_switch_active,
        "terminated_mission_count": len(SecurityControlPlane._terminated_missions),
        "enforced_gates": ["ScopeGate", "ActionClassificationGate", "ExploitationSafetyGate"],
        "destructive_pattern_count": len(SecurityControlPlane.DESTRUCTIVE_PATTERNS),
        "status": "active_enforcing",
    }

"""
ARGOLOCK V1.7 Core Data Models & Schemas
Enforces strict No-Fake-Data typing, 9-stage Finding Lifecycle,
Capability Graphs, Attack Paths, Cyber Risk Quantification, and Investment Optimization.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ─── 1. No-Fake-Data Source Classification & Figure Provenance ────────────────────

class SourceType(str, Enum):
    REAL = "REAL"                     # Verified physical target / infrastructure
    OBSERVED = "OBSERVED"             # Direct raw tool execution output (HTTP response, port probe)
    INFERRED = "INFERRED"             # Deterministic derivation from observed data
    HYPOTHESIS = "HYPOTHESIS"         # AI or heuristic generated proposition awaiting testing
    EXTERNAL_INTEL = "EXTERNAL_INTEL" # CVE, NVD, KEV, MITRE ATT&CK reference data


class FigureOrigin(str, Enum):
    OBSERVED = "OBSERVED"   # Directly measured from scan telemetry or tool output
    ASSUMED = "ASSUMED"     # User-supplied or standard industry baseline parameter
    MODELED = "MODELED"     # Mathematically calculated by statistical or risk algorithm


class ProvenanceFigure(BaseModel):
    value: Any
    origin: FigureOrigin
    source: str
    unit: Optional[str] = None
    notes: Optional[str] = None


# ─── 2. Finding Lifecycle State Machine ──────────────────────────────────────────

class FindingLifecycleState(str, Enum):
    DISCOVERED = "DISCOVERED"         # Initial raw observation logged
    CANDIDATE = "CANDIDATE"           # Normalized finding proposal
    REPRODUCING = "REPRODUCING"       # Automated replay/retest underway
    VALIDATING = "VALIDATING"         # Devil's Advocate / adversarial evaluation
    KILLED = "KILLED"                 # Disproven as false positive or non-vulnerability
    BLOCKED = "BLOCKED"               # Insufficient evidence or out-of-scope
    VERIFIED = "VERIFIED"             # Re-tested and confirmed reproducible
    IMPACT_TEST = "IMPACT_TEST"       # Non-destructive impact boundary test
    DOWNGRADED = "DOWNGRADED"         # Confirmed but lower practical severity
    CONFIRMED = "CONFIRMED"           # Fully verified with demonstrated impact
    REPORTED = "REPORTED"             # Integrated into capability graph and report


class MappedLifecycleStatus(str, Enum):
    DETECTED = "Detected"
    PENDING_VALIDATION = "Pending Validation"
    VALIDATED = "Validated"
    FALSE_POSITIVE = "False Positive"
    INCONCLUSIVE = "Inconclusive"


LIFECYCLE_MAPPING: Dict[FindingLifecycleState, MappedLifecycleStatus] = {
    FindingLifecycleState.DISCOVERED: MappedLifecycleStatus.DETECTED,
    FindingLifecycleState.CANDIDATE: MappedLifecycleStatus.DETECTED,
    FindingLifecycleState.REPRODUCING: MappedLifecycleStatus.PENDING_VALIDATION,
    FindingLifecycleState.VALIDATING: MappedLifecycleStatus.PENDING_VALIDATION,
    FindingLifecycleState.VERIFIED: MappedLifecycleStatus.VALIDATED,
    FindingLifecycleState.CONFIRMED: MappedLifecycleStatus.VALIDATED,
    FindingLifecycleState.DOWNGRADED: MappedLifecycleStatus.VALIDATED,
    FindingLifecycleState.REPORTED: MappedLifecycleStatus.VALIDATED,
    FindingLifecycleState.KILLED: MappedLifecycleStatus.FALSE_POSITIVE,
    FindingLifecycleState.BLOCKED: MappedLifecycleStatus.INCONCLUSIVE,
    FindingLifecycleState.IMPACT_TEST: MappedLifecycleStatus.PENDING_VALIDATION,
}


def map_finding_lifecycle_status(state: FindingLifecycleState | str) -> str:
    """
    Map internal 9-stage FindingLifecycleState to canonical operational lifecycle status:
    - DISCOVERED / CANDIDATE -> Detected
    - REPRODUCING / VALIDATING -> Pending Validation
    - VERIFIED / CONFIRMED / DOWNGRADED / REPORTED -> Validated
    - KILLED -> False Positive
    - BLOCKED -> Inconclusive
    """
    if isinstance(state, FindingLifecycleState):
        return LIFECYCLE_MAPPING.get(state, MappedLifecycleStatus.DETECTED).value
    try:
        parsed = FindingLifecycleState(str(state).upper())
        return LIFECYCLE_MAPPING.get(parsed, MappedLifecycleStatus.DETECTED).value
    except Exception:
        str_val = str(state).strip()
        for mapped in MappedLifecycleStatus:
            if str_val.lower() == mapped.value.lower():
                return mapped.value
        return MappedLifecycleStatus.DETECTED.value


# ─── 3. Action Classification (Execution Gates) ─────────────────────────────────

class ActionClassification(str, Enum):
    PASSIVE = "PASSIVE"                                 # DNS lookup, CT log, OSINT, static parsing
    LOW_RISK_ACTIVE = "LOW_RISK_ACTIVE"                 # Port scan, standard GET request, header check
    VALIDATION = "VALIDATION"                           # Non-destructive single-probe test
    CONTROLLED_EXPLOITATION = "CONTROLLED_EXPLOITATION" # Minimal proof-of-concept execution
    HIGH_IMPACT = "HIGH_IMPACT"                         # Resource-intensive or state-altering test
    DESTRUCTIVE = "DESTRUCTIVE"                         # Drop table, fuzzing crash, delete operations (BLOCKED)


class GateEvaluationResult(BaseModel):
    allowed: bool
    gate_name: str
    action_class: ActionClassification
    reason: str
    target: str
    timestamp: str = Field(default_factory=utc_now_iso)


# ─── 4. Capability Graph & Attack Chains ────────────────────────────────────────

class CapabilityNode(BaseModel):
    id: str = Field(default_factory=lambda: f"cap-{uuid.uuid4().hex[:8]}")
    name: str                           # e.g., "Read Other User Records (IDOR)"
    description: str
    target_asset: str                   # e.g., "api.example.com/v1/users/{id}"
    finding_id: Optional[str] = None
    prerequisite_node_ids: List[str] = Field(default_factory=list)
    confidence: float = 1.0             # 0.0 to 1.0
    terminal_impact: bool = False       # True if it achieves high-level business impact (e.g. Account Takeover)
    evidence_hash: Optional[str] = None # SHA-256 hash of proof artifact
    discovered_at: str = Field(default_factory=utc_now_iso)


class CapabilityEdge(BaseModel):
    source_id: str
    target_id: str
    transition_vulnerability: str
    transition_confidence: float = 1.0
    evidence_hash: str = ""


class AttackChain(BaseModel):
    id: str = Field(default_factory=lambda: f"chain-{uuid.uuid4().hex[:8]}")
    scan_id: str
    title: str
    entry_point: str
    terminal_impact: str
    path_nodes: List[CapabilityNode] = Field(default_factory=list)
    overall_confidence: float = 0.95
    severity: str = "critical"
    created_at: str = Field(default_factory=utc_now_iso)


# ─── 5. Cyber Risk Quantification ───────────────────────────────────────────────

class CyberRiskScore(BaseModel):
    scan_id: str
    risk_model_version: str = "2.0.0"   # Versioned explainable risk model
    score: float = Field(0.0, description="Calibrated score 0-100")
    rating: str = "Low"                 # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    severity_factor: float = 0.0        # 0.0 - 10.0
    exploitability_factor: float = 0.0  # 0.0 - 1.0
    asset_criticality_factor: float = 1.0 # 0.5 - 2.0
    exposure_factor: float = 1.0        # 0.5 - 1.5
    business_impact_factor: float = 1.0 # 0.5 - 2.0
    threat_relevance_factor: float = 1.0# 0.5 - 1.5
    confidence_factor: float = 1.0      # 0.0 - 1.0
    controls_discount: float = 0.0      # 0.0 - 0.4 discount for validated compensating controls
    inputs: Dict[str, ProvenanceFigure] = Field(default_factory=dict) # Stored explicit inputs with provenance
    uncertainty_range: Dict[str, Any] = Field(default_factory=dict) # min_score, expected_score, max_score, confidence_interval
    loss_exposure: Dict[str, Any] = Field(default_factory=dict) # min_usd, expected_usd, max_usd, hourly_downtime_cost_usd, assumptions
    calculation_breakdown: Dict[str, Any] = Field(default_factory=dict)
    calculated_at: str = Field(default_factory=utc_now_iso)


# ─── 6. Investment Optimization (Remediation ROI) ───────────────────────────────

class RemediationPriority(str, Enum):
    P1 = "P1" # Critical Immediate ROI Fix
    P2 = "P2" # High Impact Reduction
    P3 = "P3" # Medium Priority Fix
    P4 = "P4" # Low ROI / Hygiene Fix


class RemediationActionItem(BaseModel):
    id: str = Field(default_factory=lambda: f"rem-{uuid.uuid4().hex[:8]}")
    finding_id: Optional[str] = None
    title: str
    recommended_control: str
    estimated_cost: str = "Medium"      # Low, Medium, High
    cost_index: float = 2.0             # Numeric index for calculation (1.0=Low, 2.0=Med, 3.5=High)
    user_hourly_rate: float = 120.0     # User-supplied engineer hourly rate (USD)
    effort_hours: int = 8               # Expected effort hours
    effort_range: Dict[str, int] = Field(default_factory=dict) # min_hours, expected_hours, max_hours
    cost_range: Dict[str, float] = Field(default_factory=dict) # min_cost_usd, expected_cost_usd, max_cost_usd
    risk_reduction_points: float = 15.0 # Expected risk points removed
    risk_reduction_range: Dict[str, float] = Field(default_factory=dict) # min_points, expected_points, max_points
    residual_risk_points: float = 5.0
    roi_score: float = 7.5              # risk_reduction_points / cost_index
    priority: RemediationPriority = RemediationPriority.P2
    compliance_mappings: List[str] = Field(default_factory=list) # OWASP, ISO27001, SOC2
    figure_provenance: Dict[str, FigureOrigin] = Field(default_factory=dict)


class InvestmentOptimizationPlan(BaseModel):
    scan_id: str
    initial_risk_score: float
    projected_residual_risk: float
    total_risk_reduction: float
    user_hourly_rate: float = 120.0
    total_effort_range: Dict[str, int] = Field(default_factory=dict) # min_hours, expected_hours, max_hours
    total_cost_range: Dict[str, float] = Field(default_factory=dict) # min_usd, expected_usd, max_usd
    modeled_loss_reduction_range: Dict[str, float] = Field(default_factory=dict) # min_usd, expected_usd, max_usd
    assumptions: List[str] = Field(default_factory=list)
    savings_claim_notice: str = "No direct financial savings claimed. Figures represent modeled reduction in technical risk points and potential loss exposure."
    actions: List[RemediationActionItem] = Field(default_factory=list)
    generated_at: str = Field(default_factory=utc_now_iso)


# ─── 7. Remediation Tasks & Retests ──────────────────────────────────────────────

class RemediationTaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    READY_FOR_RETEST = "ready_for_retest"
    RESOLVED = "resolved"
    REOPENED = "reopened"


class RemediationTask(BaseModel):
    id: str = Field(default_factory=lambda: f"task-{uuid.uuid4().hex[:8]}")
    tenant_id: str = Field(default="tenant_default", description="Tenant isolation identifier")
    finding_id: str
    scan_id: str
    title: str
    description: str
    status: RemediationTaskStatus = RemediationTaskStatus.PENDING
    assignee: Optional[str] = None
    priority: RemediationPriority = RemediationPriority.P2
    sla_deadline: Optional[str] = None
    user_hourly_rate: float = 120.0
    estimated_hours_range: Dict[str, int] = Field(default_factory=dict) # min, expected, max
    estimated_cost_range: Dict[str, float] = Field(default_factory=dict) # min, expected, max
    original_test_method: str = "validation_engine"
    retest_ids: List[str] = Field(default_factory=list)
    verified_risk_reduction: float = 0.0 # Only updated from verified retest with RetestStatus.RESOLVED
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)


# ─── 8. Assessment Trends & Historical Posture ──────────────────────────────────

class AssessmentTrendPoint(BaseModel):
    scan_id: str
    timestamp: str
    risk_score: float
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    verified_remediations_count: int = 0
    new_findings_count: int = 0
    total_findings_count: int = 0


class AssessmentTrendView(BaseModel):
    target: str
    history_points: List[AssessmentTrendPoint] = Field(default_factory=list)
    mttr_hours_average: Optional[float] = None # Mean Time to Remediate in hours
    total_verified_risk_reduction: float = 0.0
    posture_trend_direction: str = "stable" # "improving", "deteriorating", "stable"
    data_provenance: Dict[str, Any] = Field(default_factory=dict)


# ─── 9. Mission Modes & Mission Controller ──────────────────────────────────────

class MissionMode(str, Enum):
    DISCOVERY = "DISCOVERY"             # Asset discovery, service mapping
    ASSESSMENT = "ASSESSMENT"           # Full vulnerability assessment with specialist agents
    VALIDATION = "VALIDATION"           # Re-test and reproduce candidate findings
    CONTINUOUS = "CONTINUOUS"           # Scheduled delta scanning & regression testing


class Mission(BaseModel):
    id: str = Field(default_factory=lambda: f"msn-{uuid.uuid4().hex[:8]}")
    tenant_id: str = Field(default="tenant_default", description="Tenant isolation identifier")
    name: str
    target: str
    mode: MissionMode = MissionMode.ASSESSMENT
    status: str = "running"             # pending, running, completed, cancelled, failed
    current_phase: str = "Reconnaissance"
    progress_percent: int = 0
    budget_seconds: int = 600
    scope_whitelist: List[str] = Field(default_factory=list)
    scope_blacklist: List[str] = Field(default_factory=list)
    active_agent_count: int = 4
    findings_count: int = 0
    verified_count: int = 0
    capabilities_count: int = 0
    risk_score: float = 0.0
    created_at: str = Field(default_factory=utc_now_iso)
    completed_at: Optional[str] = None

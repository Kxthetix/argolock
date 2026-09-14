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


# ─── 1. No-Fake-Data Source Classification ───────────────────────────────────────

class SourceType(str, Enum):
    REAL = "REAL"                     # Verified physical target / infrastructure
    OBSERVED = "OBSERVED"             # Direct raw tool execution output (HTTP response, port probe)
    INFERRED = "INFERRED"             # Deterministic derivation from observed data
    HYPOTHESIS = "HYPOTHESIS"         # AI or heuristic generated proposition awaiting testing
    EXTERNAL_INTEL = "EXTERNAL_INTEL" # CVE, NVD, KEV, MITRE ATT&CK reference data


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
    score: float = Field(0.0, description="Calibrated score 0-100")
    rating: str = "Low"                 # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    severity_factor: float = 0.0        # 0.0 - 10.0
    exploitability_factor: float = 0.0  # 0.0 - 1.0
    asset_criticality_factor: float = 1.0 # 0.5 - 2.0
    exposure_factor: float = 1.0        # 0.5 - 1.5
    business_impact_factor: float = 1.0 # 0.5 - 2.0
    threat_relevance_factor: float = 1.0# 0.5 - 1.5
    confidence_factor: float = 1.0      # 0.0 - 1.0
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
    risk_reduction_points: float = 15.0 # How many risk points removed
    residual_risk_points: float = 5.0
    roi_score: float = 7.5              # risk_reduction_points / cost_index
    priority: RemediationPriority = RemediationPriority.P2
    effort_hours: int = 8
    compliance_mappings: List[str] = Field(default_factory=list) # OWASP, ISO27001, SOC2


class InvestmentOptimizationPlan(BaseModel):
    scan_id: str
    initial_risk_score: float
    projected_residual_risk: float
    total_risk_reduction: float
    actions: List[RemediationActionItem] = Field(default_factory=list)
    generated_at: str = Field(default_factory=utc_now_iso)


# ─── 7. Mission Modes & Mission Controller ──────────────────────────────────────

class MissionMode(str, Enum):
    DISCOVERY = "DISCOVERY"             # Asset discovery, service mapping
    ASSESSMENT = "ASSESSMENT"           # Full vulnerability assessment with specialist agents
    VALIDATION = "VALIDATION"           # Re-test and reproduce candidate findings
    CONTINUOUS = "CONTINUOUS"           # Scheduled delta scanning & regression testing


class Mission(BaseModel):
    id: str = Field(default_factory=lambda: f"msn-{uuid.uuid4().hex[:8]}")
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

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field, ConfigDict, field_serializer


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuthorizationStatus(str, Enum):
    AUTHORIZED = "authorized"
    PENDING = "pending"
    REVOKED = "revoked"
    EXPIRED = "expired"


class TestingMode(str, Enum):
    __test__ = False
    PASSIVE = "passive"
    NON_INVASIVE = "non_invasive"
    CONTROLLED_PROOF = "controlled_proof"
    OPERATOR_APPROVED = "operator_approved"


class TestingLevel(str, Enum):
    __test__ = False
    LEVEL_0_PASSIVE = "level_0"                # Passive discovery / banner checks
    LEVEL_1_NON_INVASIVE = "level_1"           # Non-invasive validation (no changes)
    LEVEL_2_CONTROLLED_PROOF = "level_2"       # Controlled proof of condition
    LEVEL_3_OPERATOR_APPROVED = "level_3"      # Operator-approved advanced testing
    LEVEL_4_DESTRUCTIVE = "level_4"            # Destructive testing (disabled by default)


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ValidationStatus(str, Enum):
    DETECTED = "detected"
    UNDER_VALIDATION = "under_validation"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    NOT_EXPLOITABLE = "not_exploitable"
    UNABLE_TO_VALIDATE = "unable_to_validate"
    REQUIRES_MANUAL_REVIEW = "requires_manual_review"


class RetestStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    RESOLVED = "resolved"
    STILL_VULNERABLE = "still_vulnerable"
    INCONCLUSIVE = "inconclusive"


class ExploitabilityLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Target Authorization Model ───────────────────────────────────────────────

class TargetAuthorization(BaseModel):
    """Explicit asset scope and authorization record."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str
    hostname_or_ip: str
    owner: str
    authorization_status: AuthorizationStatus = AuthorizationStatus.AUTHORIZED
    scope: List[str] = Field(default_factory=list, description="Allowed CIDRs, subdomains, or hosts")
    permitted_ports: List[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])
    permitted_services: List[str] = Field(default_factory=lambda: ["http", "https"])
    testing_window_start: datetime = Field(default_factory=utc_now)
    testing_window_end: Optional[datetime] = None
    testing_mode: TestingMode = TestingMode.NON_INVASIVE
    assessment_id: str
    approval_reference: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("testing_window_start", "testing_window_end", "created_at", "updated_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


# ── Operator Testing Approval ────────────────────────────────────────────────

class TestingApproval(BaseModel):
    """Operator approval record required for Level 2 & 3 validation."""
    __test__ = False
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    assessment_id: str
    finding_id: str
    asset_id: str
    requested_by: str
    approved_by: Optional[str] = None
    testing_level: TestingLevel = TestingLevel.LEVEL_1_NON_INVASIVE
    scope_justification: str = ""
    expiration: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decision_notes: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    decided_at: Optional[datetime] = None

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("expiration", "created_at", "decided_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


# ── Tamper-Evident Evidence Record ───────────────────────────────────────────

class EvidenceRecord(BaseModel):
    """Technical proof record with SHA-256 cryptographic verification."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    asset_id: str
    tool_source: str
    technique: str
    request_sample: Optional[str] = None
    response_sample: Optional[str] = None
    banner_output: Optional[str] = None
    config_snippet: Optional[str] = None
    stdout_summary: Optional[str] = None
    sha256_hash: str = ""
    redacted_fields: List[str] = Field(default_factory=list)
    collected_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("collected_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


# ── Exploitability Assessment ────────────────────────────────────────────────

class ExploitabilityAssessment(BaseModel):
    """Multi-signal exploitability evaluation without autonomous exploit launching."""
    finding_id: str
    exploitability_level: ExploitabilityLevel = ExploitabilityLevel.MEDIUM
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    public_exploit_available: bool = False
    cisa_kev_listed: bool = False
    epss_score: float = Field(0.0, ge=0.0, le=1.0)
    cvss_base_score: float = Field(0.0, ge=0.0, le=10.0)
    version_match: bool = False
    service_match: bool = False
    network_exposure: str = "external"  # external, internal, adjacent
    requires_manual_testing: bool = False
    rationale: str = ""
    assessed_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("assessed_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


# ── Contextual Risk Model ────────────────────────────────────────────────────

class ContextualRiskScore(BaseModel):
    """Explainable cyber risk calculation."""
    finding_id: str
    technical_severity: float = Field(0.0, ge=0.0, le=10.0)
    exploitability_factor: float = Field(0.0, ge=0.0, le=10.0)
    exposure_factor: float = Field(0.0, ge=0.0, le=10.0)
    business_impact_factor: float = Field(0.0, ge=0.0, le=10.0)
    attack_path_multiplier: float = Field(1.0, ge=1.0, le=2.0)
    final_risk_score: float = Field(0.0, ge=0.0, le=100.0)
    risk_tier: str = "medium"  # critical, high, medium, low, info
    explanation: Dict[str, Any] = Field(default_factory=dict)
    calculated_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("calculated_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


# ── MITRE ATT&CK & Attack Path Models ────────────────────────────────────────

class MITREMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    finding_id: str
    asset_id: str
    evidence_reference: Optional[str] = None
    confidence: float = Field(0.9, ge=0.0, le=1.0)


class AttackPathNode(BaseModel):
    node_id: str
    name: str
    node_type: str   # internet, asset, service, vulnerability, credential, domain_controller, critical_data
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackPathEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str  # exposes, permits_access_to, escalates_to, pivots_to
    risk_weight: float = 1.0


class AttackPathGraph(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    assessment_id: str
    nodes: List[AttackPathNode] = Field(default_factory=list)
    edges: List[AttackPathEdge] = Field(default_factory=list)
    critical_path_identified: bool = False
    highest_risk_asset: Optional[str] = None
    generated_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)


# ── Remediation & Retest Models ──────────────────────────────────────────────

class RemediationPlan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    affected_asset: str
    root_cause: str
    patch_recommendation: str
    config_recommendation: str
    mitigation_steps: List[str] = Field(default_factory=list)
    priority: str = "high"  # immediate, high, medium, low
    retest_requirement: str = ""
    created_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)


class RetestRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    retest_status: RetestStatus = RetestStatus.PENDING
    original_evidence_hash: str
    new_evidence_hash: Optional[str] = None
    comparison_summary: str = ""
    executed_by: str
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("started_at", "completed_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


# ── Immutable VAPT Audit Record ──────────────────────────────────────────────

class VAPTAuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    actor: str
    action: str
    assessment_id: Optional[str] = None
    asset_id: Optional[str] = None
    finding_id: Optional[str] = None
    tool: Optional[str] = None
    tool_version: Optional[str] = None
    test_level: Optional[str] = None
    approval_id: Optional[str] = None
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: Optional[datetime] = None
    result_summary: str = ""
    evidence_hash: Optional[str] = None
    cleanup_verified: bool = True
    previous_record_hash: Optional[str] = None
    record_hash: str = ""

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("started_at", "completed_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")

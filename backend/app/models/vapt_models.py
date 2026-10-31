from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field, ConfigDict, field_serializer, model_validator


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
    tenant_id: str = Field(default="tenant_default", description="Tenant isolation identifier")
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
    ownership_proof_type: str = Field(default="dns_txt", description="dns_txt | well_known_file | benchmark_preauthorized")
    ownership_proof_token: Optional[str] = Field(None, description="DNS TXT or file challenge token")
    ownership_verified: bool = Field(default=True, description="Whether target ownership has been proven")
    excluded_paths: List[str] = Field(default_factory=list, description="Explicitly excluded endpoints/paths")
    intensity: str = Field(default="safe", description="Testing intensity: safe | standard | aggressive")
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
    tenant_id: str = Field(default="tenant_default", description="Tenant isolation identifier")
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
    """Immutable technical proof record with SHA-256 cryptographic verification."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    assessment_id: str = ""
    asset: str = ""
    tool: str = ""
    tool_version: Optional[str] = None
    request_excerpt: Optional[str] = None
    response_excerpt: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)
    method: Optional[str] = None
    hash: str = ""
    redaction_flag: bool = False

    # Backward-compatible fields
    finding_id: Optional[str] = None
    asset_id: Optional[str] = None
    tool_source: Optional[str] = None
    technique: Optional[str] = None
    request_sample: Optional[str] = None
    response_sample: Optional[str] = None
    banner_output: Optional[str] = None
    config_snippet: Optional[str] = None
    stdout_summary: Optional[str] = None
    sha256_hash: str = ""
    redacted_fields: List[str] = Field(default_factory=list)
    collected_at: Optional[datetime] = None

    model_config = ConfigDict(use_enum_values=True)

    @model_validator(mode="before")
    @classmethod
    def sync_compat_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # assessment_id <-> finding_id
            if not data.get("assessment_id") and data.get("finding_id"):
                data["assessment_id"] = str(data["finding_id"])
            elif not data.get("finding_id") and data.get("assessment_id"):
                data["finding_id"] = str(data["assessment_id"])

            # asset <-> asset_id
            if not data.get("asset") and data.get("asset_id"):
                data["asset"] = str(data["asset_id"])
            elif not data.get("asset_id") and data.get("asset"):
                data["asset_id"] = str(data["asset"])

            # tool <-> tool_source
            if not data.get("tool") and data.get("tool_source"):
                data["tool"] = str(data["tool_source"])
            elif not data.get("tool_source") and data.get("tool"):
                data["tool_source"] = str(data["tool"])

            # method <-> technique
            if not data.get("method") and data.get("technique"):
                data["method"] = str(data["technique"])
            elif not data.get("technique") and data.get("method"):
                data["technique"] = str(data["method"])

            # request_excerpt <-> request_sample
            if not data.get("request_excerpt") and data.get("request_sample"):
                data["request_excerpt"] = data["request_sample"]
            elif not data.get("request_sample") and data.get("request_excerpt"):
                data["request_sample"] = data["request_excerpt"]

            # response_excerpt <-> response_sample
            if not data.get("response_excerpt") and data.get("response_sample"):
                data["response_excerpt"] = data["response_sample"]
            elif not data.get("response_sample") and data.get("response_excerpt"):
                data["response_sample"] = data["response_excerpt"]

            # hash <-> sha256_hash
            if not data.get("hash") and data.get("sha256_hash"):
                data["hash"] = data["sha256_hash"]
            elif not data.get("sha256_hash") and data.get("hash"):
                data["sha256_hash"] = data["hash"]

            # timestamp <-> collected_at
            if not data.get("timestamp") and data.get("collected_at"):
                data["timestamp"] = data["collected_at"]
            elif not data.get("collected_at") and data.get("timestamp"):
                data["collected_at"] = data["timestamp"]

            # redaction_flag <-> redacted_fields
            if data.get("redacted_fields") and not data.get("redaction_flag"):
                data["redaction_flag"] = bool(data["redacted_fields"])
            elif data.get("redaction_flag") and not data.get("redacted_fields"):
                data["redacted_fields"] = ["[REDACTED]"]
        return data

    @field_serializer("timestamp", "collected_at")
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
    original_test_method: str = "validation_engine"
    verified_risk_reduction: float = 0.0 # Only updated from verified retest with RetestStatus.RESOLVED
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

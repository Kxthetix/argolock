"""
ARGOLOCK NET Tool Cell Models, Schemas, Manifests, and Sequential Workflow States.
Complies with ARGOLOCK_NET_Phase1_Existing_Tool_Cells_and_Sequential_Pipeline_v1.0.md
and ARGOLOCK_NET_Isolated_Tool_Pipeline_Design_v1.0.md.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict, field_serializer


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ─── 1. Sequential Stage Identifiers ──────────────────────────────────────────

class SequentialStageKey(str, Enum):
    """The 14 explicit sequential workflow stages."""
    PREFLIGHT = "01_preflight"
    SUBFINDER = "02_subfinder_discovery"
    AMASS = "03_amass_enrichment"
    SCOPE_GATE = "04_scope_resolution_gate"
    NAABU = "05_naabu_port_discovery"
    NMAP = "06_nmap_service_probes"
    HTTPX_PROBE = "07_httpx_probing"
    WHATWEB = "08_whatweb_fingerprinting"
    NUCLEI = "09_nuclei_network_web"
    ZAP_PASSIVE = "10_zap_crawl_passive"
    NIKTO = "11_nikto_server_checks"
    DALFOX = "12_dalfox_xss_checks"
    ZAP_ACTIVE = "13_zap_active_scan"
    EVIDENCE_CORRELATION = "14_evidence_correlation_reporting"


class CellWorkflowState(str, Enum):
    """Execution lifecycle state for a Tool Cell stage."""
    PLANNED = "PLANNED"
    PREFLIGHTED = "PREFLIGHTED"
    RUNNING = "RUNNING"
    RAW_CAPTURED = "RAW_CAPTURED"
    PARSED = "PARSED"
    NORMALIZED = "NORMALIZED"
    REVIEWED = "REVIEWED"
    HANDOFF_ALLOWED = "HANDOFF_ALLOWED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SKIPPED = "SKIPPED"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIAL = "PARTIAL"
    COMPLETED = "COMPLETED"


class RiskApprovalClass(str, Enum):
    """Risk tier dictating approval requirement."""
    PASSIVE = "PASSIVE"
    LOW_IMPACT_ACTIVE = "LOW_IMPACT_ACTIVE"
    VALIDATION = "VALIDATION"
    HIGH_IMPACT = "HIGH_IMPACT"
    OPERATOR_APPROVED = "OPERATOR_APPROVED"


# ─── 2. Typed Handoff Schemas ────────────────────────────────────────────────

class DomainCandidate(BaseModel):
    """Discovered candidate domain/subdomain from passive discovery."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    fqdn: str
    source_tool: str
    source_ref: str
    observed_at: datetime = Field(default_factory=utc_now)
    scope_version: str = "v1"
    confidence_hint: float = Field(default=0.8, ge=0.0, le=1.0)
    raw_ref: str
    cname_target: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("observed_at")
    def serialize_dt(self, v: datetime) -> str:
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class TargetKind(str, Enum):
    DOMAIN = "domain"
    FQDN = "fqdn"
    IP = "ip"
    CIDR = "cidr"
    HOST_PORT = "host_port"
    WEB_ORIGIN = "web_origin"
    URL = "url"


class ScopeAllowDecision(str, Enum):
    ALLOWED = "ALLOWED"
    EXCLUDED = "EXCLUDED"
    AMBIGUOUS_HELD = "AMBIGUOUS_HELD"


class ApprovedTargetSet(BaseModel):
    """Immutable, pinned target set after scope resolution and boundary enforcement."""
    set_id: str = Field(default_factory=lambda: f"tgt-{uuid.uuid4().hex[:8]}")
    asset_id: str
    scope_version: str = "v1"
    targets: List[str] = Field(default_factory=list)
    target_kind: TargetKind = TargetKind.FQDN
    allow_decision: ScopeAllowDecision = ScopeAllowDecision.ALLOWED
    resolution_evidence: Dict[str, Any] = Field(default_factory=dict)
    resolved_ips: List[str] = Field(default_factory=list)
    exclusions_applied: List[str] = Field(default_factory=list)
    is_cdn_or_shared: bool = False
    shared_provider: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: Optional[datetime] = None

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("created_at", "expires_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class ServiceEndpointCandidate(BaseModel):
    """Discovered open service endpoint from bounded port discovery."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str
    ip_or_host: str
    protocol: str = "tcp"
    port: int
    state: str = "open"  # open | filtered | closed
    source_ref: str
    scope_version: str = "v1"
    observed_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("observed_at")
    def serialize_dt(self, v: datetime) -> str:
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class ServiceFingerprint(BaseModel):
    """Identified service protocol and version metadata."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    provenance: str = "nmap_service_probe"
    raw_ref: str
    observed_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("observed_at")
    def serialize_dt(self, v: datetime) -> str:
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class WebOrigin(BaseModel):
    """Validated HTTP(S) web origin with probe response metadata."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scheme: str  # http | https
    host: str
    port: int
    redirect_chain: List[str] = Field(default_factory=list)
    scope_decision: str = "ALLOWED"
    status_code: Optional[int] = None
    title: Optional[str] = None
    server_hint: Optional[str] = None
    tls_metadata: Optional[Dict[str, Any]] = None
    source_ref: str
    observed_at: datetime = Field(default_factory=utc_now)
    raw_ref: str

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("observed_at")
    def serialize_dt(self, v: datetime) -> str:
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class RouteObservation(BaseModel):
    """Application route, form, or parameter discovered during crawl."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    origin: str
    path: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list)
    is_state_changing: bool = False
    auth_context_id: Optional[str] = None
    source_ref: str
    observed_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("observed_at")
    def serialize_dt(self, v: datetime) -> str:
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class FindingReviewState(str, Enum):
    """Strict lifecycle states for findings ensuring unconfirmed results do not inflate confirmed counts."""
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    DUPLICATE = "duplicate"
    INCONCLUSIVE = "inconclusive"
    NON_APPLICABLE = "non_applicable"
    REMEDIATED = "remediated"
    RETEST_PASSED = "retest_passed"
    ACCEPTED_RISK = "accepted_risk"


class FindingCandidate(BaseModel):
    """Candidate security finding emitted by a Tool Cell awaiting evidence verification."""
    id: str = Field(default_factory=lambda: f"fnd-{uuid.uuid4().hex[:8]}")
    candidate_type: str
    asset: str
    endpoint: str
    rule_or_template_id: str
    evidence_summary: str
    severity_hint: str = "medium"  # critical | high | medium | low | info
    confidence_hint: float = Field(default=0.7, ge=0.0, le=1.0)
    source_refs: List[str] = Field(default_factory=list)
    raw_ref: str
    reproduction_class: str = "automated_matcher"
    review_state: FindingReviewState = FindingReviewState.CANDIDATE
    duplicate_of_id: Optional[str] = None
    reviewer_rationale: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    observed_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("observed_at", "reviewed_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


# ─── 3. Tool Cell Manifest Specification ─────────────────────────────────────

class ToolCellManifest(BaseModel):
    """
    Versioned manifest declaring tool identity, boundary policies,
    typed contracts, risk class, and paired AI role.
    """
    tool_id: str
    tool_name: str
    tool_version: str
    adapter_version: str
    image_digest: str
    risk_class: RiskApprovalClass
    allowed_profiles: List[str] = Field(default_factory=list)
    target_types: List[TargetKind] = Field(default_factory=list)
    network_egress_policy: Dict[str, Any] = Field(
        default_factory=lambda: {"default_deny": True, "restrict_to_targets": True}
    )
    resource_limits: Dict[str, Any] = Field(
        default_factory=lambda: {"memory_mb": 512, "cpus": 1.0, "timeout_seconds": 60}
    )
    rate_limit_per_second: float = 10.0
    concurrency_limit: int = 2
    credential_references: List[str] = Field(default_factory=list)
    raw_evidence_policy: Dict[str, Any] = Field(
        default_factory=lambda: {
            "format": "json",
            "sha256_hash": True,
            "max_size_bytes": 10485760,  # 10 MB cap
            "quarantine_on_invalid": True,
        }
    )
    input_schema_version: str = "v1.0"
    output_schema_version: str = "v1.0"
    paired_ai_role: str
    paired_ai_profile_version: str = "1.0.0"
    cancellation_signal: str = "SIGTERM"

    model_config = ConfigDict(use_enum_values=True)


# ─── 4. Stage Approvals & Execution Tracking ─────────────────────────────────

class StageApproval(BaseModel):
    """Signed approval binding an active stage to specific targets, method, and rate ceiling."""
    approval_id: str = Field(default_factory=lambda: f"appr-{uuid.uuid4().hex[:8]}")
    stage_key: SequentialStageKey
    tool_id: str
    method_name: str
    target_count: int = 0
    target_summary: List[str] = Field(default_factory=list)
    exclusions: List[str] = Field(default_factory=list)
    rate_ceiling: float = 10.0
    timeout_seconds: int = 60
    expected_traffic_class: str = "Active HTTP probes"
    credential_reference: Optional[str] = None
    approval_expiry: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    plan_digest: str = ""
    is_approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    invalidated_reason: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("approval_expiry", "approved_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class StageExecutionRecord(BaseModel):
    """Execution status and artifact trace for an individual stage in the 14-stage pipeline."""
    stage_key: SequentialStageKey
    stage_name: str
    tool_id: str
    profile_used: str = "default"
    status: CellWorkflowState = CellWorkflowState.PLANNED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    target_count: int = 0
    targets_in_scope: List[str] = Field(default_factory=list)
    raw_artifact_ref: Optional[str] = None
    raw_artifact_sha256: Optional[str] = None
    normalized_count: int = 0
    quarantined_count: int = 0
    error_message: Optional[str] = None
    coverage_notes: Optional[str] = None
    approval_id: Optional[str] = None
    input_handoff_ref: Optional[str] = None
    output_handoff_ref: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("started_at", "completed_at")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class AIPairedProposal(BaseModel):
    """Structured proposal produced by a tool's paired AI role."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_stage: SequentialStageKey
    ai_role: str
    model_version: str = "gemini-3.8-flash"
    evidence_references: List[str] = Field(default_factory=list)
    analysis_summary: str
    uncertainty_notes: Optional[str] = None
    proposed_next_stage: Optional[SequentialStageKey] = None
    proposed_profile: Optional[str] = None
    proposed_targets: List[str] = Field(default_factory=list)
    requires_operator_approval: bool = False
    policy_evaluation_status: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("created_at")
    def serialize_dt(self, v: datetime) -> str:
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


# ─── 5. Raw Artifact & Quarantine Schemas ────────────────────────────────────

class RawEvidenceArtifact(BaseModel):
    """Immutable, stored raw scanner output before parsing."""
    artifact_id: str = Field(default_factory=lambda: f"art-{uuid.uuid4().hex[:12]}")
    scan_id: str
    stage_key: SequentialStageKey
    tool_id: str
    tool_version: str
    adapter_version: str
    image_digest: str
    target_set_digest: str
    content_format: str  # json | xml | text
    raw_content: str
    sha256_digest: str
    is_quarantined: bool = False
    quarantine_reason: Optional[str] = None
    collected_at: datetime = Field(default_factory=utc_now)

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("collected_at")
    def serialize_dt(self, v: datetime) -> str:
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")

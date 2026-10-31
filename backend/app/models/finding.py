from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field, ConfigDict, field_serializer


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DataSource(str, Enum):
    TOOL_OUTPUT = "TOOL_OUTPUT"
    NETWORK_PROBE = "NETWORK_PROBE"
    DNS_RESPONSE = "DNS_RESPONSE"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    MANUAL_VERIFIED = "MANUAL_VERIFIED"
    AI_VERIFIED = "AI_VERIFIED"
    EXTERNAL_INTEL = "EXTERNAL_INTEL"
    HYPOTHESIS = "HYPOTHESIS"


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 Broken Access Control"
    A02_CRYPTO_FAILURES = "A02:2021 Cryptographic Failures"
    A03_INJECTION = "A03:2021 Injection"
    A04_INSECURE_DESIGN = "A04:2021 Insecure Design"
    A05_SECURITY_MISCONFIG = "A05:2021 Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 Identification and Authentication Failures"
    A08_SOFTWARE_INTEGRITY = "A08:2021 Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 Server-Side Request Forgery"
    UNKNOWN = "Unknown"


class CVSSVector(BaseModel):
    attack_vector: str = "N"          # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"      # L=Low, H=High
    privileges_required: str = "N"   # N=None, L=Low, H=High
    user_interaction: str = "N"       # N=None, R=Required
    scope: str = "U"                  # U=Unchanged, C=Changed
    confidentiality: str = "N"        # N=None, L=Low, H=High
    integrity: str = "N"
    availability: str = "N"
    base_score: float = 0.0
    vector_string: str = ""


class ProofOfConcept(BaseModel):
    request: Optional[str] = None
    response: Optional[str] = None
    payload: Optional[str] = None
    screenshot_path: Optional[str] = None
    reproduction_steps: List[str] = Field(default_factory=list)


class Remediation(BaseModel):
    root_cause: Optional[str] = None
    fix_summary: Optional[str] = None
    fix_steps: List[str] = Field(default_factory=list)
    secure_code_example: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class AnalystReviewEntry(BaseModel):
    """Immutable audit trail entry for finding lifecycle transitions and analyst reviews."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = "system"
    from_state: Optional[str] = None
    to_state: str
    mapped_status: str
    rationale: Optional[str] = None
    evidence_hash: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)

    @field_serializer("timestamp")
    def serialize_dt(self, v: Optional[datetime]) -> Optional[str]:
        if v is None:
            return None
        return (v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v).isoformat().replace("+00:00", "Z")


class Finding(BaseModel):
    """A single vulnerability finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = Field(default="tenant_default", description="Tenant isolation identifier")
    scan_id: str
    title: str
    description: str
    severity: Severity
    owasp_category: OWASPCategory = OWASPCategory.UNKNOWN
    cvss: Optional[CVSSVector] = None
    cvss_score: float = 0.0
    affected_endpoint: str
    affected_parameter: Optional[str] = None
    tool_source: str = ""
    data_source: DataSource = Field(default=DataSource.TOOL_OUTPUT, description="Mandatory verifiable origin data source")
    raw_finding: Optional[Dict[str, Any]] = None
    poc: Optional[ProofOfConcept] = None
    remediation: Optional[Remediation] = None
    tags: List[str] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)
    confirmed: bool = False
    false_positive: bool = False
    validation_status: str = "detected"
    validation_confidence: float = 0.0
    asset_id: Optional[str] = None
    cwe_ids: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    evidence_id: Optional[str] = None
    evidence_hash: Optional[str] = None
    lifecycle_state: str = Field(default="DISCOVERED", description="Internal 9-stage FindingLifecycleState")
    lifecycle_status: str = Field(default="Detected", description="Canonical operational status: Detected, Pending Validation, Validated, False Positive, Inconclusive")
    validation_record: Optional[Dict[str, Any]] = None
    review_history: List[AnalystReviewEntry] = Field(default_factory=list)
    exploitability_level: Optional[str] = None
    contextual_risk_score: Optional[float] = None
    retest_status: Optional[str] = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(use_enum_values=True)

    def transition_state(
        self,
        to_state: str,
        actor: str = "system",
        rationale: Optional[str] = None,
        evidence_hash: Optional[str] = None,
    ) -> None:
        from app.models.v1_7_models import map_finding_lifecycle_status
        from_state = self.lifecycle_state
        self.lifecycle_state = str(to_state).upper()
        self.lifecycle_status = map_finding_lifecycle_status(self.lifecycle_state)
        if evidence_hash:
            self.evidence_hash = evidence_hash
        entry = AnalystReviewEntry(
            from_state=from_state,
            to_state=self.lifecycle_state,
            mapped_status=self.lifecycle_status,
            actor=actor,
            rationale=rationale,
            evidence_hash=self.evidence_hash,
        )
        self.review_history.append(entry)


def transition_finding_state(
    finding: Finding | Dict[str, Any],
    to_state: str,
    actor: str = "system",
    rationale: Optional[str] = None,
    evidence_hash: Optional[str] = None,
) -> None:
    """Transition finding lifecycle state, compute mapped status, and append review history."""
    from app.models.v1_7_models import map_finding_lifecycle_status
    if isinstance(finding, Finding):
        finding.transition_state(to_state, actor=actor, rationale=rationale, evidence_hash=evidence_hash)
    elif isinstance(finding, dict):
        from_state = finding.get("lifecycle_state", "DISCOVERED")
        finding["lifecycle_state"] = str(to_state).upper()
        mapped_status = map_finding_lifecycle_status(finding["lifecycle_state"])
        finding["lifecycle_status"] = mapped_status
        if evidence_hash:
            finding["evidence_hash"] = evidence_hash
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "actor": actor,
            "from_state": from_state,
            "to_state": finding["lifecycle_state"],
            "mapped_status": mapped_status,
            "rationale": rationale,
            "evidence_hash": finding.get("evidence_hash"),
        }
        if "review_history" not in finding or not isinstance(finding["review_history"], list):
            finding["review_history"] = []
        finding["review_history"].append(entry)

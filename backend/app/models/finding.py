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


class Finding(BaseModel):
    """A single vulnerability finding."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
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
    exploitability_level: Optional[str] = None
    contextual_risk_score: Optional[float] = None
    retest_status: Optional[str] = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(use_enum_values=True)

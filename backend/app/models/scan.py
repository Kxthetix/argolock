from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field


# ── Enumerations ──────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    AI_ANALYSIS = "ai_analysis"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanPhase(str, Enum):
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    AI_ANALYSIS = "ai_analysis"
    REPORTING = "reporting"


class ToolStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ExploitationStageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ExploitationStageInfo(BaseModel):
    name: str
    status: ExploitationStageStatus = ExploitationStageStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    summary: Optional[str] = None
    findings_count: int = 0


def default_exploitation_stages() -> Dict[str, ExploitationStageInfo]:
    return {
        "web_app": ExploitationStageInfo(name="Web Application Exploits"),
        "network": ExploitationStageInfo(name="Network Exploits"),
        "system_host": ExploitationStageInfo(name="System & Host Exploits"),
        "personnel_social": ExploitationStageInfo(name="Personnel & Social Engineering Exploits"),
    }


# ── Tool Result ───────────────────────────────────────────────────────────────


class ToolResult(BaseModel):
    tool_name: str
    status: ToolStatus = ToolStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    raw_output: Optional[str] = None
    parsed_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None


# ── Scan Models ───────────────────────────────────────────────────────────────

class ScanScope(BaseModel):
    """Authorized scope declaration for a scan target."""
    target: str = Field(..., description="Target domain, IP, or CIDR range")
    authorized: bool = Field(True, description="User confirms they own/have authorization")
    authorization_note: Optional[str] = Field(None, description="Authorization details (e.g. bug bounty program)")
    excluded_paths: List[str] = Field(default_factory=list)
    max_depth: int = Field(3, ge=1, le=10)


class ScanConfig(BaseModel):
    """Configuration for a scan run."""
    phases: List[ScanPhase] = Field(
        default=[ScanPhase.RECON, ScanPhase.SCANNING, ScanPhase.AI_ANALYSIS, ScanPhase.REPORTING]
    )
    safe_mode: bool = True
    enable_exploitation: bool = False
    nuclei_severity: List[str] = Field(default=["critical", "high", "medium"])
    nmap_ports: str = "top-1000"
    timeout_minutes: int = Field(60, ge=5, le=480)


class CreateScanRequest(BaseModel):
    scope: ScanScope
    config: ScanConfig = Field(default_factory=ScanConfig)
    name: Optional[str] = None


class ScanDocument(BaseModel):
    """MongoDB document for a scan."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: Optional[str] = None
    scope: ScanScope
    config: ScanConfig
    status: ScanStatus = ScanStatus.PENDING
    current_phase: Optional[str] = None
    progress_percent: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    tool_results: Dict[str, ToolResult] = Field(default_factory=dict)
    finding_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    error: Optional[str] = None
    exploitation_stages: Dict[str, ExploitationStageInfo] = Field(default_factory=default_exploitation_stages)

    class Config:
        use_enum_values = True

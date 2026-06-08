from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field


class ReportFormat(str, Enum):
    PDF = "pdf"
    JSON = "json"
    BOTH = "both"


class ReportDocument(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    format: ReportFormat = ReportFormat.BOTH
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    pdf_path: Optional[str] = None
    json_path: Optional[str] = None
    executive_summary: Optional[str] = None
    methodology: Optional[str] = None
    total_findings: int = 0
    risk_score: float = 0.0
    risk_rating: str = "Low"

    class Config:
        use_enum_values = True

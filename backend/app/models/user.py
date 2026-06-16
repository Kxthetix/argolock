from __future__ import annotations

from datetime import datetime
from typing import Optional
import uuid

from pydantic import BaseModel, Field


class UserDocument(BaseModel):
    """MongoDB document for a user (Auth)."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str = Field(..., description="Unique user email address")
    active_otp: Optional[str] = Field(None, description="Active 6-digit verification code")
    otp_expires_at: Optional[datetime] = Field(None, description="Expiry time of active OTP")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True

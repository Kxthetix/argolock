from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


class UserDocument(BaseModel):
    """MongoDB document for a user (Auth)."""
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str = Field(..., description="Unique user email address")
    password_hash: Optional[str] = Field(None, description="Argon2id password hash (null for OAuth-only users)")
    name: Optional[str] = Field(None, description="User display name")
    avatar_url: Optional[str] = Field(None, description="Profile avatar URL (from OAuth provider)")
    auth_provider: str = Field(default="email", description="Authentication provider: email | google | github")
    provider_id: Optional[str] = Field(None, description="OAuth provider user ID")
    email_verified: bool = Field(default=False, description="Whether email has been verified via OTP")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

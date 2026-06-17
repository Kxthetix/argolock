from __future__ import annotations

from datetime import datetime
from typing import Optional
import uuid

from pydantic import BaseModel, Field, ConfigDict


class UserDocument(BaseModel):
    """MongoDB document for a user (Auth)."""
    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str = Field(..., description="Unique user email address")
    password_hash: Optional[str] = Field(None, description="Argon2id password hash")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

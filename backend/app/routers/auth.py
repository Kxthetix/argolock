from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from loguru import logger
from pydantic import BaseModel, EmailStr, Field

from app.config import settings
from app.database import get_db
from app.models.user import UserDocument

router = APIRouter()
security = HTTPBearer(auto_error=False)

# ── Schemas ──────────────────────────────────────────────────────────────────

class SendOTPRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")


class VerifyOTPRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    otp: str = Field(..., description="6-digit verification code")


# ── Dependency ───────────────────────────────────────────────────────────────

async def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> Dict[str, Any]:
    """Dependency to validate the JWT token and return the current user."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    db = get_db()
    user = await db["users"].find_one({"email": email})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user.pop("_id", None)
    return user


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/send-otp")
async def send_otp(request: SendOTPRequest):
    """Generate and log a 6-digit OTP for the user."""
    email = request.email.strip().lower()
    otp = f"{random.randint(100000, 999999)}"
    expires_at = datetime.utcnow() + timedelta(minutes=5)

    db = get_db()
    
    # Upsert the user document with the generated OTP
    await db["users"].update_one(
        {"email": email},
        {
            "$set": {
                "active_otp": otp,
                "otp_expires_at": expires_at,
                "updated_at": datetime.utcnow()
            },
            "$setOnInsert": {
                "id": UserDocument(email=email).id,
                "created_at": datetime.utcnow()
            }
        },
        upsert=True
    )

    logger.info(f"🔑 [AUTH] Generated OTP {otp} for email {email}. Expires at {expires_at}")

    # Return OTP directly in response for demo mode/development purposes
    return {
        "message": "OTP generated and logged successfully",
        "email": email,
        "otp": otp  # Included for demo/testing convenience
    }


@router.post("/verify-otp")
async def verify_otp(request: VerifyOTPRequest):
    """Verify the 6-digit OTP and issue a JWT token."""
    email = request.email.strip().lower()
    otp = request.otp.strip()

    db = get_db()
    user = await db["users"].find_one({"email": email})

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or verification code"
        )

    active_otp = user.get("active_otp")
    otp_expires_at = user.get("otp_expires_at")

    if not active_otp or active_otp != otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or verification code"
        )

    if otp_expires_at and datetime.utcnow() > otp_expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code has expired"
        )

    # Clear OTP on successful verification
    await db["users"].update_one(
        {"email": email},
        {
            "$set": {
                "active_otp": None,
                "otp_expires_at": None,
                "updated_at": datetime.utcnow()
            }
        }
    )

    # Generate JWT Token (Expires in 24 hours)
    token_expiry = datetime.utcnow() + timedelta(days=1)
    access_token = jwt.encode(
        {"sub": email, "exp": token_expiry},
        settings.secret_key,
        algorithm="HS256"
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "email": email
    }


@router.get("/me")
async def read_current_user(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get details of the currently authenticated user."""
    return current_user

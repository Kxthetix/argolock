from __future__ import annotations

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
from app.utils.crypto import hash_password, verify_password

router = APIRouter()
security = HTTPBearer(auto_error=False)

# ── Schemas ──────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="User password (min 6 characters)")


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
    user.pop("password_hash", None)  # Hide password hash from client
    return user


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/login")
async def login(request: LoginRequest):
    """Register or log in the user using email and password."""
    email = request.email.strip().lower()
    password = request.password

    db = get_db()
    user = await db["users"].find_one({"email": email})

    if user is None:
        # Register new user dynamically on first login for demo convenience
        hashed = hash_password(password)
        user_doc = UserDocument(email=email, password_hash=hashed)
        await db["users"].insert_one(user_doc.model_dump())
        logger.info(f"👤 [AUTH] Registered new user: {email} with Argon2id")
    else:
        # Verify credentials for existing user
        stored_hash = user.get("password_hash")
        if not stored_hash or not verify_password(stored_hash, password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or password"
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


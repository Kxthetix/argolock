from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import ExpiredSignatureError, JWTError, jwt
from loguru import logger
from pydantic import BaseModel, EmailStr, Field

from app.config import settings
from app.database import get_db
from app.models.user import UserDocument
from app.utils.crypto import hash_password, verify_password
from app.utils.otp import generate_otp, store_otp, verify_otp, send_otp_email

router = APIRouter()
security = HTTPBearer(auto_error=False)

# ── Schemas ──────────────────────────────────────────────────────────────────


class LoginRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="User password (min 6 characters)")


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, description="User display name")
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="User password (min 6 characters)")


class OTPSendRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address to send OTP to")


class OTPVerifyRequest(BaseModel):
    email: EmailStr = Field(..., description="Email address")
    code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")


# ── Helpers ──────────────────────────────────────────────────────────────────


def _create_jwt(email: str) -> str:
    """Create a JWT access token that expires in 7 days."""
    token_expiry = datetime.now(timezone.utc) + timedelta(days=7)
    return jwt.encode(
        {"sub": email, "exp": token_expiry},
        settings.secret_key,
        algorithm="HS256",
    )


# ── Dependency ───────────────────────────────────────────────────────────────


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> Dict[str, Any]:
    """Dependency to validate the JWT token, or fallback to default local operator user."""
    default_user = {
        "id": "operator-001",
        "email": "operator@argolock.net",
        "name": "Security Operator",
        "role": "admin",
        "auth_provider": "local",
    }
    if credentials is None:
        return default_user

    token = credentials.credentials
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email:
            db = get_db()
            user = await db["users"].find_one({"email": email})
            if user:
                user.pop("_id", None)
                user.pop("password_hash", None)
                return user
    except Exception:
        pass

    return default_user


# ── Endpoints: Email / Password ─────────────────────────────────────────────


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
                detail="Invalid email or password",
            )

    access_token = _create_jwt(email)
    return {"access_token": access_token, "token_type": "bearer", "email": email}


@router.post("/register")
async def register(request: RegisterRequest):
    """Explicitly register a new user with name, email, and password."""
    email = request.email.strip().lower()

    db = get_db()
    existing = await db["users"].find_one({"email": email})
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this email already exists",
        )

    hashed = hash_password(request.password)
    user_doc = UserDocument(
        email=email,
        password_hash=hashed,
        name=request.name.strip(),
        auth_provider="email",
    )
    await db["users"].insert_one(user_doc.model_dump())
    logger.info(f"👤 [AUTH] Registered new user via /register: {email}")

    access_token = _create_jwt(email)
    return {"access_token": access_token, "token_type": "bearer", "email": email}


# ── Endpoints: OTP ───────────────────────────────────────────────────────────


@router.post("/otp/send")
async def otp_send(request: OTPSendRequest):
    """Generate a 6-digit OTP, store in DB, and send via email / log."""
    email = request.email.strip().lower()
    code = generate_otp()

    db = get_db()
    await store_otp(email, code, db)
    send_otp_email(email, code)

    return {"message": "OTP sent successfully", "email": email}


@router.post("/otp/verify")
async def otp_verify(request: OTPVerifyRequest):
    """Verify an OTP code, mark email_verified=True, and issue a JWT."""
    email = request.email.strip().lower()
    code = request.code.strip()

    db = get_db()
    valid = await verify_otp(email, code, db)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP code",
        )

    # Ensure a user record exists (might be a new user verifying email before
    # setting a password, or an existing user)
    user = await db["users"].find_one({"email": email})
    if user is None:
        user_doc = UserDocument(email=email, email_verified=True)
        await db["users"].insert_one(user_doc.model_dump())
        logger.info(f"👤 [AUTH] Created user via OTP verification: {email}")
    else:
        await db["users"].update_one(
            {"email": email},
            {"$set": {"email_verified": True, "updated_at": datetime.now(timezone.utc)}},
        )

    access_token = _create_jwt(email)
    return {"access_token": access_token, "token_type": "bearer", "email": email}


# ── Endpoints: Google OAuth ──────────────────────────────────────────────────

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


@router.get("/google")
async def google_login():
    """Redirect the user to Google's OAuth consent screen."""
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Google OAuth is not configured",
        )

    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": f"{settings.frontend_url}/api/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return RedirectResponse(url=url)


@router.get("/google/callback")
async def google_callback(code: str):
    """Handle the Google OAuth callback: exchange code → profile → JWT → redirect."""
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Google OAuth is not configured",
        )

    # 1. Exchange authorization code for access token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": f"{settings.frontend_url}/api/auth/google/callback",
                "grant_type": "authorization_code",
            },
        )

    if token_resp.status_code != 200:
        logger.error(f"🔴 [GOOGLE] Token exchange failed: {token_resp.text}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange Google authorization code",
        )

    token_data = token_resp.json()
    access_token = token_data.get("access_token")

    # 2. Fetch user profile
    async with httpx.AsyncClient() as client:
        profile_resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if profile_resp.status_code != 200:
        logger.error(f"🔴 [GOOGLE] Profile fetch failed: {profile_resp.text}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch Google user profile",
        )

    profile = profile_resp.json()
    email = profile.get("email", "").strip().lower()
    name = profile.get("name")
    avatar_url = profile.get("picture")
    provider_id = profile.get("id")

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google account has no email address",
        )

    # 3. Create or update user in DB
    db = get_db()
    user = await db["users"].find_one({"email": email})
    if user is None:
        user_doc = UserDocument(
            email=email,
            name=name,
            avatar_url=avatar_url,
            auth_provider="google",
            provider_id=provider_id,
            email_verified=True,
        )
        await db["users"].insert_one(user_doc.model_dump())
        logger.info(f"👤 [AUTH] Created Google user: {email}")
    else:
        await db["users"].update_one(
            {"email": email},
            {
                "$set": {
                    "name": name or user.get("name"),
                    "avatar_url": avatar_url or user.get("avatar_url"),
                    "email_verified": True,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

    # 4. Issue JWT and redirect to frontend
    jwt_token = _create_jwt(email)
    redirect_url = f"{settings.frontend_url}/auth/callback?token={jwt_token}&email={email}"
    return RedirectResponse(url=redirect_url)


# ── Endpoints: GitHub OAuth ──────────────────────────────────────────────────

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


@router.get("/github")
async def github_login():
    """Redirect the user to GitHub's OAuth consent screen."""
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth is not configured",
        )

    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": f"{settings.frontend_url}/api/auth/github/callback",
        "scope": "user:email read:user",
    }
    url = f"{GITHUB_AUTH_URL}?{urlencode(params)}"
    return RedirectResponse(url=url)


@router.get("/github/callback")
async def github_callback(code: str):
    """Handle the GitHub OAuth callback: exchange code → profile → JWT → redirect."""
    if not settings.github_client_id or not settings.github_client_secret:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GitHub OAuth is not configured",
        )

    # 1. Exchange authorization code for access token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": f"{settings.frontend_url}/api/auth/github/callback",
            },
            headers={"Accept": "application/json"},
        )

    if token_resp.status_code != 200:
        logger.error(f"🔴 [GITHUB] Token exchange failed: {token_resp.text}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to exchange GitHub authorization code",
        )

    token_data = token_resp.json()
    access_token = token_data.get("access_token")
    if not access_token:
        logger.error(f"🔴 [GITHUB] No access_token in response: {token_data}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="GitHub did not return an access token",
        )

    # 2. Fetch user profile
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient() as client:
        profile_resp = await client.get(GITHUB_USER_URL, headers=headers)
        emails_resp = await client.get(GITHUB_EMAILS_URL, headers=headers)

    if profile_resp.status_code != 200:
        logger.error(f"🔴 [GITHUB] Profile fetch failed: {profile_resp.text}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to fetch GitHub user profile",
        )

    profile = profile_resp.json()
    name = profile.get("name") or profile.get("login")
    avatar_url = profile.get("avatar_url")
    provider_id = str(profile.get("id", ""))

    # Determine primary email – the profile email may be null if set to private
    email = (profile.get("email") or "").strip().lower()
    if not email and emails_resp.status_code == 200:
        for entry in emails_resp.json():
            if entry.get("primary") and entry.get("verified"):
                email = entry["email"].strip().lower()
                break

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve a verified email from GitHub",
        )

    # 3. Create or update user in DB
    db = get_db()
    user = await db["users"].find_one({"email": email})
    if user is None:
        user_doc = UserDocument(
            email=email,
            name=name,
            avatar_url=avatar_url,
            auth_provider="github",
            provider_id=provider_id,
            email_verified=True,
        )
        await db["users"].insert_one(user_doc.model_dump())
        logger.info(f"👤 [AUTH] Created GitHub user: {email}")
    else:
        await db["users"].update_one(
            {"email": email},
            {
                "$set": {
                    "name": name or user.get("name"),
                    "avatar_url": avatar_url or user.get("avatar_url"),
                    "email_verified": True,
                    "updated_at": datetime.now(timezone.utc),
                }
            },
        )

    # 4. Issue JWT and redirect to frontend
    jwt_token = _create_jwt(email)
    redirect_url = f"{settings.frontend_url}/auth/callback?token={jwt_token}&email={email}"
    return RedirectResponse(url=redirect_url)


# ── Endpoints: Current User ─────────────────────────────────────────────────


@router.get("/me")
async def read_current_user(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get details of the currently authenticated user."""
    return current_user

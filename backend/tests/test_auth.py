import pytest
from app.database import get_db
from app.utils.crypto import hash_password, verify_password

def test_argon2id_hashing():
    """Verify that password hashing and verification function correctly."""
    password = "supersecretpassword123"
    hashed = hash_password(password)
    
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, password) is True
    assert verify_password(hashed, "wrongpassword") is False


@pytest.mark.asyncio
async def test_user_registration_on_first_login(client):
    """Verify that a user is registered when logging in for the first time."""
    email = "newuser@argolock.com"
    password = "mypassword123"
    
    # Clean up user if exists
    db = get_db()
    await db["users"].delete_one({"email": email})

    payload = {"email": email, "password": password}
    response = await client.post("/api/auth/login", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Verify user in database has a valid Argon2id hash
    user = await db["users"].find_one({"email": email})
    assert user is not None
    assert user["password_hash"].startswith("$argon2id$")


@pytest.mark.asyncio
async def test_user_login_success(client):
    """Verify that an existing user can log in with correct credentials."""
    email = "existinguser@argolock.com"
    password = "securepassword456"

    # Seed user in DB
    db = get_db()
    hashed = hash_password(password)
    await db["users"].update_one(
        {"email": email},
        {"$set": {"password_hash": hashed}},
        upsert=True
    )

    payload = {"email": email, "password": password}
    response = await client.post("/api/auth/login", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["email"] == email


@pytest.mark.asyncio
async def test_user_login_invalid_password(client):
    """Verify that login fails when using an incorrect password."""
    email = "existinguser@argolock.com"
    
    payload = {"email": email, "password": "wrongpasswordhere"}
    response = await client.post("/api/auth/login", json=payload)
    
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid email or password"


@pytest.mark.asyncio
async def test_protected_me_route(client):
    """Verify that the /me route validates the JWT and returns user profile without password_hash."""
    email = "meuser@argolock.com"
    password = "meuserpassword"
    
    # 1. Access without token -> 401
    response = await client.get("/api/auth/me")
    assert response.status_code == 401

    # 2. Login to get token
    payload = {"email": email, "password": password}
    login_response = await client.post("/api/auth/login", json=payload)
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # 3. Access with valid token -> 200
    headers = {"Authorization": f"Bearer {token}"}
    response = await client.get("/api/auth/me", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert "password_hash" not in data  # Assert sensitive hash is excluded
    assert "id" in data


@pytest.mark.asyncio
async def test_explicit_registration(client):
    """Verify that a user can explicitly register with a name, email, and password."""
    email = "register_test@argolock.com"
    password = "newpassword123"
    name = "Register Test"

    db = get_db()
    await db["users"].delete_one({"email": email})

    payload = {"name": name, "email": email, "password": password}
    response = await client.post("/api/auth/register", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email
    assert "access_token" in data

    # Verify user fields in DB
    user = await db["users"].find_one({"email": email})
    assert user is not None
    assert user["name"] == name
    assert user["auth_provider"] == "email"


@pytest.mark.asyncio
async def test_otp_send_and_verify(client):
    """Verify the OTP send, DB storage, and verification flow."""
    email = "otp_test@argolock.com"

    db = get_db()
    await db["users"].delete_one({"email": email})
    await db["otp_codes"].delete_one({"email": email})

    # 1. Send OTP
    send_payload = {"email": email}
    send_response = await client.post("/api/auth/otp/send", json=send_payload)
    assert send_response.status_code == 200
    assert send_response.json()["email"] == email

    # 2. Check OTP generated in DB
    otp_record = await db["otp_codes"].find_one({"email": email})
    assert otp_record is not None
    code = otp_record["code"]
    assert len(code) == 6

    # 3. Verify incorrect OTP -> 400
    verify_payload_bad = {"email": email, "code": "000000"}
    verify_response_bad = await client.post("/api/auth/otp/verify", json=verify_payload_bad)
    assert verify_response_bad.status_code == 400

    # 4. Verify correct OTP -> 200
    verify_payload_good = {"email": email, "code": code}
    verify_response_good = await client.post("/api/auth/otp/verify", json=verify_payload_good)
    assert verify_response_good.status_code == 200
    data = verify_response_good.json()
    assert data["email"] == email
    assert "access_token" in data

    # 5. Verify email_verified is True in user document
    user = await db["users"].find_one({"email": email})
    assert user is not None
    assert user["email_verified"] is True


@pytest.mark.asyncio
async def test_expired_token_handling(client):
    """Verify that an expired JWT token returns 401 with session expired message."""
    from datetime import datetime, timedelta, timezone
    from jose import jwt
    from app.config import settings

    # Create an expired token (1 hour in the past)
    expired_time = datetime.now(timezone.utc) - timedelta(hours=1)
    expired_token = jwt.encode(
        {"sub": "expired_test@argolock.com", "exp": expired_time},
        settings.secret_key,
        algorithm="HS256",
    )

    headers = {"Authorization": f"Bearer {expired_token}"}
    response = await client.get("/api/auth/me", headers=headers)
    assert response.status_code == 401
    assert "Session expired" in response.json()["detail"]


@pytest.mark.asyncio
async def test_system_endpoints_public_access(client):
    """Verify that /api/system/agents and /api/system/tools are accessible without auth."""
    # Agents endpoint should return 200 without auth header
    agents_res = await client.get("/api/system/agents")
    assert agents_res.status_code == 200
    agents_data = agents_res.json()
    assert "agents" in agents_data
    assert "active_provider" in agents_data

    # Tools endpoint should return 200 without auth header
    tools_res = await client.get("/api/system/tools")
    assert tools_res.status_code == 200
    tools_data = tools_res.json()
    assert "tools" in tools_data

    # Destructive clear-history endpoint should still require auth (401 without auth)
    clear_res = await client.post("/api/system/clear-history")
    assert clear_res.status_code == 401




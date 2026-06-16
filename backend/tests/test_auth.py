import pytest
from datetime import datetime, timedelta
from app.database import get_db

@pytest.mark.asyncio(scope="session")
async def test_send_otp(client):
    """Verify that sending OTP generates a 6-digit code and stores/logs it."""
    payload = {"email": "testuser@argolock.com"}
    response = await client.post("/api/auth/send-otp", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "testuser@argolock.com"
    assert "otp" in data
    assert len(data["otp"]) == 6
    assert data["otp"].isdigit()

    # Verify user in database
    db = get_db()
    user = await db["users"].find_one({"email": "testuser@argolock.com"})
    assert user is not None
    assert user["active_otp"] == data["otp"]
    assert user["otp_expires_at"] is not None


@pytest.mark.asyncio(scope="session")
async def test_verify_otp_success(client):
    """Verify that entering the correct OTP logs the user in and returns a JWT token."""
    email = "successuser@argolock.com"
    
    # 1. Send OTP
    response = await client.post("/api/auth/send-otp", json={"email": email})
    assert response.status_code == 200
    otp = response.json()["otp"]

    # 2. Verify OTP
    verify_payload = {"email": email, "otp": otp}
    response = await client.post("/api/auth/verify-otp", json=verify_payload)
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["email"] == email

    # 3. Verify OTP is cleared in database
    db = get_db()
    user = await db["users"].find_one({"email": email})
    assert user["active_otp"] is None
    assert user["otp_expires_at"] is None


@pytest.mark.asyncio(scope="session")
async def test_verify_otp_invalid(client):
    """Verify that entering an incorrect OTP returns 400 Bad Request."""
    email = "invalidotp@argolock.com"
    
    # Send OTP
    response = await client.post("/api/auth/send-otp", json={"email": email})
    assert response.status_code == 200

    # Verify invalid OTP
    verify_payload = {"email": email, "otp": "999999"}  # Incorrect code
    response = await client.post("/api/auth/verify-otp", json=verify_payload)
    
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid email or verification code"


@pytest.mark.asyncio(scope="session")
async def test_verify_otp_expired(client):
    """Verify that an expired OTP is rejected with 400 Bad Request."""
    email = "expireduser@argolock.com"
    db = get_db()

    # Manually create user with expired OTP
    await db["users"].update_one(
        {"email": email},
        {
            "$set": {
                "active_otp": "123456",
                "otp_expires_at": datetime.utcnow() - timedelta(seconds=1),  # Already expired
                "updated_at": datetime.utcnow()
            },
            "$setOnInsert": {
                "id": "expired-user-id",
                "created_at": datetime.utcnow()
            }
        },
        upsert=True
    )

    verify_payload = {"email": email, "otp": "123456"}
    response = await client.post("/api/auth/verify-otp", json=verify_payload)
    
    assert response.status_code == 400
    assert response.json()["detail"] == "Verification code has expired"


@pytest.mark.asyncio(scope="session")
async def test_protected_me_route(client):
    """Verify that the /me route validates the JWT and returns user details on success, 401 on failure."""
    email = "meuser@argolock.com"
    
    # 1. Access without token -> 401
    response = await client.get("/api/auth/me")
    assert response.status_code == 401

    # 2. Access with invalid token -> 401
    headers = {"Authorization": "Bearer invalidtoken123"}
    response = await client.get("/api/auth/me", headers=headers)
    assert response.status_code == 401

    # 3. Get valid token
    send_response = await client.post("/api/auth/send-otp", json={"email": email})
    otp = send_response.json()["otp"]
    verify_response = await client.post("/api/auth/verify-otp", json={"email": email, "otp": otp})
    token = verify_response.json()["access_token"]

    # 4. Access with valid token -> 200
    headers = {"Authorization": f"Bearer {token}"}
    response = await client.get("/api/auth/me", headers=headers)
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email

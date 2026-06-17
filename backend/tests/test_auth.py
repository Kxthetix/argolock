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


@pytest.mark.asyncio(scope="session")
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


@pytest.mark.asyncio(scope="session")
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


@pytest.mark.asyncio(scope="session")
async def test_user_login_invalid_password(client):
    """Verify that login fails when using an incorrect password."""
    email = "existinguser@argolock.com"
    
    payload = {"email": email, "password": "wrongpasswordhere"}
    response = await client.post("/api/auth/login", json=payload)
    
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid email or password"


@pytest.mark.asyncio(scope="session")
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


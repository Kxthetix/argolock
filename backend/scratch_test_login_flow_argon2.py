import asyncio
import httpx
import sys

async def main():
    print("[AUTH TEST] Starting backend Argon2id login flow integration test...")
    url = "http://127.0.0.1:8000"
    email = "argon2_integration_test@argolock.com"
    password = "supersecurepassword123"

    async with httpx.AsyncClient(base_url=url) as client:
        # 1. Register / First Login
        print(f"[AUTH TEST] Sending first login/register request for {email}...")
        resp = await client.post("/api/auth/login", json={"email": email, "password": password})
        if resp.status_code != 200:
            print(f"[AUTH TEST] Registration failed. Status: {resp.status_code}, Body: {resp.text}")
            sys.exit(1)

        data = resp.json()
        print(f"[AUTH TEST] First login successful! Token received.")
        token = data.get("access_token")
        if not token:
            print("[AUTH TEST] No access token found in response.")
            sys.exit(1)

        # 2. Login again with correct credentials
        print(f"[AUTH TEST] Sending second login request for {email} with correct password...")
        resp = await client.post("/api/auth/login", json={"email": email, "password": password})
        if resp.status_code != 200:
            print(f"[AUTH TEST] Second login failed. Status: {resp.status_code}, Body: {resp.text}")
            sys.exit(1)
        print(f"[AUTH TEST] Second login successful!")

        # 3. Try login with incorrect password
        print(f"[AUTH TEST] Sending login request with incorrect password...")
        resp_fail = await client.post("/api/auth/login", json={"email": email, "password": "wrongpassword123"})
        if resp_fail.status_code == 400:
            print(f"[AUTH TEST] Successfully rejected invalid password (400 Bad Request): {resp_fail.json()['detail']}")
        else:
            print(f"[AUTH TEST] Unexpected status code for invalid password: {resp_fail.status_code}")
            sys.exit(1)

        # 4. Access /me route with valid token
        print("[AUTH TEST] Fetching /me endpoint with authentication token...")
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.get("/api/auth/me", headers=headers)
        if resp.status_code != 200:
            print(f"[AUTH TEST] Failed to access /me. Status: {resp.status_code}, Body: {resp.text}")
            sys.exit(1)

        me_data = resp.json()
        print(f"[AUTH TEST] Success! Authenticated user profile: {me_data}")
        if "password_hash" in me_data:
            print("[AUTH TEST] Security Alert: password_hash was leaked in the response!")
            sys.exit(1)
        if me_data.get("email") != email:
            print(f"[AUTH TEST] Profile email mismatch! Expected {email}, got {me_data.get('email')}")
            sys.exit(1)

        print("[AUTH TEST] All backend Argon2id integration tests passed successfully!")

if __name__ == "__main__":
    asyncio.run(main())

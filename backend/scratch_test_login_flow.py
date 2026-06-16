import asyncio
import httpx
import sys

async def main():
    print("[AUTH TEST] Starting backend auth integration test...")
    url = "http://127.0.0.1:8000"
    email = "integration_test@argolock.com"
    
    async with httpx.AsyncClient(base_url=url) as client:
        # 1. Send OTP
        print(f"[AUTH TEST] Sending OTP request for {email}...")
        resp = await client.post("/api/auth/send-otp", json={"email": email})
        if resp.status_code != 200:
            print(f"[AUTH TEST] Failed to send OTP. Status: {resp.status_code}, Body: {resp.text}")
            sys.exit(1)
        
        data = resp.json()
        print(f"[AUTH TEST] OTP response received: {data}")
        otp = data.get("otp")
        if not otp:
            print("[AUTH TEST] No OTP found in the response.")
            sys.exit(1)
        print(f"[AUTH TEST] Retrieved OTP: {otp}")
        
        # 2. Verify OTP
        print(f"[AUTH TEST] Verifying OTP {otp} for {email}...")
        resp = await client.post("/api/auth/verify-otp", json={"email": email, "otp": otp})
        if resp.status_code != 200:
            print(f"[AUTH TEST] Verification failed. Status: {resp.status_code}, Body: {resp.text}")
            sys.exit(1)
            
        verify_data = resp.json()
        print(f"[AUTH TEST] Verification successful! Data: {verify_data}")
        token = verify_data.get("access_token")
        if not token:
            print("[AUTH TEST] No access token found in verification response.")
            sys.exit(1)
            
        # 3. Test /me route with valid token
        print("[AUTH TEST] Fetching /me endpoint with authentication token...")
        headers = {"Authorization": f"Bearer {token}"}
        resp = await client.get("/api/auth/me", headers=headers)
        if resp.status_code != 200:
            print(f"[AUTH TEST] Failed to access /me. Status: {resp.status_code}, Body: {resp.text}")
            sys.exit(1)
            
        me_data = resp.json()
        print(f"[AUTH TEST] Success! Authenticated user profile: {me_data}")
        if me_data.get("email") != email:
            print(f"[AUTH TEST] Profile email mismatch! Expected {email}, got {me_data.get('email')}")
            sys.exit(1)
            
        # 4. Test /me route with invalid token
        print("[AUTH TEST] Testing /me endpoint with invalid authentication token...")
        headers_invalid = {"Authorization": "Bearer invalidtoken123"}
        resp_invalid = await client.get("/api/auth/me", headers=headers_invalid)
        if resp_invalid.status_code == 401:
            print("[AUTH TEST] Successfully rejected invalid token (401 Unauthorized)")
        else:
            print(f"[AUTH TEST] Unexpected status code for invalid token: {resp_invalid.status_code}")
            sys.exit(1)
            
        print("[AUTH TEST] All backend integration tests passed successfully!")

if __name__ == "__main__":
    asyncio.run(main())

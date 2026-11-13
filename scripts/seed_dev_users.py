"""
Seed default development users in MongoDB.
"""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.database import connect_db, get_db, disconnect_db
from app.utils.crypto import hash_password

async def seed():
    await connect_db()
    db = get_db()
    pw_hash = hash_password("Argolock2026!")

    for email, role, name in [
        ("admin@argolock.net", "admin", "System Administrator"),
        ("analyst@argolock.net", "analyst", "Lead Security Analyst"),
        ("viewer@argolock.net", "viewer", "Compliance Viewer"),
    ]:
        await db["users"].update_one(
            {"email": email},
            {"$set": {
                "email": email,
                "password_hash": pw_hash,
                "role": role,
                "tenant_id": "tenant_default",
                "name": name,
                "auth_provider": "email"
            }},
            upsert=True
        )
        print(f"Seeded {email} ({role}) with password Argolock2026!")

    await disconnect_db()

if __name__ == "__main__":
    asyncio.run(seed())

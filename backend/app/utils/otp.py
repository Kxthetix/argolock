from __future__ import annotations

import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from typing import Any

from loguru import logger

from app.config import settings


def generate_otp() -> str:
    """Generate a cryptographically random 6-digit OTP code."""
    return str(secrets.randbelow(900_000) + 100_000)


async def store_otp(email: str, code: str, db: Any) -> None:
    """Store an OTP code in MongoDB with TTL-based expiry.

    The ``otp_codes`` collection must have a TTL index on the ``expires_at``
    field.  We ensure it here (idempotent) so the collection is self-cleaning.
    """
    collection = db["otp_codes"]

    # Ensure TTL index exists (idempotent – MongoDB ignores if already present)
    await collection.create_index("expires_at", expireAfterSeconds=0)

    expires_at = datetime.utcnow() + timedelta(minutes=settings.otp_expiry_minutes)

    # Upsert: one active OTP per email at any time
    await collection.update_one(
        {"email": email},
        {
            "$set": {
                "code": code,
                "expires_at": expires_at,
                "created_at": datetime.utcnow(),
            }
        },
        upsert=True,
    )
    logger.info(f"🔑 [OTP] Stored OTP for {email}, expires at {expires_at.isoformat()}")


async def verify_otp(email: str, code: str, db: Any) -> bool:
    """Verify an OTP code and delete it after use (single-use).

    Returns ``True`` if the code is valid and not expired, ``False`` otherwise.
    """
    collection = db["otp_codes"]
    record = await collection.find_one({"email": email, "code": code})

    if record is None:
        logger.warning(f"🔑 [OTP] Verification failed for {email}: no matching code")
        return False

    # Expired check (belt-and-suspenders; TTL index also removes stale docs)
    if record.get("expires_at") and record["expires_at"] < datetime.utcnow():
        await collection.delete_one({"_id": record["_id"]})
        logger.warning(f"🔑 [OTP] Verification failed for {email}: code expired")
        return False

    # Delete after successful verification (single-use)
    await collection.delete_one({"_id": record["_id"]})
    logger.info(f"🔑 [OTP] Verification succeeded for {email}")
    return True


def send_otp_email(email: str, code: str) -> None:
    """Send OTP code via SMTP if configured, otherwise log to console."""
    if not settings.smtp_host or not settings.smtp_user:
        logger.info(
            f"📧 [OTP] SMTP not configured – OTP for {email}: {code}"
        )
        return

    msg = EmailMessage()
    msg["Subject"] = f"ArgoLock – Your verification code: {code}"
    msg["From"] = settings.smtp_user
    msg["To"] = email
    msg.set_content(
        f"Your ArgoLock verification code is:\n\n"
        f"    {code}\n\n"
        f"This code expires in {settings.otp_expiry_minutes} minutes.\n"
        f"If you did not request this, please ignore this email."
    )

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password or "")
            server.send_message(msg)
        logger.info(f"📧 [OTP] Email sent to {email}")
    except Exception as exc:
        logger.error(f"📧 [OTP] Failed to send email to {email}: {exc}")
        # Fallback: still log the code so the user is not locked out in dev
        logger.info(f"📧 [OTP] Fallback – OTP for {email}: {code}")

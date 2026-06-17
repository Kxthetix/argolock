from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# PasswordHasher uses Argon2id by default with safe parameters
ph = PasswordHasher()

def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return ph.hash(password)

def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against an Argon2id hash."""
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False

"""Authentication — JWT token verification with bcrypt password hashing."""

import hashlib
import hmac
import os
import secrets

import bcrypt
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

# Secrets
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", Fernet.generate_key().decode())

security = HTTPBearer()
fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)


def hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(user_id: str, role: str = "user") -> str:
    """Create a JWT access token."""
    payload = {"sub": user_id, "role": role}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def encrypt_pii(data: str) -> str:
    """Encrypt PII data with Fernet (AES-128-CBC)."""
    return fernet.encrypt(data.encode()).decode()


def decrypt_pii(token: str) -> str:
    """Decrypt PII data."""
    return fernet.decrypt(token.encode()).decode()


def generate_api_key() -> str:
    """Generate a secure API key using SHA-256."""
    raw = secrets.token_bytes(32)
    return hashlib.sha256(raw).hexdigest()


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify HMAC-SHA256 webhook signature."""
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Validate JWT and return current user."""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return {"user_id": user_id, "role": payload.get("role", "user")}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

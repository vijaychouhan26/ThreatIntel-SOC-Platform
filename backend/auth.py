import os
import logging
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
import bcrypt
import pyotp
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set")
JWT_ALGO = "HS256"
TOKEN_EXPIRE_MIN = 60 * 8  # 8 ghante
JWT_NOT_BEFORE = int(os.getenv("JWT_NOT_BEFORE", "0"))

# --- Password (bcrypt directly, passlib nahi) ---
def hash_password(plain: str) -> str:
    # bcrypt 72 byte limit -- truncate safely
    pw = plain.encode("utf-8")[:72]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    pw = plain.encode("utf-8")[:72]
    return bcrypt.checkpw(pw, hashed.encode("utf-8"))

# --- JWT token ---
def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        # Tokens created while AUTH_DISABLED was enabled have no issued-at claim
        # and are rejected once MFA authentication is switched back on.
        if int(payload.get("iat", 0)) < JWT_NOT_BEFORE:
            return None
        return payload.get("sub")
    except JWTError:
        return None

# --- TOTP (MFA) ---
def verify_totp(secret: str, code: str) -> bool:
    if not secret:
        if os.getenv("AUTH_DISABLED", "").lower() in ("true", "1", "t", "yes", "y"):
            return True
        logging.warning("MFA_SECRET is empty/None but auth is enabled")
        raise ValueError("MFA_SECRET is missing")
    return pyotp.TOTP(secret).verify(code, valid_window=1)

"""Password hashing (Argon2id), JWT access tokens and opaque refresh tokens."""
import hashlib
import secrets
import uuid
from datetime import timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import get_settings
from app.core.database import utcnow

_ph = PasswordHasher()
# Used to equalise timing when the user does not exist.
_DUMMY_HASH = _ph.hash("cyber-range-dummy-password")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str | None) -> bool:
    try:
        return _ph.verify(hashed or _DUMMY_HASH, password) and hashed is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    return _ph.check_needs_rehash(hashed)


def create_access_token(user_id: int, session_id: int) -> str:
    s = get_settings()
    now = utcnow()
    payload = {
        "sub": str(user_id),
        "sid": session_id,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + timedelta(minutes=s.access_token_minutes),
        "typ": "access",
    }
    return jwt.encode(payload, s.jwt_secret.get_secret_value(), algorithm=s.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    s = get_settings()
    data = jwt.decode(token, s.jwt_secret.get_secret_value(), algorithms=[s.jwt_algorithm])
    if data.get("typ") != "access":
        raise jwt.InvalidTokenError("wrong token type")
    return data


def new_opaque_token() -> tuple[str, str]:
    """Return (plaintext, sha256 hex). Only the hash is stored."""
    raw = secrets.token_urlsafe(48)
    return raw, sha256(raw)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


PASSWORD_MIN = 12


def password_problems(pw: str) -> list[str]:
    problems = []
    if len(pw) < PASSWORD_MIN:
        problems.append(f"at least {PASSWORD_MIN} characters")
    if pw.lower() == pw or pw.upper() == pw:
        problems.append("both upper and lower case letters")
    if not any(c.isdigit() for c in pw):
        problems.append("a digit")
    return problems

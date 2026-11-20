"""Authentication & authorization dependencies (server-side RBAC)."""
from dataclasses import dataclass

import jwt
from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record_standalone
from app.core.database import get_db, utcnow
from app.core.errors import Forbidden, Unauthorized
from app.core.security import decode_access_token
from app.iam.models import User, UserSession


@dataclass
class Principal:
    user: User
    session_id: int
    permissions: frozenset[str]
    roles: frozenset[str]
    read_only: bool = False
    mfa_enrollment_required: bool = False

    @property
    def id(self) -> int:
        return self.user.id

    @property
    def username(self) -> str:
        return self.user.username

    def has(self, perm: str) -> bool:
        return perm in self.permissions


def effective_permissions(user: User) -> frozenset[str]:
    return frozenset(p.code for r in user.roles for p in r.permissions)


def principal_from_token(db: Session, token: str) -> Principal:
    """Resolve an access token to a principal (shared by HTTP and WebSocket authentication)."""
    try:
        claims = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise Unauthorized("Access token expired", code="token_expired") from None
    except jwt.InvalidTokenError:
        raise Unauthorized("Invalid access token") from None
    sess = db.get(UserSession, claims.get("sid"))
    if not sess or sess.revoked_at is not None or sess.expires_at < utcnow() or str(sess.user_id) != claims.get("sub"):
        raise Unauthorized("Session is no longer valid", code="session_revoked")
    user = db.execute(select(User).where(User.id == sess.user_id, User.deleted_at.is_(None))).scalar_one_or_none()
    if not user or not user.is_active:
        raise Unauthorized("Account disabled")
    return Principal(user, sess.id, effective_permissions(user), frozenset(r.code for r in user.roles), read_only=sess.read_only)


SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
# Writes allowed from a read-only session.
READ_ONLY_WRITE_PATHS = ("/auth/logout",)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise Unauthorized("Authentication required")
    p = principal_from_token(db, auth[7:].strip())
    from app.core.config import get_settings
    path = request.url.path.removeprefix(get_settings().api_prefix)
    if p.read_only and request.method not in SAFE_METHODS and not path.startswith(READ_ONLY_WRITE_PATHS):
        raise Forbidden("This session is read-only (mobile mode). Sign in again without read-only mode to make changes.", code="read_only_session")
    return p


def require(*perms: str):
    """Dependency factory: principal must hold *all* listed permissions. Denials are audited."""

    def _dep(request: Request, p: Principal = Depends(get_principal)) -> Principal:
        missing = [x for x in perms if not p.has(x)]
        if missing:
            record_standalone(
                "authz.denied", outcome="denied", actor=p.user,
                resource_type="endpoint", resource_id=f"{request.method} {request.url.path}"[:64],
                details={"missing": missing},
            )
            raise Forbidden("You do not have permission to perform this action", details={"missing": missing})
        return p

    return _dep


def authorize_owner_or(p: Principal, owner_id: int, perm: str, *, resource_type: str, resource_id) -> None:
    """Resource-level check: owner may act on own resource, others need `perm`."""
    if p.id == owner_id or p.has(perm):
        return
    record_standalone("authz.denied", outcome="denied", actor=p.user, resource_type=resource_type,
                      resource_id=resource_id, details={"missing": [perm], "reason": "not_owner"})
    raise Forbidden("You can only act on your own resources", details={"missing": [perm]})

"""IAM for the local edition: one local operator, sessions, and the permission catalog.

There is no password login, user management, SSO, MFA or self sign-up. The single operator account is created on
first start and gets a session through POST /auth/local, which only answers requests addressed to this computer
(see app.iam.router). Permissions are still checked on every endpoint (default deny) and sensitive actions are audited.
"""
import secrets
from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.config import get_settings
from app.core.database import utcnow
from app.core.errors import Conflict, NotFound, Unauthorized
from app.core.security import create_access_token, hash_password, new_opaque_token, sha256
from app.iam.catalog import OPERATOR_ROLE, PERMISSIONS, ROLES
from app.iam.deps import effective_permissions
from app.iam.models import Permission, Role, User, UserSession


def sync_catalog(db: Session) -> dict:
    """Idempotently upsert permission catalog and system roles. Never removes custom grants."""
    perms = {p.code: p for p in db.execute(select(Permission)).scalars()}
    created_p = 0
    for code, (domain, desc, sensitive) in PERMISSIONS.items():
        if code not in perms:
            perms[code] = Permission(code=code, domain=domain, description=desc, is_sensitive=sensitive)
            db.add(perms[code])
            created_p += 1
        else:
            perms[code].domain, perms[code].description, perms[code].is_sensitive = domain, desc, sensitive
    db.flush()
    created_r = 0
    for code, (name, desc, grant) in ROLES.items():
        role = db.execute(select(Role).where(Role.code == code)).scalar_one_or_none()
        if role is None:
            role = Role(code=code, name=name, description=desc, is_system=True, permissions=[perms[g] for g in grant])
            db.add(role)
            created_r += 1
        else:
            role.is_system = True
            have = {p.code for p in role.permissions}
            role.permissions.extend(perms[g] for g in grant if g not in have)
    db.flush()
    return {"permissions_created": created_p, "roles_created": created_r}


def _issue_session(db: Session, user: User, ip: str | None, ua: str | None, *, read_only: bool = False, method: str = "password",
                   mfa: bool = False) -> tuple[UserSession, str]:
    raw, digest = new_opaque_token()
    s = UserSession(user_id=user.id, refresh_token_hash=digest, ip_address=ip, user_agent=(ua or "")[:255],
                    expires_at=utcnow() + timedelta(days=get_settings().refresh_token_days), read_only=read_only, auth_method=method, mfa=mfa)
    db.add(s)
    db.flush()
    return s, raw


def start_session(db: Session, user: User, ip, ua, *, read_only: bool = False, method: str = "password", mfa: bool = False):
    user.failed_login_count, user.locked_until, user.last_login_at = 0, None, utcnow()
    sess, refresh = _issue_session(db, user, ip, ua, read_only=read_only, method=method, mfa=mfa)
    record(db, "auth.login", actor=user, resource_type="session", resource_id=sess.id,
           details={"method": method, "mfa": mfa, "read_only": read_only})
    db.commit()
    return sess, create_access_token(user.id, sess.id), refresh


def refresh(db: Session, raw_refresh: str | None, ip: str | None, ua: str | None) -> tuple[User, UserSession, str, str]:
    if not raw_refresh:
        raise Unauthorized("No refresh token")
    sess = db.execute(
        select(UserSession).where(UserSession.refresh_token_hash == sha256(raw_refresh)).with_for_update()
    ).scalar_one_or_none()
    now = utcnow()
    if not sess:
        raise Unauthorized("Invalid refresh token")
    if sess.revoked_at is not None:
        # Reuse of a rotated token: revoke every session of the user (token theft signal).
        if sess.revoke_reason == "rotated":
            n = revoke_all_sessions(db, sess.user_id, "refresh_reuse_detected")
            record(db, "auth.refresh_reuse_detected", outcome="failure", actor_label=f"user:{sess.user_id}",
                   resource_type="user", resource_id=sess.user_id, details={"sessions_revoked": n})
            db.commit()
        raise Unauthorized("Session revoked", code="session_revoked")
    if sess.expires_at < now:
        raise Unauthorized("Session expired", code="session_expired")
    user = db.get(User, sess.user_id)
    if not user or not user.is_active or user.deleted_at:
        raise Unauthorized("Account disabled")
    sess.revoked_at, sess.revoke_reason = now, "rotated"
    new_sess, new_raw = _issue_session(db, user, ip, ua, read_only=sess.read_only, method=sess.auth_method, mfa=sess.mfa)
    new_sess.expires_at = sess.expires_at  # rotation does not extend absolute lifetime
    db.commit()
    return user, new_sess, create_access_token(user.id, new_sess.id), new_raw


def revoke_session(db: Session, sess: UserSession, reason: str) -> None:
    if sess.revoked_at is None:
        sess.revoked_at, sess.revoke_reason = utcnow(), reason


def revoke_all_sessions(db: Session, user_id: int, reason: str) -> int:
    rows = db.execute(select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))).scalars().all()
    for s in rows:
        revoke_session(db, s, reason)
    return len(rows)


def _roles_by_codes(db: Session, codes: list[str]) -> list[Role]:
    codes = sorted(set(codes))
    roles = db.execute(select(Role).where(Role.code.in_(codes))).scalars().all() if codes else []
    unknown = set(codes) - {r.code for r in roles}
    if unknown:
        raise NotFound("Unknown role(s)", details={"roles": sorted(unknown)})
    return list(roles)


def create_user(db: Session, actor, *, email: str, username: str, full_name: str, password: str, role_codes: list[str],
                actor_label: str | None = None) -> User:
    email = email.lower()
    if db.execute(select(User.id).where(or_(User.email == email, User.username == username))).first():
        raise Conflict("A user with that email or username already exists")
    user = User(email=email, username=username, full_name=full_name, password_hash=hash_password(password),
                password_changed_at=utcnow(), roles=_roles_by_codes(db, role_codes))
    db.add(user)
    db.flush()
    record(db, "iam.user.create", actor=actor, actor_label=actor_label, resource_type="user", resource_id=user.id,
           details={"username": username, "roles": sorted(role_codes)})
    return user


def get_user(db: Session, user_id: int) -> User:
    user = db.execute(select(User).where(User.id == user_id, User.deleted_at.is_(None))).scalar_one_or_none()
    if not user:
        raise NotFound("User not found")
    return user


def ensure_operator(db: Session) -> User:
    """The one local account. Created on first use with an unusable random password (there is no password login)."""
    name = get_settings().local_operator
    user = db.execute(select(User).where(User.username == name, User.deleted_at.is_(None))).scalar_one_or_none()
    if user is None:
        sync_catalog(db)
        user = create_user(db, None, email=f"{name}@localhost.localdomain", username=name, full_name="Operator lokal",
                           password=secrets.token_urlsafe(48), role_codes=[OPERATOR_ROLE], actor_label="system:local")
    elif not any(r.code == OPERATOR_ROLE for r in user.roles):
        user.roles = [*user.roles, *_roles_by_codes(db, [OPERATOR_ROLE])]
    user.is_active = True
    return user


def me_payload(user: User, sess: UserSession | None = None) -> dict:
    return {"user": user, "permissions": sorted(effective_permissions(user)), "read_only": bool(sess and sess.read_only),
            "mfa_enrollment_required": False, "auth_method": sess.auth_method if sess else "local"}

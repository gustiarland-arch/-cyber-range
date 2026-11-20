"""Local session endpoints. There is no password login: the single local operator gets a session from POST /auth/local.

/auth/local only answers a request addressed to this computer: the Host header (and the Origin, when the browser sends
one) must name an allowed local host (CR_LOCAL_ALLOWED_HOSTS, default localhost / 127.0.0.1 / ::1). That blocks other
web sites (cross-origin requests and DNS rebinding) from obtaining a session. The compose file also publishes the web
port on 127.0.0.1 only, so other machines on the network cannot reach it.
"""
import hmac
from urllib.parse import urlsplit

from fastapi import APIRouter, Cookie, Depends, Request, Response
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.config import get_settings
from app.core.context import current_context
from app.core.database import get_db
from app.core.errors import Forbidden
from app.iam import service
from app.iam.deps import Principal, get_principal
from app.iam.models import User, UserSession
from app.iam.schemas import MeOut, TokenOut, UserOut

REFRESH_COOKIE = "cr_refresh"
auth_router = APIRouter(prefix="/auth", tags=["auth"])


def _set_refresh(resp: Response, raw: str) -> None:
    s = get_settings()
    resp.set_cookie(REFRESH_COOKIE, raw, httponly=True, secure=s.cookie_secure, samesite="strict",
                    max_age=s.refresh_token_days * 86400, path=f"{s.api_prefix}/auth")


def _token_out(user: User, access: str, sess: UserSession | None = None) -> TokenOut:
    p = service.me_payload(user, sess)
    return TokenOut(access_token=access, expires_in=get_settings().access_token_minutes * 60,
                    user=UserOut.model_validate(user), permissions=p["permissions"], read_only=p["read_only"])


def _hostname(value: str) -> str:
    v = value.strip().lower()
    if "://" not in v:
        v = "//" + v
    try:
        return (urlsplit(v).hostname or "").strip("[]")
    except ValueError:
        return ""


def is_local_request(request: Request) -> bool:
    allowed = {h.strip().lower().strip("[]") for h in get_settings().local_allowed_hosts.split(",") if h.strip()}
    if _hostname(request.headers.get("host", "")) not in allowed:
        return False
    origin = request.headers.get("origin")
    if origin and _hostname(origin) not in allowed:
        return False
    return request.headers.get("sec-fetch-site", "same-origin") in ("same-origin", "none")


@auth_router.post("/local", response_model=TokenOut)
def local_session(request: Request, response: Response, db: Session = Depends(get_db)):
    """Start a session for the local operator (no password: this edition has exactly one user, on this computer)."""
    ctx = current_context()
    if not is_local_request(request):
        record(db, "auth.local", outcome="denied", actor_label=f"host:{request.headers.get('host', '')[:80]}",
               details={"origin": (request.headers.get("origin") or "")[:120]})
        db.commit()
        raise Forbidden("A local session can only be opened from this computer (http://localhost)", code="not_local")
    expected = get_settings().local_access_token.get_secret_value()
    if expected and not hmac.compare_digest(request.headers.get("x-local-token", "").encode(), expected.encode()):
        record(db, "auth.local", outcome="denied", actor_label="local:token", details={"reason": "local access token missing or wrong"})
        db.commit()
        raise Forbidden("This installation requires its local access token (CR_LOCAL_ACCESS_TOKEN in .env)", code="local_token_required")
    user = service.ensure_operator(db)
    sess, access, raw = service.start_session(db, user, ctx.ip, ctx.user_agent, method="local")
    _set_refresh(response, raw)
    return _token_out(user, access, sess)


@auth_router.post("/refresh", response_model=TokenOut)
def refresh(response: Response, db: Session = Depends(get_db), cr_refresh: str | None = Cookie(default=None)):
    ctx = current_context()
    user, sess, access, raw = service.refresh(db, cr_refresh, ctx.ip, ctx.user_agent)
    _set_refresh(response, raw)
    return _token_out(user, access, sess)


@auth_router.post("/logout", status_code=204)
def logout(response: Response, p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    sess = db.get(UserSession, p.session_id)
    service.revoke_session(db, sess, "logout")
    record(db, "auth.logout", actor=p, resource_type="session", resource_id=p.session_id)
    db.commit()
    response.delete_cookie(REFRESH_COOKIE, path=f"{get_settings().api_prefix}/auth")


@auth_router.get("/me", response_model=MeOut)
def me(p: Principal = Depends(get_principal), db: Session = Depends(get_db)):
    return service.me_payload(p.user, db.get(UserSession, p.session_id))

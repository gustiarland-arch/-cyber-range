"""Per-request context (request id, client IP, user agent) via contextvars + middleware."""
import uuid
from contextvars import ContextVar
from dataclasses import dataclass

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.config import get_settings


@dataclass
class RequestContext:
    request_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None


_EMPTY = RequestContext()
_ctx: ContextVar[RequestContext | None] = ContextVar("request_ctx", default=None)


def current_context() -> RequestContext:
    return _ctx.get() or _EMPTY


def client_ip(request: Request) -> str | None:
    if get_settings().trust_proxy_headers:
        real = request.headers.get("x-real-ip")
        if real:
            return real[:45]
    return request.client.host if request.client else None


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id")
        try:
            rid = str(uuid.UUID(rid)) if rid else str(uuid.uuid4())
        except ValueError:
            rid = str(uuid.uuid4())
        request.state.request_id = rid
        token = _ctx.set(RequestContext(rid, client_ip(request), (request.headers.get("user-agent") or "")[:255]))
        structlog.contextvars.bind_contextvars(request_id=rid)
        try:
            response = await call_next(request)
        finally:
            _ctx.reset(token)
            structlog.contextvars.clear_contextvars()
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

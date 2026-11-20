"""Consistent JSON error envelope: {"error": {"code", "message", "request_id", "details"}}."""
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.i18n import translate, translate_validation, wants_indonesian
from app.core.logging import log


class AppError(Exception):
    status_code = 400
    code = "bad_request"

    def __init__(self, message: str, *, details: dict | None = None, code: str | None = None, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        self.details = details
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class NotFound(AppError):
    status_code, code = 404, "not_found"


class Conflict(AppError):
    status_code, code = 409, "conflict"


class Unauthorized(AppError):
    status_code, code = 401, "unauthorized"


class Forbidden(AppError):
    status_code, code = 403, "permission_denied"


class TooManyRequests(AppError):
    status_code, code = 429, "rate_limited"


def _id(request: Request) -> bool:
    return wants_indonesian(request.headers.get("accept-language"))


def _body(request: Request, code: str, message: str, details=None) -> dict:
    if _id(request):
        message = translate(message)
    return {"error": {"code": code, "message": message, "details": details, "request_id": getattr(request.state, "request_id", None)}}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError):
        return JSONResponse(_body(request, exc.code, exc.message, exc.details), status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        tr = translate_validation if _id(request) else (lambda m: m)
        details = [{"loc": list(e["loc"]), "msg": tr(e["msg"])} for e in exc.errors()]
        return JSONResponse(_body(request, "validation_error", "Request validation failed", details), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        return JSONResponse(_body(request, "http_error", str(exc.detail)), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.exception("unhandled_error", path=request.url.path)
        return JSONResponse(_body(request, "internal_error", "Internal server error"), status_code=500)

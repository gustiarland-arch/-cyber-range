from app import __version__
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import models  # noqa: F401  (register all mappers)
from app.api.health import router as health_router
from app.audit.router import router as audit_router
from app.core.config import get_settings
from app.core.context import RequestContextMiddleware
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging
from app.dashboard.router import router as dashboard_router
from app.governance.router import router as settings_router
from app.iam.router import auth_router
from app.network.router import router as network_router
from app.cyber_range.router import router as labs_router
from app.cyber_range.kit_router import router as kit_router
from app.blueteam.router import router as soc_router
from app.redteam.router import router as redteam_router
from app.intel.router import router as intel_router
from app.vuln.router import router as vuln_router
from app.malware.router import router as malware_router
from app.forensics.router import router as forensics_router
from app.training.router import router as training_router
from app.reports.router import backup_router, router as reports_router
from app.terminal.router import router as terminal_router
from app.soar.router import router as soar_router


def create_app() -> FastAPI:
    s = get_settings()
    configure_logging(s.debug)
    docs = s.environment != "production"  # interactive API docs are not served in production
    app = FastAPI(title="CYBER RANGE API", version=__version__, docs_url=f"{s.api_prefix}/docs" if docs else None,
                  openapi_url=f"{s.api_prefix}/openapi.json" if docs else None, redoc_url=None)
    app.add_middleware(CORSMiddleware, allow_origins=s.cors_origins, allow_credentials=True,
                       allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type", "X-Request-ID"])
    app.add_middleware(RequestContextMiddleware)
    install_error_handlers(app)
    api = APIRouter(prefix=s.api_prefix)
    for r in (health_router, auth_router, audit_router, settings_router, dashboard_router, network_router, labs_router, kit_router, soc_router, redteam_router, intel_router, vuln_router, malware_router, forensics_router, training_router, reports_router, backup_router, terminal_router, soar_router):
        api.include_router(r)
    app.include_router(api)
    return app


app = create_app()

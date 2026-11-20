"""Liveness, readiness and detailed system health (incl. host capability checks)."""
import os
import platform
import shutil
import subprocess
import time

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import engine, get_db
from app.core.redis_client import get_redis
from app.iam.deps import Principal, require

router = APIRouter(tags=["health"])
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _timed(fn):
    t = time.perf_counter()
    try:
        data = fn()
        return {"status": "up", "latency_ms": round((time.perf_counter() - t) * 1000, 1), **(data or {})}
    except Exception as e:  # noqa: BLE001
        return {"status": "down", "latency_ms": round((time.perf_counter() - t) * 1000, 1), "error": type(e).__name__}


def _alembic_head() -> str | None:
    cfg = Config(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "alembic"))
    return ScriptDirectory.from_config(cfg).get_current_head()


def check_mysql() -> dict:
    def f():
        with engine.connect() as c:
            version = c.execute(text("SELECT VERSION()")).scalar_one()
            cs = c.execute(text("SELECT @@character_set_database")).scalar_one()
            engine_default = c.execute(text("SELECT @@default_storage_engine")).scalar_one()
            try:
                current = c.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
            except Exception:  # noqa: BLE001
                current = None
        head = _alembic_head()
        return {"version": version, "charset": cs, "storage_engine": engine_default,
                "migration_current": current, "migration_head": head, "migrations_up_to_date": current == head,
                "version_ok": version.startswith("8.4")}
    return _timed(f)


def check_redis() -> dict:
    return _timed(lambda: {"version": get_redis().info("server").get("redis_version")} if get_redis().ping() else None)


def check_workers() -> dict:
    def f():
        from app.core.celery_app import celery_app
        replies = celery_app.control.ping(timeout=1.0) or []
        if not replies:
            raise RuntimeError("no workers")
        return {"workers": [next(iter(r)) for r in replies]}
    return _timed(f)


def host_capabilities() -> dict:
    gpu = None
    smi = shutil.which("nvidia-smi")
    if smi:
        try:
            gpu = subprocess.run([smi, "--query-gpu=name", "--format=csv,noheader"], capture_output=True, text=True, timeout=3).stdout.strip() or None  # noqa: S603 (fixed args)
        except Exception:  # noqa: BLE001
            gpu = None
    try:
        mem_gb = round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1024**3, 1)
    except (ValueError, OSError, AttributeError):
        mem_gb = None
    cpuinfo = ""
    try:
        with open("/proc/cpuinfo") as fh:
            cpuinfo = fh.read()
    except OSError:
        pass
    return {
        "note": "Detected from the API process; inside a container this reflects the container view.",
        "os": f"{platform.system()} {platform.release()}", "python": platform.python_version(), "arch": platform.machine(),
        "cpu_count": os.cpu_count(), "memory_gb": mem_gb,
        "kvm_device": os.path.exists("/dev/kvm"), "cpu_virt_flags": (" vmx" in cpuinfo or " svm" in cpuinfo),
        "docker_socket": os.path.exists("/var/run/docker.sock"), "gpu": gpu,
        "vm_mode": "kvm" if os.path.exists("/dev/kvm") else "container-only (KVM unavailable; use remote Linux lab host for VMs)",
    }


@router.get("/health/live")
def live():
    return {"status": "ok"}


@router.get("/health/ready")
def ready():
    mysql, redis_ = check_mysql(), check_redis()
    ok = mysql["status"] == "up" and mysql.get("migrations_up_to_date", False)
    body = {"status": "ready" if ok else "not_ready", "mysql": mysql["status"], "migrations_up_to_date": mysql.get("migrations_up_to_date"),
            "redis": redis_["status"]}
    return JSONResponse(body, status_code=200 if ok else 503)


def system_health_payload() -> dict:
    comps = {"mysql": check_mysql(), "redis": check_redis(), "workers": check_workers()}
    required = ("mysql",)
    overall = "down" if any(comps[k]["status"] != "up" for k in required) else (
        "degraded" if any(comps[k]["status"] != "up" for k in ("redis", "workers")) else "healthy")
    return {"overall": overall, "components": comps, "host": host_capabilities(), "environment": get_settings().environment}


@router.get("/system/health")
def system_health(_p: Principal = Depends(require("system.health.view")), _db: Session = Depends(get_db)):
    return system_health_payload()

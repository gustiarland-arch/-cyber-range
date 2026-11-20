"""Report generation. Access is checked when a report is requested (the builder enforces the domain permission and
resource scope) and again on download, so a report never outlives the requester's access to its data."""
import hashlib
import io
import os

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import SessionLocal, utcnow
from app.core.errors import AppError, Forbidden, NotFound
from app.core.logging import log
from app.core.storage import get_storage
from app.iam.deps import Principal, effective_permissions
from app.iam.models import User
from app.reports import builders, render
from app.reports.models import FORMATS, KINDS, BackupRun, Report

# domain permission needed to read a report's data (checked again on download)
DATA_PERM = {"incident": "incident.view", "assessment": "redteam.assessment.view", "lab_run": "lab.view", "vulnerability": "vuln.view",
             "evidence": "evidence.view", "training": "training.manage"}


def principal_for(db: Session, user_id: int) -> Principal:
    u = db.get(User, user_id)
    perms = effective_permissions(u) if u and u.is_active and not u.deleted_at else frozenset()
    return Principal(user=u, session_id=0, permissions=perms, roles=frozenset(r.code for r in u.roles) if u else frozenset())


def request(db: Session, p, *, kind: str, fmt: str, params: dict) -> Report:
    if kind not in KINDS or fmt not in FORMATS:
        raise AppError("Unknown report kind or format", code="validation_error", status_code=422)
    clean = {k: v for k, v in (params or {}).items() if k in ("incident_id", "assessment_id", "lab_id", "case_id", "status", "days") and v not in (None, "")}
    doc = builders.BUILDERS[kind](db, p, clean)  # validates access and existence now, before queueing
    r = Report(kind=kind, fmt=fmt, title=doc["title"][:255], params=clean, status="queued", created_by=p.id, sources=doc["sources"])
    db.add(r)
    db.flush()
    record(db, "report.request", actor=p, resource_type="report", resource_id=r.id, details={"kind": kind, "format": fmt, "params": clean})
    db.commit()
    _schedule(r.id)
    db.refresh(r)
    return r


def _schedule(report_id: int):
    if os.environ.get("CR_ANALYSIS_EXECUTION", "celery") == "inline":
        generate(report_id)
    else:
        from app.core.celery_app import celery_app
        celery_app.send_task("app.reports.tasks.generate_report", args=[report_id], queue="reports")


def generate(report_id: int) -> None:
    """Build and render with the requester's CURRENT permissions; store the file; record hash and sources."""
    with SessionLocal() as db:
        r = db.get(Report, report_id)
        if not r or r.status not in ("queued", "failed"):
            return
        r.status = "running"
        db.commit()
        try:
            p = principal_for(db, r.created_by)
            doc = builders.BUILDERS[r.kind](db, p, r.params)
            now = utcnow()
            meta = {"generated_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"), "generated_by": p.user.username if p.user else "?", "report_id": r.id}
            data = render.to_pdf(doc, meta) if r.fmt == "pdf" else render.to_csv(doc, meta)
            key = f"reports/{r.id}/report-{r.id}.{r.fmt}"
            get_storage().put(key, io.BytesIO(data), len(data))
            r.object_key, r.size, r.sha256 = key, len(data), hashlib.sha256(data).hexdigest()
            r.sources, r.row_count, r.title = doc["sources"], len(doc["primary"]["rows"]), doc["title"][:255]
            r.status, r.finished_at, r.error = "completed", now, None
            record(db, "report.generated", actor_label="system:reports", resource_type="report", resource_id=r.id,
                   details={"sha256": r.sha256, "size": r.size, "rows": r.row_count})
        except Exception as e:  # report failure must be visible, not silent
            db.rollback()
            r = db.get(Report, report_id)
            r.status, r.finished_at, r.error = "failed", utcnow(), (getattr(e, "message", None) or str(e))[:2000]
            log.warning("report_failed", report_id=report_id, error=str(e))
        db.commit()


def visible(db: Session, p, report_id: int) -> Report:
    r = db.get(Report, report_id)
    if not r or not (r.created_by == p.id or p.has("reports.manage")):
        raise NotFound("Report not found")
    return r


def open_download(db: Session, p, r: Report):
    if r.status != "completed" or not r.object_key:
        raise AppError("The report is not ready", code="not_ready", status_code=409)
    perm = DATA_PERM[r.kind]
    if not p.has(perm):
        raise Forbidden("You no longer have access to this report's data", details={"missing": [perm]})
    record(db, "report.download", actor=p, resource_type="report", resource_id=r.id, details={"sha256": r.sha256})
    db.commit()
    return get_storage().open_iter(r.object_key)


def delete(db: Session, p, r: Report) -> None:
    if r.object_key:
        get_storage().delete(r.object_key)
    record(db, "report.delete", actor=p, resource_type="report", resource_id=r.id, details={"kind": r.kind})
    db.delete(r)
    db.commit()


def counts(db: Session) -> dict:
    last = db.execute(select(BackupRun).where(BackupRun.kind == "backup").order_by(BackupRun.finished_at.desc()).limit(1)).scalar_one_or_none()
    return {"reports_total": db.execute(select(func.count()).select_from(Report)).scalar_one(),
            "last_backup_at": last.finished_at if last else None, "last_backup_status": last.status if last else None}

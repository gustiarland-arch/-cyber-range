"""Reports API and backup status."""
import os

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.iam.deps import Principal, require
from app.iam.models import User
from app.reports import render
from app.reports import service as svc
from app.reports.models import FORMATS, KINDS, BackupRun, Report

router = APIRouter(prefix="/reports", tags=["reports"])
VIEW = Depends(require("reports.view"))
GENERATE = Depends(require("reports.generate"))

KIND_INFO = {
    "incident": {"label": "Incident", "param": "incident_id", "perm": "incident.view"},
    "assessment": {"label": "Red team assessment", "param": "assessment_id", "perm": "redteam.assessment.view"},
    "lab_run": {"label": "Lab run", "param": "lab_id", "perm": "lab.view"},
    "vulnerability": {"label": "Vulnerabilities", "param": None, "perm": "vuln.view"},
    "evidence": {"label": "Evidence / case", "param": "case_id", "perm": "evidence.view"},
    "training": {"label": "Training", "param": None, "perm": "training.manage"},
}


def _out(r: Report, users: dict):
    return {"id": r.id, "kind": r.kind, "format": r.fmt, "title": r.title, "params": r.params, "status": r.status, "created_by": users.get(r.created_by),
            "created_at": r.created_at, "finished_at": r.finished_at, "sources": r.sources, "row_count": r.row_count, "sha256": r.sha256, "size": r.size,
            "error": r.error}


@router.get("/meta")
def meta(p: Principal = VIEW):
    return {"kinds": [{"kind": k, **v, "allowed": p.has(v["perm"])} for k, v in KIND_INFO.items()], "formats": FORMATS,
            "pdf_unicode": os.path.exists(f"{render.FONT_DIR}/DejaVuSans.ttf"), "can_generate": p.has("reports.generate"), "can_manage": p.has("reports.manage"),
            "policy": "Reports are built only from stored records, state their data sources and generation time, and are re-checked against "
                      "your current permissions when downloaded."}


@router.get("")
def list_reports(kind: str = Query("", max_length=16), mine: bool = False, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
                 db: Session = Depends(get_db), p: Principal = VIEW):
    q = select(Report)
    if not p.has("reports.manage") or mine:
        q = q.where(Report.created_by == p.id)
    if kind:
        q = q.where(Report.kind == kind)
    total = db.execute(select(func.count()).select_from(q.subquery())).scalar_one()
    rows = db.execute(q.order_by(Report.id.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    users = dict(db.execute(select(User.id, User.username).where(User.id.in_({r.created_by for r in rows} or {-1}))).all())
    return {"total": total, "page": page, "items": [_out(r, users) for r in rows]}


class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(pattern="^(" + "|".join(KINDS) + ")$")
    format: str = Field("pdf", pattern="^(pdf|csv)$")
    params: dict = Field(default_factory=dict)


@router.post("", status_code=202)
def create(body: ReportIn, db: Session = Depends(get_db), p: Principal = GENERATE):
    r = svc.request(db, p, kind=body.kind, fmt=body.format, params=body.params)
    return _out(r, {p.id: p.username})


@router.get("/{rid}")
def get(rid: int, db: Session = Depends(get_db), p: Principal = VIEW):
    r = svc.visible(db, p, rid)
    return _out(r, dict(db.execute(select(User.id, User.username).where(User.id == r.created_by)).all()))


@router.get("/{rid}/download")
def download(rid: int, db: Session = Depends(get_db), p: Principal = VIEW):
    r = svc.visible(db, p, rid)
    it = svc.open_download(db, p, r)
    media = "application/pdf" if r.fmt == "pdf" else "text/csv; charset=utf-8"
    return StreamingResponse(it, media_type=media, headers={"Content-Disposition": f'attachment; filename="cyber-range-{r.kind}-{r.id}.{r.fmt}"',
                                                            "X-Report-SHA256": r.sha256 or "", "X-Content-Type-Options": "nosniff"})


@router.delete("/{rid}", status_code=204)
def delete(rid: int, db: Session = Depends(get_db), p: Principal = GENERATE):
    svc.delete(db, p, svc.visible(db, p, rid))


# ------------------------------------------------------------------ backups (status only; backups run from the host)
backup_router = APIRouter(prefix="/system/backups", tags=["system"])


@backup_router.get("")
def backups(db: Session = Depends(get_db), _p: Principal = Depends(require("system.health.view"))):
    rows = db.execute(select(BackupRun).order_by(BackupRun.finished_at.desc()).limit(50)).scalars().all()
    return [{"id": b.id, "label": b.label, "kind": b.kind, "status": b.status, "started_at": b.started_at, "finished_at": b.finished_at,
             "components": b.components, "total_size": b.total_size, "schema_revision": b.schema_revision, "host": b.host, "note": b.note} for b in rows]

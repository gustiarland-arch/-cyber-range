import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.audit.service import record, verify_chain
from app.core.database import get_db
from app.iam.deps import Principal, require
from app.iam.schemas import Page

router = APIRouter(prefix="/audit-logs", tags=["audit"])


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    occurred_at: datetime
    actor_user_id: int | None
    actor_label: str
    action: str
    outcome: str
    resource_type: str | None
    resource_id: str | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    details: dict | None
    entry_hash: str


def _filtered(action, actor, outcome, resource_type, since, until):
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if actor:
        stmt = stmt.where(AuditLog.actor_label == actor)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if since:
        stmt = stmt.where(AuditLog.occurred_at >= since.replace(tzinfo=None))
    if until:
        stmt = stmt.where(AuditLog.occurred_at <= until.replace(tzinfo=None))
    return stmt


@router.get("", response_model=Page[AuditOut])
def list_logs(db: Session = Depends(get_db), _p: Principal = Depends(require("audit.view")),
              action: str | None = Query(None, max_length=96), actor: str | None = Query(None, max_length=255),
              outcome: str | None = Query(None, pattern="^(success|failure|denied)$"),
              resource_type: str | None = Query(None, max_length=64),
              since: datetime | None = None, until: datetime | None = None,
              page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500)):
    stmt = _filtered(action, actor, outcome, resource_type, since, until)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    items = db.execute(stmt.order_by(AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return Page[AuditOut](items=[AuditOut.model_validate(i) for i in items], total=total, page=page, page_size=page_size)


@router.get("/verify")
def verify(db: Session = Depends(get_db), p: Principal = Depends(require("audit.view"))):
    result = verify_chain(db)
    record(db, "audit.verify", actor=p, outcome="success" if result["valid"] else "failure", details=result)
    db.commit()
    return result


@router.get("/export.csv")
def export(db: Session = Depends(get_db), p: Principal = Depends(require("audit.view")),
           action: str | None = None, actor: str | None = None, outcome: str | None = Query(None, pattern="^(success|failure|denied)$"),
           resource_type: str | None = None, since: datetime | None = None, until: datetime | None = None):
    rows = db.execute(_filtered(action, actor, outcome, resource_type, since, until).order_by(AuditLog.id).limit(50000)).scalars().all()
    record(db, "audit.export", actor=p, details={"rows": len(rows), "filters": {"action": action, "actor": actor, "outcome": outcome}})
    db.commit()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "occurred_at_utc", "actor", "action", "outcome", "resource_type", "resource_id", "ip", "request_id", "entry_hash"])
    for r in rows:
        w.writerow([r.id, r.occurred_at.isoformat(), r.actor_label, r.action, r.outcome, r.resource_type, r.resource_id,
                    r.ip_address, r.request_id, r.entry_hash])
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})

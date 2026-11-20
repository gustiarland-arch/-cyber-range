from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam import service as soc
from app.blueteam.models import Alert
from app.core.database import get_db
from app.core.errors import AppError, Conflict, NotFound
from app.iam.deps import Principal, require
from app.iam.models import User
from app.soar import service as svc
from app.soar.models import RUN_STATUSES, Playbook, PlaybookRun

router = APIRouter(prefix="/soar", tags=["soar"])
VIEW = Depends(require("incident.view"))
RESPOND = Depends(require("incident.respond"))
MANAGE = Depends(require("soar.manage"))


def _pb_out(pb: Playbook) -> dict:
    return {"id": pb.id, "code": pb.code, "name": pb.name, "description": pb.description, "trigger": pb.trigger,
            "steps": [{**s, "approval": svc.ACTIONS[s["action"]]["approval"], "label": svc.ACTIONS[s["action"]]["label"]} for s in pb.steps],
            "is_enabled": pb.is_enabled, "builtin": pb.builtin, "runs_total": pb.runs_total, "updated_at": pb.updated_at}


def _run_out(db: Session, r: PlaybookRun, detail=False) -> dict:
    pb = db.get(Playbook, r.playbook_id)
    a = db.get(Alert, r.alert_id)
    req = db.get(User, r.requested_by) if r.requested_by else None
    out = {"id": r.id, "playbook": {"id": pb.id, "code": pb.code, "name": pb.name}, "alert": {"id": a.id, "title": a.title, "severity": a.severity, "status": a.status,
           "incident_id": a.incident_id}, "status": r.status, "trigger": r.trigger, "current_step": r.current_step, "steps_total": len(r.steps),
           "is_demo": r.is_demo, "requested_by": req.username if req else None, "created_at": r.created_at, "finished_at": r.finished_at, "error": r.error}
    if r.status == "awaiting_approval":
        s = r.steps[r.current_step]
        out["waiting"] = {"index": r.current_step, "action": s["action"], "label": svc.ACTIONS[s["action"]]["label"]}
    if detail:
        out["steps"] = [{**s, "label": svc.ACTIONS[s["action"]]["label"]} for s in r.steps]
        out["facts"] = r.facts
    return out


@router.get("/meta")
def meta(_p: Principal = VIEW):
    return {"actions": svc.catalogue(), "statuses": list(RUN_STATUSES), "max_steps": svc.MAX_STEPS}


@router.get("/playbooks")
def list_playbooks(db: Session = Depends(get_db), _p: Principal = VIEW):
    return {"items": [_pb_out(pb) for pb in db.execute(select(Playbook).order_by(Playbook.builtin.desc(), Playbook.code)).scalars()]}


class PlaybookIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=3, max_length=40, pattern=r"^[A-Z0-9][A-Z0-9_-]+$")
    name: str = Field(min_length=3, max_length=160)
    description: str = Field("", max_length=4000)
    trigger: dict
    steps: list[dict]
    is_enabled: bool = True


class PlaybookPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=3, max_length=160)
    description: str | None = Field(None, max_length=4000)
    trigger: dict | None = None
    steps: list[dict] | None = None
    is_enabled: bool | None = None


@router.post("/playbooks", status_code=201)
def create_playbook(body: PlaybookIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    trig, steps = svc.validate_playbook(body.trigger, body.steps)
    if db.execute(select(Playbook).where(Playbook.code == body.code)).scalar_one_or_none():
        raise Conflict("A playbook with this code already exists")
    pb = Playbook(code=body.code, name=body.name, description=body.description, trigger=trig, steps=steps, is_enabled=body.is_enabled, created_by=p.id)
    db.add(pb)
    db.flush()
    record(db, "soar.playbook.create", actor=p, resource_type="soar_playbook", resource_id=pb.id, details={"code": pb.code, "trigger": trig, "steps": [s["action"] for s in steps]})
    db.commit()
    return _pb_out(pb)


@router.patch("/playbooks/{pb_id}")
def update_playbook(pb_id: int, body: PlaybookPatch, db: Session = Depends(get_db), p: Principal = MANAGE):
    pb = db.get(Playbook, pb_id)
    if not pb:
        raise NotFound("Playbook not found")
    data = body.model_dump(exclude_none=True)
    if pb.builtin and set(data) - {"is_enabled", "trigger"}:
        raise AppError("Built-in playbooks can only be enabled/disabled or re-triggered; copy it to change steps", code="builtin_readonly", status_code=409)
    if "trigger" in data or "steps" in data:
        data["trigger"], data["steps"] = svc.validate_playbook(data.get("trigger", pb.trigger), data.get("steps", pb.steps))
    for k, v in data.items():
        setattr(pb, k, v)
    record(db, "soar.playbook.update", actor=p, resource_type="soar_playbook", resource_id=pb.id, details={k: (v if k != "steps" else [s["action"] for s in v]) for k, v in data.items()})
    db.commit()
    return _pb_out(pb)


@router.delete("/playbooks/{pb_id}", status_code=204)
def delete_playbook(pb_id: int, db: Session = Depends(get_db), p: Principal = MANAGE):
    pb = db.get(Playbook, pb_id)
    if not pb:
        raise NotFound("Playbook not found")
    if pb.builtin:
        raise AppError("Built-in playbooks cannot be deleted; disable it instead", code="builtin_readonly", status_code=409)
    if db.execute(select(func.count()).select_from(PlaybookRun).where(PlaybookRun.playbook_id == pb.id)).scalar_one():
        raise Conflict("This playbook has runs; disable it instead so the history stays intact")
    record(db, "soar.playbook.delete", actor=p, resource_type="soar_playbook", resource_id=pb.id, details={"code": pb.code})
    db.delete(pb)
    db.commit()


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    playbook_id: int
    alert_id: int


@router.post("/runs", status_code=201)
def start_run(body: RunIn, db: Session = Depends(get_db), p: Principal = RESPOND):
    pb = db.get(Playbook, body.playbook_id)
    if not pb:
        raise NotFound("Playbook not found")
    alert = soc.get_alert(db, body.alert_id, lock=True)
    run = svc.start(db, pb, alert, p, trigger="manual")
    db.commit()
    return _run_out(db, run, detail=True)


@router.get("/runs")
def list_runs(db: Session = Depends(get_db), _p: Principal = VIEW, status: str = Query("all"), alert_id: int | None = None,
              limit: int = Query(100, ge=1, le=500)):
    q = select(PlaybookRun).order_by(PlaybookRun.id.desc()).limit(limit)
    if status == "open":
        q = q.where(PlaybookRun.status.in_(("running", "awaiting_approval")))
    elif status != "all":
        if status not in RUN_STATUSES:
            raise AppError("Unknown status", code="validation_error", status_code=422)
        q = q.where(PlaybookRun.status == status)
    if alert_id:
        q = q.where(PlaybookRun.alert_id == alert_id)
    runs = db.execute(q).scalars().all()
    pending = db.execute(select(func.count()).select_from(PlaybookRun).where(PlaybookRun.status == "awaiting_approval")).scalar_one()
    return {"items": [_run_out(db, r) for r in runs], "awaiting_approval": pending}


@router.get("/runs/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    return _run_out(db, svc.get_run(db, run_id), detail=True)


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    step: int = Field(ge=0)
    approve: bool
    note: str = Field("", max_length=2000)


@router.post("/runs/{run_id}/decision")
def decide(run_id: int, body: Decision, db: Session = Depends(get_db), p: Principal = RESPOND):
    run = svc.get_run(db, run_id, lock=True)
    if not body.approve and not body.note.strip():
        raise AppError("A reason is required to reject a step", code="validation_error", status_code=422)
    svc.decide(db, run, p, body.step, body.approve, body.note.strip())
    db.commit()
    return _run_out(db, run, detail=True)


@router.post("/runs/{run_id}/cancel")
def cancel(run_id: int, db: Session = Depends(get_db), p: Principal = RESPOND):
    run = svc.cancel(db, svc.get_run(db, run_id, lock=True), p)
    db.commit()
    return _run_out(db, run, detail=True)

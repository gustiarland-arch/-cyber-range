from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import get_db
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.cyber_range.models import Lab, LabInstance
from app.iam.deps import Principal, require
from app.iam.models import User
from app.redteam import purple
from app.redteam import service as svc
from app.redteam.actions import ACTIONS, SENSITIVE_DEFAULT, validate_steps
from app.redteam.models import Assessment, AssessmentEvent, Finding, Scenario

router = APIRouter(prefix="/redteam", tags=["red team"])
VIEW = Depends(require("redteam.assessment.view"))
REQUEST = Depends(require("redteam.assessment.request"))
APPROVE = Depends(require("redteam.assessment.approve"))
EXECUTE = Depends(require("redteam.assessment.execute"))


def _users(db, ids):
    ids = {i for i in ids if i}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all()) if ids else {}


@router.get("/actions")
def actions(_p: Principal = VIEW):
    return {"actions": [{"id": k, **v} for k, v in ACTIONS.items()], "sensitive_default_ports": SENSITIVE_DEFAULT,
            "policy": "Only these non-destructive actions exist. No exploitation, credential attacks, persistence, evasion or payloads."}


# ------------------------------------------------------------------ scenarios
class ScenarioIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    code: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,63}$")
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(default="", max_length=4000)
    objective: str = Field(default="", max_length=4000)
    difficulty: str = Field(default="basic", pattern="^(basic|intermediate|advanced)$")
    steps: list


def _sc_out(s: Scenario, users=None):
    return {"id": s.id, "code": s.code, "name": s.name, "description": s.description, "objective": s.objective, "difficulty": s.difficulty,
            "steps": [{**st, "mitre": ACTIONS[st["action"]]["mitre"], "tactic": ACTIONS[st["action"]]["tactic"]} for st in s.steps],
            "is_builtin": s.is_builtin, "created_by": (users or {}).get(s.created_by), "created_by_id": s.created_by, "updated_at": s.updated_at}


@router.get("/scenarios")
def list_scenarios(db: Session = Depends(get_db), _p: Principal = VIEW):
    rows = db.execute(select(Scenario).where(Scenario.is_archived.is_(False)).order_by(Scenario.is_builtin.desc(), Scenario.code)).scalars().all()
    users = _users(db, [r.created_by for r in rows])
    return [_sc_out(r, users) for r in rows]


def _check(body: ScenarioIn):
    errs = validate_steps(body.steps)
    if errs:
        raise AppError("Invalid scenario", code="invalid_scenario", status_code=422, details=errs)
    return [{"action": s["action"], "title": str(s.get("title") or ACTIONS[s["action"]]["title"])[:128], "params": s.get("params") or {}} for s in body.steps]


@router.post("/scenarios", status_code=201)
def create_scenario(body: ScenarioIn, db: Session = Depends(get_db), p: Principal = REQUEST):
    steps = _check(body)
    if db.execute(select(Scenario.id).where(Scenario.code == body.code)).first():
        raise Conflict("A scenario with this code exists")
    s = Scenario(**body.model_dump(exclude={"steps"}), steps=steps, created_by=p.id)
    db.add(s)
    db.flush()
    record(db, "redteam.scenario.create", actor=p, resource_type="scenario", resource_id=s.id, details={"code": s.code, "actions": [x["action"] for x in steps]})
    db.commit()
    return _sc_out(s)


@router.put("/scenarios/{sid}")
def update_scenario(sid: int, body: ScenarioIn, db: Session = Depends(get_db), p: Principal = REQUEST):
    s = db.get(Scenario, sid)
    if not s or s.is_archived:
        raise NotFound("Scenario not found")
    if s.is_builtin or (s.created_by != p.id and not p.has("redteam.assessment.approve")):
        raise Forbidden("Built-in scenarios are read-only; others can be edited by their author")
    steps = _check(body)
    s.name, s.description, s.objective, s.difficulty, s.steps = body.name, body.description, body.objective, body.difficulty, steps
    record(db, "redteam.scenario.update", actor=p, resource_type="scenario", resource_id=s.id, details={"code": s.code})
    db.commit()
    return _sc_out(s)


@router.delete("/scenarios/{sid}", status_code=204)
def archive_scenario(sid: int, db: Session = Depends(get_db), p: Principal = REQUEST):
    s = db.get(Scenario, sid)
    if not s or s.is_archived:
        raise NotFound("Scenario not found")
    if s.is_builtin or (s.created_by != p.id and not p.has("redteam.assessment.approve")):
        raise Forbidden("Built-in scenarios cannot be archived")
    s.is_archived = True  # kept: assessments reference it
    record(db, "redteam.scenario.archive", actor=p, resource_type="scenario", resource_id=s.id)
    db.commit()


# ------------------------------------------------------------------ targets
@router.get("/labs")
def assessable_labs(db: Session = Depends(get_db), p: Principal = REQUEST):
    q = select(Lab).where(Lab.deleted_at.is_(None))
    if not p.has("lab.manage"):
        q = q.where(Lab.owner_id == p.id)
    out = []
    for lab in db.execute(q).scalars():
        inst = db.execute(select(LabInstance).where(LabInstance.lab_id == lab.id, LabInstance.status == "running")).scalar_one_or_none()
        if not inst:
            continue
        plan = {c["node_key"]: c for c in lab.plan["containers"]}
        out.append({"id": lab.id, "name": lab.name, "runtime_id": inst.runtime_id, "networks": [{"name": n["name"], "cidr": n["cidr"]} for n in lab.plan["networks"]],
                    "nodes": [{"node_key": c.node_key, "label": plan.get(c.node_key, {}).get("label", c.node_key), "type": plan.get(c.node_key, {}).get("type"),
                               "addresses": c.addresses or {}, "status": c.status} for c in inst.containers]})
    return out


# ------------------------------------------------------------------ assessments
class AssessmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=3, max_length=255)
    justification: str = Field(min_length=10, max_length=4000)
    scenario_id: int
    lab_id: int
    attacker_node: str = Field(max_length=64)
    target_nodes: list[str] = Field(min_length=1, max_length=50)
    window_start: datetime
    window_end: datetime


def _a_out(db, a: Assessment, users, detail=False):
    out = {"id": a.id, "title": a.title, "status": a.status, "scenario": {"code": a.scenario["code"], "name": a.scenario["name"]},
           "lab_id": a.lab_id, "lab": a.scope.get("lab_name"), "runtime_id": a.runtime_id, "attacker_node": a.attacker_node, "attacker_ip": a.attacker_ip,
           "targets": a.scope["targets"], "window_start": a.window_start, "window_end": a.window_end,
           "requested_by": users.get(a.requested_by), "requested_by_id": a.requested_by, "decided_by": users.get(a.decided_by),
           "decision_comment": a.decision_comment, "decided_at": a.decided_at, "started_at": a.started_at, "finished_at": a.finished_at,
           "current_step": a.current_step, "abort_requested": a.abort_requested, "error": a.error, "created_at": a.created_at,
           "finding_count": db.execute(select(func.count()).select_from(Finding).where(Finding.assessment_id == a.id)).scalar_one()}
    if detail:
        out["justification"] = a.justification
        out["scope"] = a.scope
        out["steps"] = [{**s, "mitre": ACTIONS[s["action"]]["mitre"], "tactic": ACTIONS[s["action"]]["tactic"]} for s in a.scenario["steps"]]
        out["objective"] = a.scenario.get("objective")
        evs = db.execute(select(AssessmentEvent).where(AssessmentEvent.assessment_id == a.id).order_by(AssessmentEvent.id)).scalars().all()
        eu = _users(db, [e.actor_id for e in evs])
        out["timeline"] = [{"id": e.id, "at": e.at, "kind": e.kind, "step": e.step_index, "message": e.message, "actor": eu.get(e.actor_id), "data": e.data} for e in evs]
        out["findings"] = [{"id": f.id, "step": f.step_index, "kind": f.kind, "severity": f.severity, "title": f.title, "target_ip": f.target_ip,
                            "port": f.port, "detail": f.detail, "at": f.at}
                           for f in db.execute(select(Finding).where(Finding.assessment_id == a.id).order_by(Finding.severity.desc(), Finding.id)).scalars()]
        out["detections"] = svc.detections(db, a)
        out["purple"] = purple.assessment_steps(db, a)
    return out


def _get(db, aid, lock=False) -> Assessment:
    q = select(Assessment).where(Assessment.id == aid)
    a = db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
    if not a:
        raise NotFound("Assessment not found")
    return a


@router.get("/assessments")
def list_assessments(db: Session = Depends(get_db), p: Principal = VIEW, status: str = Query("all"), mine: bool = False):
    q = select(Assessment)
    if status == "awaiting_me":
        q = q.where(Assessment.status == "pending_approval", Assessment.requested_by != p.id)
    elif status == "active":
        q = q.where(Assessment.status.in_(("pending_approval", "approved", "queued", "running")))
    elif status != "all":
        q = q.where(Assessment.status == status)
    if mine:
        q = q.where(Assessment.requested_by == p.id)
    rows = db.execute(q.order_by(Assessment.id.desc()).limit(300)).scalars().all()
    for a in rows:
        svc.refresh_expiry(db, a)
    users = _users(db, [x for a in rows for x in (a.requested_by, a.decided_by)])
    return [_a_out(db, a, users) for a in rows]


@router.post("/assessments", status_code=201)
def request_assessment(body: AssessmentIn, db: Session = Depends(get_db), p: Principal = REQUEST):
    a = svc.request(db, p, **body.model_dump())
    db.commit()
    return _a_out(db, a, _users(db, [a.requested_by]), detail=True)


@router.get("/assessments/{aid}")
def get_assessment(aid: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    a = _get(db, aid)
    svc.refresh_expiry(db, a)
    return _a_out(db, a, _users(db, [a.requested_by, a.decided_by]), detail=True)


class Decision(BaseModel):
    approve: bool
    comment: str = Field(min_length=3, max_length=2000)


@router.post("/assessments/{aid}/decision")
def decide(aid: int, body: Decision, db: Session = Depends(get_db), p: Principal = APPROVE):
    a = _get(db, aid, lock=True)
    svc.decide(db, p, a, body.approve, body.comment)
    db.commit()
    return get_assessment(aid, db, p)


@router.post("/assessments/{aid}/execute")
def execute(aid: int, db: Session = Depends(get_db), p: Principal = EXECUTE):
    a = _get(db, aid, lock=True)
    svc.start(db, p, a)
    db.expire_all()
    return get_assessment(aid, db, p)


@router.post("/assessments/{aid}/abort")
def abort(aid: int, db: Session = Depends(get_db), p: Principal = VIEW):
    a = _get(db, aid, lock=True)
    if not (a.requested_by == p.id or p.has("redteam.assessment.approve") or p.has("lab.killswitch")):
        raise Forbidden("Only the requester, an approver or a kill-switch holder can stop an assessment")
    svc.abort(db, p, a)
    db.commit()
    return get_assessment(aid, db, p)


@router.get("/assessments/{aid}/report")
def report(aid: int, db: Session = Depends(get_db), p: Principal = VIEW):
    a = _get(db, aid)
    if a.status not in ("completed", "aborted", "failed"):
        raise Conflict("A report is available once the assessment has run", code="invalid_state")
    md = svc.report_markdown(db, a, _users(db, [a.requested_by, a.decided_by]))
    record(db, "redteam.report.download", actor=p, resource_type="assessment", resource_id=a.id)
    db.commit()
    return Response(md, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="assessment-{a.id}-report.md"'})


# ------------------------------------------------------------------ purple team
@router.get("/purple")
def purple_summary(db: Session = Depends(get_db), _p: Principal = VIEW, days: int = Query(30, ge=1, le=365), lab_id: int | None = None):
    """Attacked vs detected per ATT&CK technique across executed assessments."""
    return purple.summary(db, days, lab_id)


@router.get("/purple/report")
def purple_report(db: Session = Depends(get_db), p: Principal = VIEW, days: int = Query(30, ge=1, le=365)):
    md = purple.report_markdown(db, days)
    record(db, "redteam.purple.report", actor=p, resource_type="purple_report", details={"days": days})
    db.commit()
    return Response(md, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="purple-team-{days}d.md"'})

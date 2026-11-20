"""Vulnerability management API: catalogue, authorised lab scan jobs, findings workflow and remediation tasks."""
from datetime import date

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import get_db, utcnow
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.cyber_range.models import Lab, LabInstance
from app.iam.deps import Principal, require
from app.iam.models import User
from app.vuln import checks
from app.vuln import service as svc
from app.vuln.models import FINDING_STATUSES, FindingEvent, RemediationTask, ScanFinding, ScanJob, Vulnerability

router = APIRouter(prefix="/vuln", tags=["vulnerability"])
VIEW = Depends(require("vuln.view"))
SCAN = Depends(require("vuln.scan"))
MANAGE = Depends(require("vuln.manage"))


def _users(db, ids):
    ids = {i for i in ids if i}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all()) if ids else {}


def _v_out(v: Vulnerability):
    return {k: getattr(v, k) for k in ("id", "code", "title", "severity", "cwe", "category", "description", "remediation", "references",
                                       "detection", "is_builtin", "cves", "created_at", "updated_at")} | {"cvss": float(v.cvss) if v.cvss is not None else None}


def _f_out(f: ScanFinding, v: Vulnerability, labs: dict, users: dict):
    return {"id": f.id, "vulnerability": {"id": v.id, "code": v.code, "title": v.title, "cves": v.cves, "detection": v.detection, "category": v.category},
            "lab_id": f.lab_id, "lab": labs.get(f.lab_id), "node_key": f.node_key, "asset": f.asset_label, "ip": f.ip, "port": f.port,
            "severity": f.severity, "status": f.status, "source": f.source, "evidence": f.evidence, "first_seen": f.first_seen, "last_seen": f.last_seen,
            "times_seen": f.times_seen, "resolved_at": f.resolved_at, "status_reason": f.status_reason, "risk_accepted_until": f.risk_accepted_until,
            "owner": users.get(f.owner_id), "owner_id": f.owner_id, "last_job_id": f.last_job_id}


def _labs(db):
    return dict(db.execute(select(Lab.id, Lab.name)).all())


@router.get("/meta")
def meta(_p: Principal = VIEW):
    return {"profiles": checks.PROFILES, "statuses": FINDING_STATUSES, "transitions": {k: sorted(v) for k, v in svc.TRANSITIONS.items()},
            "http_paths": checks.HTTP_PATHS,
            "policy": "Scans run only from a node of your own running lab against nodes of that lab. Checks are non-destructive: TCP connect, "
                      "volunteered banners, one Redis PING and HTTP status/headers. No exploitation, brute force or credential use."}


@router.get("/overview")
def overview(db: Session = Depends(get_db), _p: Principal = VIEW):
    open_ = ScanFinding.status.in_(svc.OPEN_STATES)
    by_sev = dict(db.execute(select(ScanFinding.severity, func.count()).where(open_).group_by(ScanFinding.severity)).all())
    by_status = dict(db.execute(select(ScanFinding.status, func.count()).group_by(ScanFinding.status)).all())
    top = db.execute(select(Vulnerability, func.count(ScanFinding.id)).join(ScanFinding, ScanFinding.vulnerability_id == Vulnerability.id)
                     .where(open_).group_by(Vulnerability.id).order_by(func.count(ScanFinding.id).desc(), Vulnerability.severity.desc()).limit(8)).all()
    labs = _labs(db)
    by_lab = db.execute(select(ScanFinding.lab_id, func.count()).where(open_).group_by(ScanFinding.lab_id)).all()
    assets = db.execute(select(ScanFinding.lab_id, ScanFinding.node_key, ScanFinding.asset_label, func.count(), func.max(ScanFinding.severity))
                        .where(open_).group_by(ScanFinding.lab_id, ScanFinding.node_key, ScanFinding.asset_label)
                        .order_by(func.max(ScanFinding.severity).desc(), func.count().desc()).limit(10)).all()
    jobs = db.execute(select(ScanJob).order_by(ScanJob.id.desc()).limit(5)).scalars().all()
    users = _users(db, [j.requested_by for j in jobs])
    return {"open_by_severity": {str(s): by_sev.get(s, 0) for s in range(5)}, "open_total": sum(by_sev.values()), "by_status": by_status,
            "top_vulnerabilities": [{**_v_out(v), "open": n} for v, n in top],
            "by_lab": [{"lab_id": lid, "lab": labs.get(lid), "open": n} for lid, n in by_lab],
            "riskiest_assets": [{"lab_id": a[0], "lab": labs.get(a[0]), "node_key": a[1], "asset": a[2], "open": a[3], "max_severity": a[4]} for a in assets],
            "recent_jobs": [_job_out(j, users) for j in jobs], **svc.counts(db)}


# ------------------------------------------------------------------ catalogue
class VulnIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    code: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,47}$")
    title: str = Field(min_length=3, max_length=255)
    severity: int = Field(ge=0, le=4)
    cvss: float | None = Field(default=None, ge=0, le=10)
    cves: list[str] = Field(default_factory=list, max_length=20)
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d{1,5}$")
    category: str = Field(default="configuration", max_length=32)
    description: str = Field(default="", max_length=8000)
    remediation: str = Field(default="", max_length=8000)
    references: list[str] = Field(default_factory=list, max_length=20)


@router.get("/catalog")
def catalog(db: Session = Depends(get_db), _p: Principal = VIEW):
    rows = db.execute(select(Vulnerability).order_by(Vulnerability.is_builtin.desc(), Vulnerability.code)).scalars()
    return [_v_out(v) for v in rows]


def _check_cves(cves):
    import re
    bad = [c for c in cves if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", c)]
    if bad:
        raise AppError(f"Invalid CVE identifiers: {', '.join(bad)}", code="validation_error", status_code=422)


@router.post("/catalog", status_code=201)
def create_vuln(body: VulnIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    _check_cves(body.cves)
    if db.execute(select(Vulnerability).where(Vulnerability.code == body.code)).scalar_one_or_none():
        raise Conflict("A catalogue entry with this code exists", code="duplicate")
    v = Vulnerability(**body.model_dump(), detection="manual", is_builtin=False, created_by=p.id)
    db.add(v)
    db.flush()
    record(db, "vuln.catalog.create", actor=p, resource_type="vulnerability", resource_id=v.id, details={"code": v.code})
    db.commit()
    return _v_out(v)


@router.put("/catalog/{vid}")
def update_vuln(vid: int, body: VulnIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    v = db.get(Vulnerability, vid)
    if not v:
        raise NotFound("Catalogue entry not found")
    if v.is_builtin:
        raise Conflict("Builtin entries are maintained with the scanner checks and cannot be edited", code="builtin")
    _check_cves(body.cves)
    for k, val in body.model_dump().items():
        setattr(v, k, val)
    record(db, "vuln.catalog.update", actor=p, resource_type="vulnerability", resource_id=v.id)
    db.commit()
    return _v_out(v)


# ------------------------------------------------------------------ scans
def _job_out(j: ScanJob, users, detail=False):
    out = {"id": j.id, "name": j.name, "profile": j.profile, "lab_id": j.lab_id, "lab": j.scope.get("lab_name"), "runtime_id": j.runtime_id,
           "scanner_node": j.scanner_node, "scanner_ip": j.scanner_ip, "targets": j.scope["targets"], "ports": len(j.ports), "status": j.status,
           "summary": j.summary, "error": j.error, "requested_by": users.get(j.requested_by), "requested_by_id": j.requested_by,
           "created_at": j.created_at, "started_at": j.started_at, "finished_at": j.finished_at, "abort_requested": j.abort_requested}
    if detail:
        out["log"] = j.log
        out["port_list"] = j.ports
    return out


@router.get("/labs")
def scannable_labs(db: Session = Depends(get_db), p: Principal = SCAN):
    q = select(Lab).where(Lab.deleted_at.is_(None))
    if not p.has("lab.manage"):
        q = q.where(Lab.owner_id == p.id)
    out = []
    for lab in db.execute(q).scalars():
        inst = db.execute(select(LabInstance).where(LabInstance.lab_id == lab.id, LabInstance.status == "running")).scalar_one_or_none()
        if not inst:
            continue
        plan = {c["node_key"]: c for c in lab.plan["containers"]}
        out.append({"id": lab.id, "name": lab.name, "runtime_id": inst.runtime_id,
                    "nodes": [{"node_key": c.node_key, "label": plan.get(c.node_key, {}).get("label", c.node_key), "type": plan.get(c.node_key, {}).get("type"),
                               "image": plan.get(c.node_key, {}).get("image"), "addresses": c.addresses or {}, "status": c.status} for c in inst.containers]})
    return out


class ScanIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=160)
    lab_id: int
    scanner_node: str = Field(max_length=64)
    target_nodes: list[str] = Field(min_length=1, max_length=50)
    profile: str = Field(default="standard", pattern="^(quick|standard|custom)$")
    ports: list[int] | None = None


@router.get("/scans")
def list_scans(lab_id: int | None = None, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100),
               db: Session = Depends(get_db), _p: Principal = VIEW):
    w = [ScanJob.lab_id == lab_id] if lab_id else []
    total = db.execute(select(func.count()).select_from(ScanJob).where(*w)).scalar_one()
    rows = db.execute(select(ScanJob).where(*w).order_by(ScanJob.id.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
    users = _users(db, [j.requested_by for j in rows])
    return {"items": [_job_out(j, users) for j in rows], "total": total, "page": page, "page_size": page_size}


@router.post("/scans", status_code=202)
def start_scan(body: ScanIn, db: Session = Depends(get_db), p: Principal = SCAN):
    j = svc.create_job(db, p, name=body.name, lab_id=body.lab_id, scanner_node=body.scanner_node, target_nodes=body.target_nodes,
                       profile=body.profile, ports=body.ports)
    db.refresh(j)
    return _job_out(j, _users(db, [j.requested_by]), detail=True)


@router.get("/scans/{jid}")
def get_scan(jid: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    j = db.get(ScanJob, jid)
    if not j:
        raise NotFound("Scan job not found")
    out = _job_out(j, _users(db, [j.requested_by]), detail=True)
    rows = db.execute(select(ScanFinding, Vulnerability).join(Vulnerability, Vulnerability.id == ScanFinding.vulnerability_id)
                      .where(ScanFinding.last_job_id == j.id).order_by(ScanFinding.severity.desc(), ScanFinding.id)).all()
    labs = _labs(db)
    out["findings"] = [_f_out(f, v, labs, {}) for f, v in rows]
    return out


@router.post("/scans/{jid}/abort")
def abort_scan(jid: int, db: Session = Depends(get_db), p: Principal = SCAN):
    j = db.execute(select(ScanJob).where(ScanJob.id == jid).with_for_update()).scalar_one_or_none()
    if not j:
        raise NotFound("Scan job not found")
    if j.requested_by != p.id and not p.has("lab.manage"):
        raise Forbidden("Only the requester can abort this scan")
    if j.status == "queued":
        j.status, j.finished_at = "aborted", utcnow()
    elif j.status == "running":
        j.abort_requested = True  # the scanner script is bounded by its timeout; results after abort are still recorded
    else:
        raise Conflict(f"Scan is {j.status}", code="invalid_state")
    svc._log(j, f"Abort requested by {p.username}")
    record(db, "vuln.scan.abort", actor=p, resource_type="scan_job", resource_id=j.id)
    db.commit()
    return _job_out(j, _users(db, [j.requested_by]))


# ------------------------------------------------------------------ findings
@router.get("/findings")
def list_findings(status: str = Query("open"), severity: int | None = Query(None, ge=0, le=4), lab_id: int | None = None, q: str = "",
                  vulnerability_id: int | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                  db: Session = Depends(get_db), _p: Principal = VIEW):
    w = []
    if status == "open":
        w.append(ScanFinding.status.in_(svc.OPEN_STATES))
    elif status != "all":
        if status not in FINDING_STATUSES:
            raise AppError("Unknown status filter", code="validation_error", status_code=422)
        w.append(ScanFinding.status == status)
    if severity is not None:
        w.append(ScanFinding.severity == severity)
    if lab_id:
        w.append(ScanFinding.lab_id == lab_id)
    if vulnerability_id:
        w.append(ScanFinding.vulnerability_id == vulnerability_id)
    if q:
        like = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"
        w.append(or_(Vulnerability.title.like(like), Vulnerability.code.like(like), ScanFinding.asset_label.like(like), ScanFinding.ip.like(like)))
    base = select(ScanFinding, Vulnerability).join(Vulnerability, Vulnerability.id == ScanFinding.vulnerability_id).where(*w)
    total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()
    rows = db.execute(base.order_by(ScanFinding.severity.desc(), ScanFinding.last_seen.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    labs, users = _labs(db), _users(db, [f.owner_id for f, _ in rows])
    return {"items": [_f_out(f, v, labs, users) for f, v in rows], "total": total, "page": page, "page_size": page_size}


def _finding(db, fid, lock=False) -> ScanFinding:
    q = select(ScanFinding).where(ScanFinding.id == fid)
    f = db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
    if not f:
        raise NotFound("Finding not found")
    return f


def _task_out(t: RemediationTask, users):
    return {"id": t.id, "finding_id": t.finding_id, "title": t.title, "notes": t.notes, "status": t.status, "assignee": users.get(t.assignee_id),
            "assignee_id": t.assignee_id, "due_date": t.due_date, "completed_at": t.completed_at, "created_by": users.get(t.created_by),
            "created_at": t.created_at, "overdue": bool(t.due_date and t.status in ("open", "in_progress") and t.due_date < utcnow().date())}


@router.get("/findings/{fid}")
def get_finding(fid: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    f = _finding(db, fid)
    v = db.get(Vulnerability, f.vulnerability_id)
    evs = db.execute(select(FindingEvent).where(FindingEvent.finding_id == f.id).order_by(FindingEvent.id)).scalars().all()
    tasks = db.execute(select(RemediationTask).where(RemediationTask.finding_id == f.id).order_by(RemediationTask.id)).scalars().all()
    users = _users(db, [f.owner_id, *[e.actor_id for e in evs], *[t.assignee_id for t in tasks], *[t.created_by for t in tasks]])
    return {**_f_out(f, v, _labs(db), users), "vulnerability_detail": _v_out(v),
            "history": [{"id": e.id, "at": e.at, "kind": e.kind, "message": e.message, "job_id": e.job_id, "actor": users.get(e.actor_id)} for e in evs],
            "tasks": [_task_out(t, users) for t in tasks], "allowed_transitions": sorted(svc.TRANSITIONS.get(f.status, set()))}


class ManualFindingIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    vulnerability_id: int
    lab_id: int
    node_key: str = Field(min_length=1, max_length=64)
    port: int = Field(default=0, ge=0, le=65535)
    note: str = Field(min_length=10, max_length=4000)


@router.post("/findings", status_code=201)
def create_finding(body: ManualFindingIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    v = db.get(Vulnerability, body.vulnerability_id)
    lab = db.execute(select(Lab).where(Lab.id == body.lab_id, Lab.deleted_at.is_(None))).scalar_one_or_none()
    if not v or not lab:
        raise NotFound("Vulnerability or lab not found")
    node = next((c for c in lab.plan.get("containers", []) if c["node_key"] == body.node_key), None)
    if not node:
        raise AppError("The asset must be a node of the selected lab", code="invalid_scope", status_code=422)
    if db.execute(select(ScanFinding).where(ScanFinding.lab_id == lab.id, ScanFinding.node_key == body.node_key,
                                            ScanFinding.vulnerability_id == v.id, ScanFinding.port == body.port)).scalar_one_or_none():
        raise Conflict("This vulnerability is already recorded for that asset and port", code="duplicate")
    f = ScanFinding(vulnerability_id=v.id, lab_id=lab.id, node_key=body.node_key, asset_label=node.get("label", body.node_key), port=body.port,
                    severity=v.severity, status="open", source="manual", evidence={"analyst_note": body.note}, created_by=p.id, owner_id=p.id)
    db.add(f)
    db.flush()
    svc._finding_event(db, f, "created", f"Recorded manually by {p.username}", actor=p)
    record(db, "vuln.finding.create", actor=p, resource_type="scan_finding", resource_id=f.id, details={"vulnerability": v.code, "lab": lab.id})
    db.commit()
    return get_finding(f.id, db, p)


class StatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    status: str
    reason: str = Field(default="", max_length=2000)
    risk_accepted_until: date | None = None


@router.post("/findings/{fid}/status")
def set_status(fid: int, body: StatusIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    f = _finding(db, fid, lock=True)
    svc.change_status(db, p, f, body.status, body.reason, body.risk_accepted_until)
    db.commit()
    return get_finding(fid, db, p)


class OwnerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner_id: int | None


@router.post("/findings/{fid}/owner")
def set_owner(fid: int, body: OwnerIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    f = _finding(db, fid, lock=True)
    if body.owner_id and not db.get(User, body.owner_id):
        raise NotFound("User not found")
    f.owner_id = body.owner_id
    svc._finding_event(db, f, "owner", f"Owner set by {p.username}", actor=p)
    record(db, "vuln.finding.owner", actor=p, resource_type="scan_finding", resource_id=f.id, details={"owner": body.owner_id})
    db.commit()
    return get_finding(fid, db, p)


# ------------------------------------------------------------------ remediation tasks
class TaskIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=3, max_length=255)
    notes: str = Field(default="", max_length=4000)
    assignee_id: int | None = None
    due_date: date | None = None


class TaskPatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    status: str | None = Field(default=None, pattern="^(open|in_progress|done|cancelled)$")
    notes: str | None = Field(default=None, max_length=4000)
    assignee_id: int | None = None
    due_date: date | None = None


@router.get("/tasks")
def list_tasks(mine: bool = False, status: str = Query("active", pattern="^(active|all|done)$"), db: Session = Depends(get_db), p: Principal = VIEW):
    w = []
    if mine:
        w.append(RemediationTask.assignee_id == p.id)
    if status == "active":
        w.append(RemediationTask.status.in_(("open", "in_progress")))
    elif status == "done":
        w.append(RemediationTask.status == "done")
    rows = db.execute(select(RemediationTask, ScanFinding, Vulnerability).join(ScanFinding, ScanFinding.id == RemediationTask.finding_id)
                      .join(Vulnerability, Vulnerability.id == ScanFinding.vulnerability_id).where(*w)
                      .order_by(RemediationTask.due_date.is_(None), RemediationTask.due_date, RemediationTask.id.desc()).limit(500)).all()
    users = _users(db, [t.assignee_id for t, _, _ in rows] + [t.created_by for t, _, _ in rows])
    return [{**_task_out(t, users), "finding": {"id": f.id, "asset": f.asset_label, "port": f.port, "severity": f.severity, "status": f.status,
                                                "vulnerability": v.title, "code": v.code}} for t, f, v in rows]


@router.post("/findings/{fid}/tasks", status_code=201)
def create_task(fid: int, body: TaskIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    f = _finding(db, fid, lock=True)
    if f.status in ("resolved", "false_positive"):
        raise Conflict(f"Finding is {f.status}", code="invalid_state")
    if body.assignee_id and not db.get(User, body.assignee_id):
        raise NotFound("Assignee not found")
    t = RemediationTask(finding_id=f.id, title=body.title, notes=body.notes, assignee_id=body.assignee_id, due_date=body.due_date, created_by=p.id)
    db.add(t)
    if f.status == "open":
        svc.change_status(db, p, f, "in_remediation", f"Remediation task created: {body.title}")
    svc._finding_event(db, f, "task", f"Task '{body.title}' created by {p.username}", actor=p)
    db.flush()
    record(db, "vuln.task.create", actor=p, resource_type="remediation_task", resource_id=t.id, details={"finding": f.id})
    db.commit()
    return _task_out(t, _users(db, [t.assignee_id, t.created_by]))


@router.patch("/tasks/{tid}")
def update_task(tid: int, body: TaskPatch, db: Session = Depends(get_db), p: Principal = MANAGE):
    t = db.execute(select(RemediationTask).where(RemediationTask.id == tid).with_for_update()).scalar_one_or_none()
    if not t:
        raise NotFound("Task not found")
    data = body.model_dump(exclude_unset=True)
    if "assignee_id" in data and data["assignee_id"] and not db.get(User, data["assignee_id"]):
        raise NotFound("Assignee not found")
    for k in ("notes", "assignee_id", "due_date"):
        if k in data:
            setattr(t, k, data[k])
    f = _finding(db, t.finding_id, lock=True)
    if body.status and body.status != t.status:
        t.status = body.status
        t.completed_at = utcnow() if body.status == "done" else None
        svc._finding_event(db, f, "task", f"Task '{t.title}' → {body.status} by {p.username}", actor=p)
        others = db.execute(select(func.count()).select_from(RemediationTask).where(RemediationTask.finding_id == f.id, RemediationTask.id != t.id,
                                                                                     RemediationTask.status.in_(("open", "in_progress")))).scalar_one()
        if body.status == "done" and not others and f.status in ("open", "in_remediation"):
            svc.change_status(db, p, f, "fixed_pending_verification", f"All remediation tasks done ('{t.title}')")
    record(db, "vuln.task.update", actor=p, resource_type="remediation_task", resource_id=t.id, details={k: str(v) for k, v in data.items()})
    db.commit()
    return _task_out(t, _users(db, [t.assignee_id, t.created_by]))


@router.get("/assignees")
def assignees(db: Session = Depends(get_db), _p: Principal = MANAGE):
    rows = db.execute(select(User.id, User.username, User.full_name).where(User.deleted_at.is_(None), User.is_active.is_(True)).order_by(User.username)).all()
    return [{"id": i, "username": u, "full_name": n} for i, u, n in rows]

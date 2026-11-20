"""Digital Forensics / Cases & Evidence API."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam.models import Incident
from app.core.database import get_db, utcnow
from app.core.errors import AppError, NotFound
from app.core.storage import get_storage
from app.forensics import service as svc
from app.forensics.models import CUSTODY_ACTIONS, EVIDENCE_KINDS, EVIDENCE_STATUSES, CustodyEvent, Evidence, EvidenceHash, ForensicCase
from app.iam.deps import Principal, effective_permissions, require
from app.iam.models import User

router = APIRouter(prefix="/forensics", tags=["forensics"])
VIEW = Depends(require("evidence.view"))
MANAGE = Depends(require("evidence.manage"))
UPLOAD_KINDS = tuple(k for k in EVIDENCE_KINDS if k not in ("malware_sample",))


def _users(db, ids):
    ids = {i for i in ids if i}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all()) if ids else {}


def _c_out(c: ForensicCase, users, n_evidence=0):
    return {"id": c.id, "reference": c.reference, "title": c.title, "description": c.description, "status": c.status, "classification": c.classification,
            "incident_id": c.incident_id, "lead": users.get(c.lead_id), "lead_id": c.lead_id, "created_by": users.get(c.created_by), "created_at": c.created_at,
            "updated_at": c.updated_at, "closed_at": c.closed_at, "closure_note": c.closure_note, "evidence_count": n_evidence}


def _e_out(e: Evidence, users, case_ref=None):
    return {"id": e.id, "reference": e.reference, "case_id": e.case_id, "case_reference": case_ref, "kind": e.kind, "title": e.title,
            "description": e.description, "source": e.source, "collected_by": users.get(e.collected_by), "collected_at": e.collected_at, "filename": e.filename,
            "size": e.size, "sha256": e.sha256, "sample_id": e.sample_id, "origin": e.origin, "status": e.status, "custodian": users.get(e.custodian_id),
            "custodian_id": e.custodian_id, "is_sealed": e.is_sealed, "integrity": e.integrity, "last_verified_at": e.last_verified_at,
            "custody_entries": e.custody_seq, "downloadable": bool(e.storage_key), "created_at": e.created_at}


@router.get("/meta")
def meta(db: Session = Depends(get_db), _p: Principal = VIEW):
    from app.governance.service import get_value
    return {"kinds": EVIDENCE_KINDS, "upload_kinds": UPLOAD_KINDS, "statuses": EVIDENCE_STATUSES, "custody_actions": CUSTODY_ACTIONS,
            "max_upload_mb": get_value(db, "evidence.max_upload_mb"), "storage": get_storage().status()}


@router.get("/overview")
def overview(db: Session = Depends(get_db), _p: Principal = VIEW):
    by_kind = dict(db.execute(select(Evidence.kind, func.count()).group_by(Evidence.kind)).all())
    by_integrity = dict(db.execute(select(Evidence.integrity, func.count()).group_by(Evidence.integrity)).all())
    recent = db.execute(select(CustodyEvent, Evidence).join(Evidence, Evidence.id == CustodyEvent.evidence_id).order_by(CustodyEvent.id.desc()).limit(15)).all()
    stale = db.execute(select(func.count()).select_from(Evidence).where(or_(Evidence.last_verified_at.is_(None),
                                                                            Evidence.last_verified_at < utcnow() - timedelta(days=30)))).scalar_one()
    return {**svc.counts(db), "by_kind": by_kind, "by_integrity": by_integrity, "verification_due": stale,
            "recent_custody": [{"id": ev.id, "at": ev.at, "action": ev.action, "actor": ev.actor_label, "evidence_id": e.id, "evidence": e.reference,
                                "title": e.title, "result": ev.result, "to": ev.to_custodian} for ev, e in recent]}


# ------------------------------------------------------------------ cases
class CaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(default="", max_length=8000)
    classification: str = Field(default="internal", pattern="^(internal|confidential|restricted)$")
    incident_id: int | None = None


@router.get("/cases")
def list_cases(status: str = Query("open", pattern="^(open|closed|all)$"), q: str = "", db: Session = Depends(get_db), _p: Principal = VIEW):
    w = [] if status == "all" else [ForensicCase.status == status]
    if q:
        like = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"
        w.append(or_(ForensicCase.title.like(like), ForensicCase.reference.like(like)))
    rows = db.execute(select(ForensicCase).where(*w).order_by(ForensicCase.id.desc()).limit(500)).scalars().all()
    n = dict(db.execute(select(Evidence.case_id, func.count()).group_by(Evidence.case_id)).all())
    users = _users(db, [c.lead_id for c in rows] + [c.created_by for c in rows])
    return [_c_out(c, users, n.get(c.id, 0)) for c in rows]


@router.post("/cases", status_code=201)
def create_case(body: CaseIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    if body.incident_id and not db.get(Incident, body.incident_id):
        raise NotFound("Incident not found")
    c = svc.new_case(db, p, title=body.title, description=body.description, classification=body.classification, incident_id=body.incident_id)
    db.commit()
    return _c_out(c, _users(db, [c.lead_id, c.created_by]))


def _case(db, cid, lock=False) -> ForensicCase:
    q = select(ForensicCase).where(ForensicCase.id == cid)
    c = db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
    if not c:
        raise NotFound("Case not found")
    return c


@router.get("/cases/{cid}")
def get_case(cid: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    c = _case(db, cid)
    items = db.execute(select(Evidence).where(Evidence.case_id == c.id).order_by(Evidence.id)).scalars().all()
    users = _users(db, [c.lead_id, c.created_by, *[e.custodian_id for e in items], *[e.collected_by for e in items]])
    inc = db.get(Incident, c.incident_id) if c.incident_id else None
    return {**_c_out(c, users, len(items)), "incident": {"id": inc.id, "title": inc.title, "status": inc.status} if inc else None,
            "evidence": [_e_out(e, users, c.reference) for e in items]}


class CasePatch(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=8000)
    lead_id: int | None = None
    status: str | None = Field(default=None, pattern="^(open|closed)$")
    closure_note: str | None = Field(default=None, max_length=4000)


@router.patch("/cases/{cid}")
def update_case(cid: int, body: CasePatch, db: Session = Depends(get_db), p: Principal = MANAGE):
    c = _case(db, cid, lock=True)
    data = body.model_dump(exclude_unset=True)
    if "lead_id" in data:
        u = db.get(User, data["lead_id"]) if data["lead_id"] else None
        if not u or "evidence.manage" not in effective_permissions(u):
            raise AppError("The case lead must hold evidence.manage", code="validation_error", status_code=422)
        c.lead_id = u.id
    for k in ("title", "description"):
        if k in data:
            setattr(c, k, data[k])
    if data.get("status") and data["status"] != c.status:
        if data["status"] == "closed":
            if len((data.get("closure_note") or "").strip()) < 10:
                raise AppError("Closing a case needs a closure note (at least 10 characters)", code="validation_error", status_code=422)
            c.status, c.closed_at, c.closure_note = "closed", utcnow(), data["closure_note"]
        else:
            c.status, c.closed_at = "open", None
    record(db, "forensics.case.update", actor=p, resource_type="forensic_case", resource_id=c.id, details={k: str(v)[:200] for k, v in data.items()})
    db.commit()
    return get_case(cid, db, p)


@router.get("/cases/{cid}/report")
def case_report(cid: int, db: Session = Depends(get_db), p: Principal = VIEW):
    c = _case(db, cid)
    items = db.execute(select(Evidence).where(Evidence.case_id == c.id)).scalars().all()
    users = _users(db, [c.lead_id, *[e.custodian_id for e in items], *[e.collected_by for e in items]])
    md = svc.report_markdown(db, c, users)
    for e in items:
        e = svc.lock(db, e.id)
        svc.custody(db, e, "exported", p, reason="Included in chain-of-custody report", details={"operation": "case_report"})
    record(db, "forensics.case.report", actor=p, resource_type="forensic_case", resource_id=c.id)
    db.commit()
    return Response(md, media_type="text/markdown; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{c.reference}-custody.md"'})


# ------------------------------------------------------------------ evidence
@router.get("/evidence")
def list_evidence(q: str = "", integrity: str = "", kind: str = "", page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                  db: Session = Depends(get_db), _p: Principal = VIEW):
    w = []
    if q:
        v = q.strip().lower()
        like = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"
        w.append(or_(Evidence.sha256 == v, Evidence.title.like(like), Evidence.reference.like(like), Evidence.source.like(like)))
    if integrity:
        w.append(Evidence.integrity == integrity)
    if kind:
        w.append(Evidence.kind == kind)
    total = db.execute(select(func.count()).select_from(Evidence).where(*w)).scalar_one()
    rows = db.execute(select(Evidence, ForensicCase.reference).join(ForensicCase, ForensicCase.id == Evidence.case_id).where(*w)
                      .order_by(Evidence.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    users = _users(db, [e.custodian_id for e, _ in rows] + [e.collected_by for e, _ in rows])
    return {"items": [_e_out(e, users, ref) for e, ref in rows], "total": total, "page": page, "page_size": page_size}


@router.post("/cases/{cid}/evidence", status_code=201)
def upload_evidence(cid: int, file: UploadFile = File(...), kind: str = Form(...), title: str = Form(..., min_length=3, max_length=255),
                    description: str = Form("", max_length=8000), source: str = Form("", max_length=255), collected_at: datetime | None = Form(None),
                    location: str = Form("", max_length=255), db: Session = Depends(get_db), p: Principal = MANAGE):
    if kind not in UPLOAD_KINDS:
        raise AppError(f"kind must be one of {', '.join(UPLOAD_KINDS)} (submit samples through Malware Analysis)", code="validation_error", status_code=422)
    if collected_at and collected_at.replace(tzinfo=None) > utcnow():
        raise AppError("The collection time cannot be in the future", code="validation_error", status_code=422)
    e = svc.add_file(db, p, cid, file.file, file.filename or "evidence.bin", kind=kind, title=title.strip(), description=description.strip(),
                     source=source.strip(), collected_at=collected_at, location=location.strip())
    return _e_out(e, _users(db, [e.custodian_id, e.collected_by]))


class SampleEvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    sample_id: int
    title: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=8000)
    location: str = Field(default="", max_length=255)


@router.post("/cases/{cid}/evidence/sample", status_code=201)
def evidence_from_sample(cid: int, body: SampleEvidenceIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    e = svc.add_sample(db, p, cid, body.sample_id, title=body.title, description=body.description, location=body.location)
    return _e_out(e, _users(db, [e.custodian_id, e.collected_by]))


class EventsEvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    event_ids: list[int] = Field(default_factory=list, max_length=5000)
    alert_id: int | None = None
    title: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=8000)


@router.post("/cases/{cid}/evidence/events", status_code=201)
def evidence_from_events(cid: int, body: EventsEvidenceIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    if not p.has("blueteam.alerts.view"):
        raise AppError("Exporting SIEM events needs blueteam.alerts.view", code="forbidden", status_code=403)
    e = svc.add_events(db, p, cid, event_ids=body.event_ids, alert_id=body.alert_id, title=body.title, description=body.description)
    return _e_out(e, _users(db, [e.custodian_id, e.collected_by]))


@router.get("/evidence/{eid}")
def get_evidence(eid: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    e = db.get(Evidence, eid)
    if not e:
        raise NotFound("Evidence not found")
    c = db.get(ForensicCase, e.case_id)
    evs = db.execute(select(CustodyEvent).where(CustodyEvent.evidence_id == e.id).order_by(CustodyEvent.seq)).scalars().all()
    hashes = db.execute(select(EvidenceHash).where(EvidenceHash.evidence_id == e.id).order_by(EvidenceHash.algorithm)).scalars().all()
    users = _users(db, [e.custodian_id, e.collected_by, c.lead_id])
    return {**_e_out(e, users, c.reference), "case": {"id": c.id, "reference": c.reference, "title": c.title, "status": c.status, "lead": users.get(c.lead_id), "lead_id": c.lead_id},
            "hashes": [{"algorithm": h.algorithm, "value": h.value, "computed_at": h.computed_at} for h in hashes],
            "custody": [{"seq": v.seq, "at": v.at, "action": v.action, "actor": v.actor_label, "from": v.from_custodian, "to": v.to_custodian, "reason": v.reason,
                         "location": v.location, "sha256_observed": v.sha256_observed, "result": v.result, "details": v.details, "entry_hash": v.entry_hash} for v in evs],
            "chain": svc.verify_chain(db, e)}


class ReasonIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: str = Field(min_length=5, max_length=4000)


class TransferIn(ReasonIn):
    to_user_id: int
    location: str = Field(default="", max_length=255)


class StatusIn(ReasonIn):
    status: str = Field(pattern="^(collected|in_analysis|preserved|released)$")


@router.post("/evidence/{eid}/verify")
def verify(eid: int, db: Session = Depends(get_db), p: Principal = MANAGE):
    e = svc.lock(db, eid)
    return svc.verify(db, p, e)


@router.post("/evidence/{eid}/transfer")
def transfer(eid: int, body: TransferIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    svc.transfer(db, p, svc.lock(db, eid), body.to_user_id, body.reason, body.location)
    return get_evidence(eid, db, p)


@router.post("/evidence/{eid}/status")
def set_status(eid: int, body: StatusIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    svc.set_status(db, p, svc.lock(db, eid), body.status, body.reason)
    return get_evidence(eid, db, p)


@router.post("/evidence/{eid}/seal")
def seal(eid: int, body: ReasonIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    svc.seal(db, p, svc.lock(db, eid), body.reason)
    return get_evidence(eid, db, p)


@router.post("/evidence/{eid}/notes")
def add_note(eid: int, body: ReasonIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    svc.note(db, p, svc.lock(db, eid), body.reason)
    return get_evidence(eid, db, p)


@router.post("/evidence/{eid}/download")
def download(eid: int, body: ReasonIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    e = svc.lock(db, eid)
    it = svc.open_download(db, p, e, body.reason)
    name = (e.filename or f"{e.reference.replace('/', '_')}.bin").replace('"', "")
    return StreamingResponse(it, media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{name}"', "X-Evidence-SHA256": e.sha256, "X-Content-Type-Options": "nosniff"})


@router.get("/custodians")
def custodians(db: Session = Depends(get_db), _p: Principal = MANAGE):
    out = []
    for u in db.execute(select(User).where(User.deleted_at.is_(None), User.is_active.is_(True)).order_by(User.username)).scalars():
        if "evidence.manage" in effective_permissions(u):
            out.append({"id": u.id, "username": u.username, "full_name": u.full_name})
    return out


@router.get("/incidents/{iid}/cases")
def cases_for_incident(iid: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    rows = db.execute(select(ForensicCase).where(ForensicCase.incident_id == iid).order_by(ForensicCase.id)).scalars().all()
    return [{"id": c.id, "reference": c.reference, "title": c.title, "status": c.status} for c in rows]




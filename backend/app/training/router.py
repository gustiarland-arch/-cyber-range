"""Practice API: CTF challenges (flags and Sigma/YARA rules), missions, and authoring of both.

Learner endpoints need `training.participate` (managers can read everything to review content). Authoring needs
`training.manage`. Flags and mission answers are write-only: they are never returned by any endpoint.
"""
import re

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import get_db
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.storage import get_storage, spool
from app.iam.deps import Principal, get_principal, require
from app.iam.models import User
from app.network.templates import TEMPLATES
from app.training import service as svc
from app.training.models import CATEGORIES, LEVELS, OBJECTIVE_KINDS, Challenge, Hint, Mission, Objective, ScoreEvent, Submission

router = APIRouter(prefix="/training", tags=["training"])
PLAY = Depends(require("training.participate"))
MANAGE = Depends(require("training.manage"))
SLUG = r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"
NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
MAX_ATTACHMENT = 20 * 1024 * 1024


def _reader(request: Request, p: Principal = Depends(get_principal)) -> Principal:
    if p.has("training.participate") or p.has("training.manage"):
        return p
    return require("training.participate")(request, p)  # audited denial


READ = Depends(_reader)


def _users(db, ids):
    ids = {i for i in ids if i}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all()) if ids else {}


def _templates():
    return [{"key": k, "title": v["title"]} for k, v in TEMPLATES.items() if k != "blank"]


@router.get("/meta")
def meta(_p: Principal = READ):
    return {"categories": CATEGORIES, "levels": LEVELS, "objective_kinds": OBJECTIVE_KINDS, "lab_templates": _templates(),
            "wrong_limit": svc.WRONG_LIMIT, "wrong_window_s": svc.WRONG_WINDOW, "min_share": svc.MIN_SHARE,
            "policy": "Flags and answers are stored only as salted hashes. Points come from verified actions in your own isolated labs; "
                      "hints reduce a challenge's value (never below 10%). Authors cannot score on their own content."}


@router.get("/me")
def me(db: Session = Depends(get_db), p: Principal = READ):
    return svc.my_summary(db, p)




# ------------------------------------------------------------------ challenges
def _ch_out(ch: Challenge, solves: dict, mine: dict, users=None, manage=False):
    ev = mine.get(ch.id)
    out = {"id": ch.id, "slug": ch.slug, "title": ch.title, "category": ch.category, "difficulty": ch.difficulty, "points": ch.points,
           "flag_format": ch.flag_format, "lab_template": ch.lab_template, "is_published": ch.is_published, "is_builtin": ch.is_builtin,
           "solves": solves.get(ch.id, 0), "solved": bool(ev), "my_points": ev.points if ev else None, "first_blood": bool(ev and ev.first_blood),
           "solved_at": ev.at if ev else None, "attachments": [{"name": a["name"], "size": a["size"], "sha256": a["sha256"]} for a in ch.attachments or []],
           "kind": ch.kind}
    if manage:
        out["created_by"] = (users or {}).get(ch.created_by)
    return out


@router.get("/challenges")
def list_challenges(category: str = "", db: Session = Depends(get_db), p: Principal = READ):
    q = select(Challenge).order_by(Challenge.points, Challenge.title)
    if not p.has("training.manage"):
        q = q.where(Challenge.is_published.is_(True))
    if category:
        q = q.where(Challenge.category == category)
    rows = db.execute(q).scalars().all()
    solves, mine = svc.solve_counts(db), svc.scored(db, p.id, "challenge")
    users = _users(db, [c.created_by for c in rows])
    return [_ch_out(c, solves, mine, users, p.has("training.manage")) for c in rows]


@router.get("/challenges/{chid}")
def get_challenge(chid: int, db: Session = Depends(get_db), p: Principal = READ):
    ch = svc.visible_challenge(db, p, chid)
    mine = svc.scored(db, p.id, "challenge", [ch.id])
    out = _ch_out(ch, svc.solve_counts(db), mine, _users(db, [ch.created_by]), p.has("training.manage"))
    unlocked = svc.unlocked_hints(db, p.id, ch.id)
    hints = db.execute(select(Hint).where(Hint.challenge_id == ch.id).order_by(Hint.position)).scalars().all()
    out["description"] = ch.description
    out["hints"] = [{"id": h.id, "position": h.position, "cost": h.cost, "unlocked": h.id in unlocked, "text": h.text if h.id in unlocked else None} for h in hints]
    out["hint_penalty"] = svc.hint_penalty(db, p.id, ch.id)
    out["potential_points"] = max(int(round(ch.points * svc.MIN_SHARE)), ch.points - out["hint_penalty"])
    out["is_author"] = ch.created_by == p.id
    out["wrong_recent"] = db.execute(select(func.count()).select_from(Submission).where(Submission.user_id == p.id, Submission.challenge_id == ch.id,
                                                                                        Submission.is_correct.is_(False))).scalar_one()
    return out


class FlagIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flag: str = Field(min_length=1, max_length=512)


@router.post("/challenges/{chid}/submit")
def submit(chid: int, body: FlagIn, db: Session = Depends(get_db), p: Principal = PLAY):
    out = svc.submit_flag(db, p, chid, body.flag)
    db.commit()
    return out


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=1, max_length=svc.MAX_RULE_SOURCE)


@router.post("/challenges/{chid}/submit-rule")
def submit_rule(chid: int, body: RuleIn, db: Session = Depends(get_db), p: Principal = PLAY):
    out = svc.submit_rule(db, p, chid, body.source)
    db.commit()
    return out


@router.post("/challenges/{chid}/hints/{hid}/unlock")
def unlock(chid: int, hid: int, db: Session = Depends(get_db), p: Principal = PLAY):
    h = svc.unlock_hint(db, p, chid, hid)
    db.commit()
    return {"id": h.id, "text": h.text, "cost": h.cost}


@router.get("/challenges/{chid}/attachments/{name}")
def attachment(chid: int, name: str, db: Session = Depends(get_db), p: Principal = READ):
    ch = svc.visible_challenge(db, p, chid)
    a = next((x for x in ch.attachments or [] if x["name"] == name), None)
    if not a:
        raise NotFound("Attachment not found")
    record(db, "training.attachment.download", actor=p, resource_type="challenge", resource_id=ch.id, details={"name": name})
    db.commit()
    return StreamingResponse(get_storage().open_iter(a["key"]), media_type="application/octet-stream",
                             headers={"Content-Disposition": f'attachment; filename="{a["name"]}"', "X-Content-Type-Options": "nosniff",
                                      "X-Attachment-SHA256": a["sha256"]})


class PracticeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(pattern="^(challenge|mission)$")
    id: int


@router.post("/practice-lab", status_code=201)
def practice_lab(body: PracticeIn, db: Session = Depends(get_db), p: Principal = PLAY):
    item = svc.visible_challenge(db, p, body.id) if body.kind == "challenge" else svc.visible_mission(db, p, body.id)
    if not item.lab_template:
        raise Conflict("This item has no practice lab", code="no_lab")
    return svc.launch_practice_lab(db, p, template=item.lab_template, title=item.title)


# ------------------------------------------------------------------ missions
def _obj_out(o: Objective, done: dict):
    ev = done.get(o.id)
    return {"id": o.id, "position": o.position, "title": o.title, "kind": o.kind, "points": o.points, "hint": o.hint,
            "met": bool(ev), "evidence": ev.detail.get("evidence") if ev else None, "met_at": ev.at if ev else None,
            "target": {k: v for k, v in (o.config or {}).items() if k in ("slug", "code", "scenario")}}


@router.get("/missions")
def list_missions(db: Session = Depends(get_db), p: Principal = READ):
    q = select(Mission).order_by(Mission.difficulty, Mission.title)
    if not p.has("training.manage"):
        q = q.where(Mission.is_published.is_(True))
    rows = db.execute(q).scalars().all()
    prog = svc.mission_progress(db, p.id)
    pts = dict(db.execute(select(Objective.mission_id, func.sum(Objective.points)).group_by(Objective.mission_id)).all())
    return [{"id": m.id, "slug": m.slug, "title": m.title, "difficulty": m.difficulty, "lab_template": m.lab_template, "is_published": m.is_published,
             "is_builtin": m.is_builtin, "objectives": prog.get(m.id, {}).get("objectives", 0), "met": prog.get(m.id, {}).get("met", 0),
             "points": int(pts.get(m.id) or 0)} for m in rows]


@router.get("/missions/{mid}")
def get_mission(mid: int, db: Session = Depends(get_db), p: Principal = READ):
    m = svc.visible_mission(db, p, mid)
    objs = svc.objectives_of(db, m.id)
    done = svc.scored(db, p.id, "objective", [o.id for o in objs])
    return {"id": m.id, "slug": m.slug, "title": m.title, "briefing": m.briefing, "difficulty": m.difficulty, "lab_template": m.lab_template,
            "is_published": m.is_published, "is_builtin": m.is_builtin, "is_author": m.created_by == p.id,
            "objectives": [_obj_out(o, done) for o in objs]}


@router.post("/missions/{mid}/check")
def check_mission(mid: int, db: Session = Depends(get_db), p: Principal = PLAY):
    out = svc.check_mission(db, p, mid)
    db.commit()
    return {"results": out}


class AnswerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str = Field(min_length=1, max_length=512)


@router.post("/missions/{mid}/objectives/{oid}/answer")
def answer(mid: int, oid: int, body: AnswerIn, db: Session = Depends(get_db), p: Principal = PLAY):
    out = svc.answer_objective(db, p, mid, oid, body.answer)
    db.commit()
    return out




# ------------------------------------------------------------------ authoring
def _editable(obj, what: str):
    if obj is None:
        raise NotFound(f"{what} not found")
    if obj.is_builtin:
        raise Forbidden(f"Builtin {what.lower()}s are maintained by the platform; only publishing can be toggled")
    return obj


class PublishIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    is_published: bool


def _slug_free(db, model, slug, exclude=None):
    q = select(model.id).where(model.slug == slug)
    if exclude:
        q = q.where(model.id != exclude)
    if db.execute(q).first():
        raise Conflict("That slug is already used", code="slug_taken")


class HintIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=3, max_length=2000)
    cost: int = Field(10, ge=0, le=1000)


class ChallengeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=SLUG)
    title: str = Field(min_length=3, max_length=160)
    category: str
    difficulty: str = Field("beginner", pattern="^(beginner|intermediate|advanced)$")
    points: int = Field(100, ge=10, le=2000)
    description: str = Field(min_length=10, max_length=100_000)
    flag_format: str = Field("CR{...}", max_length=64)
    flag: str | None = Field(None, max_length=512)  # write-only; required on create
    case_sensitive: bool = False
    lab_template: str | None = None
    hints: list[HintIn] = Field(default_factory=list, max_length=10)

    @field_validator("category")
    @classmethod
    def _cat(cls, v):
        if v not in CATEGORIES:
            raise ValueError("unknown category")
        return v

    @field_validator("lab_template")
    @classmethod
    def _tpl(cls, v):
        if v and v not in TEMPLATES:
            raise ValueError("unknown lab template")
        return v or None


def _apply_challenge(db, ch: Challenge, body: ChallengeIn):
    old_case = ch.case_sensitive
    for k in ("slug", "title", "category", "difficulty", "points", "description", "flag_format", "case_sensitive", "lab_template"):
        setattr(ch, k, getattr(body, k))
    if body.flag:
        svc.set_flag(ch, body.flag)
    elif ch.flag_hash and old_case != body.case_sensitive:
        raise AppError("Changing case sensitivity requires re-entering the flag", code="flag_required", status_code=422)
    db.flush()
    existing = {h.position: h for h in db.execute(select(Hint).where(Hint.challenge_id == ch.id)).scalars()}
    for i, h in enumerate(body.hints, 1):
        row = existing.pop(i, None) or Hint(challenge_id=ch.id, position=i)
        row.text, row.cost = h.text, h.cost
        db.add(row)
    for row in existing.values():
        db.delete(row)


@router.get("/challenges/{chid}/authoring")
def challenge_authoring(chid: int, db: Session = Depends(get_db), _p: Principal = MANAGE):
    ch = db.get(Challenge, chid)
    if not ch:
        raise NotFound("Challenge not found")
    hints = db.execute(select(Hint).where(Hint.challenge_id == ch.id).order_by(Hint.position)).scalars().all()
    return {"id": ch.id, "slug": ch.slug, "title": ch.title, "category": ch.category, "difficulty": ch.difficulty, "points": ch.points,
            "description": ch.description, "flag_format": ch.flag_format, "case_sensitive": ch.case_sensitive, "lab_template": ch.lab_template,
            "is_published": ch.is_published, "is_builtin": ch.is_builtin, "flag_set": bool(ch.flag_hash),
            "hints": [{"text": h.text, "cost": h.cost} for h in hints],
            "attachments": [{"name": a["name"], "size": a["size"], "sha256": a["sha256"]} for a in ch.attachments or []]}


@router.post("/challenges", status_code=201)
def create_challenge(body: ChallengeIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    if not body.flag:
        raise AppError("A flag is required", code="flag_required", status_code=422)
    _slug_free(db, Challenge, body.slug)
    ch = Challenge(created_by=p.id, is_published=False, is_builtin=False, attachments=[], flag_salt="", flag_hash="")
    db.add(ch)
    _apply_challenge(db, ch, body)
    record(db, "training.challenge.create", actor=p, resource_type="challenge", resource_id=ch.id, details={"slug": ch.slug, "points": ch.points})
    db.commit()
    return {"id": ch.id}


@router.put("/challenges/{chid}")
def update_challenge(chid: int, body: ChallengeIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    ch = _editable(db.get(Challenge, chid), "Challenge")
    _slug_free(db, Challenge, body.slug, ch.id)
    if body.slug != ch.slug and ch.attachments:
        raise Conflict("Remove attachments before changing the slug", code="has_attachments")
    _apply_challenge(db, ch, body)
    record(db, "training.challenge.update", actor=p, resource_type="challenge", resource_id=ch.id, details={"flag_changed": bool(body.flag)})
    db.commit()
    return {"id": ch.id}


@router.post("/challenges/{chid}/publish")
def publish_challenge(chid: int, body: PublishIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    ch = db.get(Challenge, chid)
    if not ch:
        raise NotFound("Challenge not found")
    ch.is_published = body.is_published
    record(db, "training.challenge.publish", actor=p, resource_type="challenge", resource_id=ch.id, details={"is_published": ch.is_published})
    db.commit()
    return {"id": ch.id, "is_published": ch.is_published}


@router.delete("/challenges/{chid}", status_code=204)
def delete_challenge(chid: int, db: Session = Depends(get_db), p: Principal = MANAGE):
    ch = _editable(db.get(Challenge, chid), "Challenge")
    if db.execute(select(Submission.id).where(Submission.challenge_id == ch.id).limit(1)).first():
        raise Conflict("This challenge has submissions; unpublish it instead", code="in_use")
    for a in ch.attachments or []:
        get_storage().delete(a["key"])
    record(db, "training.challenge.delete", actor=p, resource_type="challenge", resource_id=ch.id, details={"slug": ch.slug})
    db.delete(ch)
    db.commit()


@router.post("/challenges/{chid}/attachments", status_code=201)
def upload_attachment(chid: int, file: UploadFile = File(...), name: str = Form("", max_length=100), db: Session = Depends(get_db), p: Principal = MANAGE):
    ch = _editable(db.get(Challenge, chid), "Challenge")
    fname = (name or file.filename or "").strip().split("/")[-1].split("\\")[-1]
    if not NAME_RX.match(fname):
        raise AppError("Attachment names may contain letters, digits, '.', '_' and '-' only", code="validation_error", status_code=422)
    if len(ch.attachments or []) >= 10 and not any(a["name"] == fname for a in ch.attachments):
        raise Conflict("At most 10 attachments per challenge", code="too_many")
    sp = spool(file.file, MAX_ATTACHMENT)
    try:
        sp.file.seek(0)
        data = sp.file.read()
    finally:
        sp.close()
    meta = svc.store_attachment(ch, fname, data)
    record(db, "training.attachment.upload", actor=p, resource_type="challenge", resource_id=ch.id, details={"name": fname, "sha256": meta["sha256"], "size": meta["size"]})
    db.commit()
    return {"name": meta["name"], "size": meta["size"], "sha256": meta["sha256"]}


@router.delete("/challenges/{chid}/attachments/{name}", status_code=204)
def delete_attachment(chid: int, name: str, db: Session = Depends(get_db), p: Principal = MANAGE):
    ch = _editable(db.get(Challenge, chid), "Challenge")
    a = next((x for x in ch.attachments or [] if x["name"] == name), None)
    if not a:
        raise NotFound("Attachment not found")
    get_storage().delete(a["key"])
    ch.attachments = [x for x in ch.attachments if x["name"] != name]
    record(db, "training.attachment.delete", actor=p, resource_type="challenge", resource_id=ch.id, details={"name": name})
    db.commit()


class ObjectiveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=3, max_length=255)
    kind: str
    points: int = Field(25, ge=0, le=1000)
    hint: str = Field("", max_length=2000)
    answer: str | None = Field(None, max_length=512)  # write-only, kind=answer
    slug: str | None = None        # challenge
    code: str | None = Field(None, max_length=32)       # vuln_finding
    scenario: str | None = Field(None, max_length=64)   # assessment


class MissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(pattern=SLUG)
    title: str = Field(min_length=3, max_length=160)
    briefing: str = Field(min_length=10, max_length=50_000)
    difficulty: str = Field("beginner", pattern="^(beginner|intermediate|advanced)$")
    lab_template: str | None = None
    objectives: list[ObjectiveIn] = Field(min_length=1, max_length=20)

    @field_validator("lab_template")
    @classmethod
    def _tpl(cls, v):
        if v and v not in TEMPLATES:
            raise ValueError("unknown lab template")
        return v or None


def _objective_config(db, o: ObjectiveIn, current: Objective | None) -> dict:
    from app.redteam.models import Scenario
    from app.vuln.models import Vulnerability
    if o.kind == "answer":
        if o.answer:
            return svc.answer_config(o.answer)
        if current and current.kind == "answer" and current.config.get("hash"):
            return current.config
        raise AppError(f"Objective '{o.title}' needs an answer", code="validation_error", status_code=422)
    if o.kind == "challenge":
        if not o.slug or not db.execute(select(Challenge.id).where(Challenge.slug == o.slug)).first():
            raise AppError(f"Objective '{o.title}': unknown challenge", code="validation_error", status_code=422)
        return {"slug": o.slug}
    if o.kind == "vuln_finding":
        if not o.code or not db.execute(select(Vulnerability.id).where(Vulnerability.code == o.code)).first():
            raise AppError(f"Objective '{o.title}': unknown vulnerability code", code="validation_error", status_code=422)
        return {"code": o.code}
    if o.kind == "assessment":
        if not o.scenario or not db.execute(select(Scenario.id).where(Scenario.code == o.scenario)).first():
            raise AppError(f"Objective '{o.title}': unknown scenario", code="validation_error", status_code=422)
        return {"scenario": o.scenario}
    if o.kind == "sensor":
        return {"sensor": o.slug if o.slug in ("zeek", "suricata") else "any"}
    if o.kind in ("alert_closed", "incident_closed"):
        return {}
    raise AppError("Unknown objective kind", code="validation_error", status_code=422)


def _apply_mission(db, m: Mission, body: MissionIn):
    for k in ("slug", "title", "briefing", "difficulty", "lab_template"):
        setattr(m, k, getattr(body, k))
    db.flush()
    existing = {o.position: o for o in svc.objectives_of(db, m.id)}
    for i, o in enumerate(body.objectives, 1):
        row = existing.pop(i, None)
        cfg = _objective_config(db, o, row)
        if row is not None and (row.kind != o.kind or row.config != cfg) and db.execute(
                select(ScoreEvent.id).where(ScoreEvent.source == "objective", ScoreEvent.ref_id == row.id).limit(1)).first():
            raise Conflict(f"Objective {i} has been met by learners and cannot change its check", code="in_use")
        row = row or Objective(mission_id=m.id, position=i)
        row.title, row.kind, row.points, row.hint, row.config = o.title, o.kind, o.points, o.hint, cfg
        db.add(row)
    for row in existing.values():
        if db.execute(select(ScoreEvent.id).where(ScoreEvent.source == "objective", ScoreEvent.ref_id == row.id).limit(1)).first():
            raise Conflict("An objective learners have met cannot be removed", code="in_use")
        db.delete(row)


@router.get("/missions/{mid}/authoring")
def mission_authoring(mid: int, db: Session = Depends(get_db), _p: Principal = MANAGE):
    m = db.get(Mission, mid)
    if not m:
        raise NotFound("Mission not found")
    return {"id": m.id, "slug": m.slug, "title": m.title, "briefing": m.briefing, "difficulty": m.difficulty, "lab_template": m.lab_template,
            "is_published": m.is_published, "is_builtin": m.is_builtin,
            "objectives": [{"title": o.title, "kind": o.kind, "points": o.points, "hint": o.hint, "answer_set": o.kind == "answer" and bool(o.config.get("hash")),
                            **{k: v for k, v in o.config.items() if k in ("slug", "code", "scenario")},
                            **({"slug": o.config.get("sensor", "any")} if o.kind == "sensor" else {})} for o in svc.objectives_of(db, m.id)]}


@router.post("/missions", status_code=201)
def create_mission(body: MissionIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    _slug_free(db, Mission, body.slug)
    m = Mission(created_by=p.id, is_published=False, is_builtin=False)
    db.add(m)
    _apply_mission(db, m, body)
    record(db, "training.mission.create", actor=p, resource_type="mission", resource_id=m.id, details={"slug": m.slug})
    db.commit()
    return {"id": m.id}


@router.put("/missions/{mid}")
def update_mission(mid: int, body: MissionIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    m = _editable(db.get(Mission, mid), "Mission")
    _slug_free(db, Mission, body.slug, m.id)
    _apply_mission(db, m, body)
    record(db, "training.mission.update", actor=p, resource_type="mission", resource_id=m.id)
    db.commit()
    return {"id": m.id}


@router.post("/missions/{mid}/publish")
def publish_mission(mid: int, body: PublishIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    m = db.get(Mission, mid)
    if not m:
        raise NotFound("Mission not found")
    m.is_published = body.is_published
    record(db, "training.mission.publish", actor=p, resource_type="mission", resource_id=m.id, details={"is_published": m.is_published})
    db.commit()
    return {"id": m.id, "is_published": m.is_published}


@router.delete("/missions/{mid}", status_code=204)
def delete_mission(mid: int, db: Session = Depends(get_db), p: Principal = MANAGE):
    m = _editable(db.get(Mission, mid), "Mission")
    ids = [o.id for o in svc.objectives_of(db, m.id)]
    if ids and db.execute(select(ScoreEvent.id).where(ScoreEvent.source == "objective", ScoreEvent.ref_id.in_(ids)).limit(1)).first():
        raise Conflict("Learners have met objectives of this mission; unpublish it instead", code="in_use")
    record(db, "training.mission.delete", actor=p, resource_type="mission", resource_id=m.id, details={"slug": m.slug})
    db.delete(m)
    db.commit()



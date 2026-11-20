"""Practice: CTF challenges, missions and scoring.

Integrity rules:
- Flags and mission answers are stored only as salted SHA-256 hashes; submissions store only the hash of the attempt.
- Every point comes from the append-only `score_events` ledger (unique per user/source/ref, so nothing scores twice).
- Platform-verified objectives (challenge, vuln_finding, assessment, sensor, alert/incident closed) are checked against real records owned by
  the learner; nothing is self-declared.
- Authors (and training managers) may test their own challenges but never score on them.
"""
import hashlib
import io
import secrets
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import utcnow
from app.core.errors import AppError, Forbidden, NotFound, TooManyRequests
from app.core.redis_client import rate_limiter
from app.core.storage import get_storage
from app.training import content, content_id
from app.training.models import Challenge, Hint, HintUnlock, Mission, Objective, ScoreEvent, Submission

WRONG_LIMIT, WRONG_WINDOW = 10, 300  # wrong flag attempts per user per challenge
MIN_SHARE = 0.10  # hints can never reduce a solve below 10 % of its value


# ------------------------------------------------------------------ hashing
def normalise(value: str, case_sensitive: bool) -> str:
    v = (value or "").strip()
    return v if case_sensitive else v.lower()


def hash_secret(salt: str, value: str, case_sensitive: bool) -> str:
    return hashlib.sha256((salt + normalise(value, case_sensitive)).encode()).hexdigest()


def set_flag(ch: Challenge, flag: str) -> None:
    if not flag or len(flag.strip()) < 3:
        raise AppError("The flag must be at least 3 characters", code="validation_error", status_code=422)
    ch.flag_salt = secrets.token_hex(16)
    ch.flag_hash = hash_secret(ch.flag_salt, flag, ch.case_sensitive)


def flag_matches(ch: Challenge, value: str) -> bool:
    return secrets.compare_digest(hash_secret(ch.flag_salt, value, ch.case_sensitive), ch.flag_hash)


def answer_config(answer: str, case_sensitive: bool = False) -> dict:
    salt = secrets.token_hex(16)
    return {"salt": salt, "hash": hash_secret(salt, answer, case_sensitive), "case_sensitive": case_sensitive}


def answer_matches(cfg: dict, value: str) -> bool:
    if not cfg.get("salt") or not cfg.get("hash"):
        return False
    return secrets.compare_digest(hash_secret(cfg["salt"], value, bool(cfg.get("case_sensitive"))), cfg["hash"])


# ------------------------------------------------------------------ attachments
def attachment_key(slug: str, name: str) -> str:
    return f"training/{slug}/{name}"


def store_attachment(ch: Challenge, name: str, data: bytes) -> dict:
    key = attachment_key(ch.slug, name)
    get_storage().put(key, io.BytesIO(data), len(data))
    meta = {"name": name, "key": key, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    ch.attachments = [a for a in (ch.attachments or []) if a["name"] != name] + [meta]
    return meta


# ------------------------------------------------------------------ seed
ALL_CHALLENGES = content.CHALLENGES + content_id.CHALLENGES
ALL_MISSIONS = content.MISSIONS + content_id.MISSIONS
ALL_FLAGS = {**content.FLAGS, **content_id.FLAGS}
ALL_ATTACHMENTS = {**content.ATTACHMENTS, **content_id.ATTACHMENTS}


def seed(db: Session) -> dict:
    stats = {"challenges": 0, "missions": 0}
    for c in ALL_CHALLENGES:
        row = db.execute(select(Challenge).where(Challenge.slug == c["slug"])).scalar_one_or_none()
        kind = c.get("kind", "flag")
        # rule challenges are solved by grading a rule; their flag is a random secret nobody knows
        flag = ALL_FLAGS[c["slug"]] if kind == "flag" else None
        if row is None:
            row = Challenge(slug=c["slug"], is_builtin=True, is_published=True, case_sensitive=False, attachments=[])
            db.add(row)
            stats["challenges"] += 1
        row.title, row.category, row.difficulty, row.points = c["title"], c["category"], c["difficulty"], c["points"]
        row.description, row.lab_template, row.is_builtin = c["description"], c.get("lab_template"), True
        row.kind, row.grader = kind, content_id.grader(c["slug"])
        row.flag_format = "CR{...}" if kind == "flag" else ("rule Sigma (YAML)" if kind == "sigma" else "rule YARA")
        if flag is None:
            if not row.flag_hash:
                set_flag(row, "CR{" + secrets.token_hex(16) + "}")
        elif not row.flag_hash or not flag_matches(row, flag):
            set_flag(row, flag)
        db.flush()
        hints = {h.position: h for h in db.execute(select(Hint).where(Hint.challenge_id == row.id)).scalars()}
        for i, (text, cost) in enumerate(c["hints"], 1):
            h = hints.get(i) or Hint(challenge_id=row.id, position=i)
            h.text, h.cost = text, cost
            db.add(h)
        for name, data in ALL_ATTACHMENTS.get(c["slug"], []):
            current = next((a for a in row.attachments or [] if a["name"] == name), None)
            if not current or current["sha256"] != hashlib.sha256(data).hexdigest() or not get_storage().exists(current["key"]):
                store_attachment(row, name, data)
    for m in ALL_MISSIONS:
        row = db.execute(select(Mission).where(Mission.slug == m["slug"])).scalar_one_or_none()
        if row is None:
            row = Mission(slug=m["slug"], is_builtin=True, is_published=True, title=m["title"])
            db.add(row)
            stats["missions"] += 1
        row.title, row.briefing, row.difficulty, row.lab_template, row.is_builtin = m["title"], m["briefing"], m["difficulty"], m.get("lab_template"), True
        db.flush()
        objs = {o.position: o for o in db.execute(select(Objective).where(Objective.mission_id == row.id)).scalars()}
        for i, o in enumerate(m["objectives"], 1):
            x = objs.get(i) or Objective(mission_id=row.id, position=i)
            x.title, x.kind, x.points, x.hint = o["title"], o["kind"], o["points"], o.get("hint", "")
            if o["kind"] == "answer":
                if not answer_matches(x.config or {}, o["answer"]):
                    x.config = answer_config(o["answer"])
            else:
                x.config = o["config"]
            db.add(x)
    db.flush()
    return stats


# ------------------------------------------------------------------ scoring
def _award(db: Session, p, *, source: str, ref_id: int, category: str, points: int, detail: dict, first_blood: bool = False) -> ScoreEvent | None:
    ev = ScoreEvent(user_id=p.id, source=source, ref_id=ref_id, category=category, points=points, detail=detail, first_blood=first_blood)
    try:
        with db.begin_nested():
            db.add(ev)
            db.flush()
    except IntegrityError:
        return None  # already scored (concurrent request)
    return ev


def scored(db: Session, user_id: int, source: str, ref_ids=None) -> dict[int, ScoreEvent]:
    q = select(ScoreEvent).where(ScoreEvent.user_id == user_id, ScoreEvent.source == source)
    if ref_ids is not None:
        ids = list(ref_ids)
        if not ids:
            return {}
        q = q.where(ScoreEvent.ref_id.in_(ids))
    return {e.ref_id: e for e in db.execute(q).scalars()}


def is_author(p, obj) -> bool:
    return obj.created_by == p.id


# ------------------------------------------------------------------ challenges
def visible_challenge(db: Session, p, challenge_id: int) -> Challenge:
    ch = db.get(Challenge, challenge_id)
    if not ch or not (ch.is_published or p.has("training.manage")):
        raise NotFound("Challenge not found")
    return ch


def unlocked_hints(db: Session, user_id: int, challenge_id: int) -> set[int]:
    return set(db.execute(select(HintUnlock.hint_id).join(Hint, Hint.id == HintUnlock.hint_id)
                          .where(HintUnlock.user_id == user_id, Hint.challenge_id == challenge_id)).scalars())


def hint_penalty(db: Session, user_id: int, challenge_id: int) -> int:
    return int(db.execute(select(func.coalesce(func.sum(Hint.cost), 0)).join(HintUnlock, HintUnlock.hint_id == Hint.id)
                          .where(HintUnlock.user_id == user_id, Hint.challenge_id == challenge_id)).scalar_one())


def unlock_hint(db: Session, p, challenge_id: int, hint_id: int) -> Hint:
    ch = visible_challenge(db, p, challenge_id)
    h = db.get(Hint, hint_id)
    if not h or h.challenge_id != ch.id:
        raise NotFound("Hint not found")
    if not db.execute(select(HintUnlock).where(HintUnlock.user_id == p.id, HintUnlock.hint_id == h.id)).scalar_one_or_none():
        solved = bool(scored(db, p.id, "challenge", [ch.id]))
        try:
            with db.begin_nested():
                db.add(HintUnlock(user_id=p.id, hint_id=h.id))
                db.flush()
        except IntegrityError:
            pass
        record(db, "training.hint.unlock", actor=p, resource_type="challenge", resource_id=ch.id,
               details={"hint": h.position, "cost": 0 if solved else h.cost})
    return h


def submit_flag(db: Session, p, challenge_id: int, value: str) -> dict:
    ch = visible_challenge(db, p, challenge_id)
    if not value or len(value) > 512:
        raise AppError("Enter a flag (at most 512 characters)", code="validation_error", status_code=422)
    already = scored(db, p.id, "challenge", [ch.id]).get(ch.id)
    if already:
        return {"correct": True, "already_solved": True, "points": already.points, "first_blood": already.first_blood}
    rl_key = f"ctf:{p.id}:{ch.id}"
    recent_wrong = db.execute(select(func.count()).select_from(Submission).where(
        Submission.user_id == p.id, Submission.challenge_id == ch.id, Submission.is_correct.is_(False),
        Submission.submitted_at >= utcnow() - timedelta(seconds=WRONG_WINDOW))).scalar_one()
    if recent_wrong >= WRONG_LIMIT or not rate_limiter.hit(rl_key, WRONG_LIMIT * 3, WRONG_WINDOW):
        raise TooManyRequests(f"Too many attempts. Wait a few minutes before submitting again (limit {WRONG_LIMIT} wrong attempts per {WRONG_WINDOW // 60} minutes).")
    if ch.kind != "flag":
        raise AppError("This challenge is solved by submitting a rule, not a flag", code="rule_challenge", status_code=422)
    correct = flag_matches(ch, value)
    db.add(Submission(user_id=p.id, challenge_id=ch.id, value_hash=hashlib.sha256(normalise(value, ch.case_sensitive).encode()).hexdigest(),
                      is_correct=correct))
    db.flush()
    if not correct:
        record(db, "training.flag.wrong", actor=p, resource_type="challenge", resource_id=ch.id, outcome="failure")
        return {"correct": False, "remaining_attempts": max(0, WRONG_LIMIT - recent_wrong - 1)}
    return _score_solve(db, p, ch)


def _score_solve(db: Session, p, ch: Challenge) -> dict:
    if is_author(p, ch) or not ch.is_published:
        record(db, "training.flag.test", actor=p, resource_type="challenge", resource_id=ch.id, details={"reason": "author_or_unpublished"})
        return {"correct": True, "scored": False, "reason": "Authors and unpublished challenges do not score."}
    penalty = hint_penalty(db, p.id, ch.id)
    points = max(int(round(ch.points * MIN_SHARE)), ch.points - penalty)
    first = not db.execute(select(ScoreEvent.id).where(ScoreEvent.source == "challenge", ScoreEvent.ref_id == ch.id).limit(1)).first()
    ev = _award(db, p, source="challenge", ref_id=ch.id, category=ch.category, points=points,
                detail={"title": ch.title, "base": ch.points, "hint_penalty": penalty}, first_blood=first)
    if ev is None:
        return {"correct": True, "already_solved": True}
    record(db, "training.challenge.solved", actor=p, resource_type="challenge", resource_id=ch.id,
           details={"points": points, "first_blood": first, "hint_penalty": penalty})
    return {"correct": True, "scored": True, "points": points, "first_blood": first, "hint_penalty": penalty}


MAX_RULE_SOURCE = 20_000


def _grade_sigma(grader: dict, source: str) -> dict:
    from app.blueteam import rules as rule_engine
    from app.blueteam.sigma import SigmaError, parse
    try:
        results = parse(source)
    except SigmaError as e:
        return {"ok": False, "error": str(e)}
    good = [r for r in results if r["ok"]]
    if not good:
        return {"ok": False, "error": "; ".join(f"{r['title']}: {r['error']}" for r in results)}
    events = grader["events"]
    hit: set[int] = set()
    for r in good:
        rule = r["rule"]
        matched = [e for e in events if rule_engine.matches(rule["conditions"], e)]
        if rule["kind"] == "threshold":
            th = rule["threshold"]
            groups: dict = {}
            for e in matched:
                groups.setdefault(e.get(th["group_by"]), []).append(e)
            matched = [e for g in groups.values() if len(g) >= th["count"] for e in g]
        hit |= {e["id"] for e in matched}
    bad = set(grader["malicious"])
    visible = {e["id"] for e in events if e["id"] < 100}
    return {"ok": True, "rules": len(good), "detected": len(hit & bad), "malicious_total": len(bad),
            "false_positives": len(hit - bad),
            "missed_visible": sorted((bad - hit) & visible), "false_positive_visible": sorted((hit - bad) & visible),
            "hidden_passed": all((e["id"] in hit) == (e["id"] in bad) for e in events if e["id"] not in visible),
            "solved": hit == bad}


def _grade_yara(grader: dict, source: str) -> dict:
    import base64

    from app.malware import yara_engine
    try:
        yara_engine.validate(source)
        import yara
        compiled = yara.compile(source=source, includes=False)
    except yara_engine.RuleError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:  # noqa: BLE001 - any compile failure is the learner's syntax problem
        return {"ok": False, "error": f"YARA: {e}"}
    results, solved = [], True
    for s in grader["samples"]:
        got = bool(compiled.match(data=base64.b64decode(s["b64"]), timeout=5))
        okay = got == s["match"]
        solved &= okay
        if not s["hidden"]:
            results.append({"name": s["name"], "should_match": s["match"], "matched": got, "ok": okay})
    hidden = [s for s in grader["samples"] if s["hidden"]]
    return {"ok": True, "samples": results, "hidden_total": len(hidden),
            "hidden_passed": all(bool(compiled.match(data=base64.b64decode(s["b64"]), timeout=5)) == s["match"] for s in hidden),
            "solved": solved}


def submit_rule(db: Session, p, challenge_id: int, source: str) -> dict:
    """Grade a Sigma or YARA rule against the challenge's events/samples (including hidden ones) and score a full pass."""
    ch = visible_challenge(db, p, challenge_id)
    if ch.kind not in ("sigma", "yara") or not ch.grader:
        raise AppError("This challenge is solved with a flag", code="flag_challenge", status_code=422)
    if not source or not source.strip() or len(source) > MAX_RULE_SOURCE:
        raise AppError(f"Enter a rule (at most {MAX_RULE_SOURCE // 1000} KB)", code="validation_error", status_code=422)
    already = scored(db, p.id, "challenge", [ch.id]).get(ch.id)
    if not rate_limiter.hit(f"ctfrule:{p.id}:{ch.id}", 30, WRONG_WINDOW):
        raise TooManyRequests("Too many attempts. Wait a few minutes before submitting again.")
    report = _grade_sigma(ch.grader, source) if ch.kind == "sigma" else _grade_yara(ch.grader, source)
    solved = bool(report.get("solved"))
    db.add(Submission(user_id=p.id, challenge_id=ch.id, value_hash=hashlib.sha256(source.encode()).hexdigest(), is_correct=solved))
    db.flush()
    record(db, "training.rule.graded", actor=p, resource_type="challenge", resource_id=ch.id, outcome="success" if solved else "failure",
           details={"kind": ch.kind, "solved": solved})
    out = {"report": report, "correct": solved}
    if already:
        return {**out, "already_solved": True, "points": already.points}
    if solved:
        out.update(_score_solve(db, p, ch))
    return out


def solve_counts(db: Session) -> dict[int, int]:
    return dict(db.execute(select(ScoreEvent.ref_id, func.count()).where(ScoreEvent.source == "challenge").group_by(ScoreEvent.ref_id)).all())




# ------------------------------------------------------------------ missions
def visible_mission(db: Session, p, mission_id: int) -> Mission:
    m = db.get(Mission, mission_id)
    if not m or not (m.is_published or p.has("training.manage")):
        raise NotFound("Mission not found")
    return m


def objectives_of(db: Session, mission_id: int) -> list[Objective]:
    return list(db.execute(select(Objective).where(Objective.mission_id == mission_id).order_by(Objective.position, Objective.id)).scalars())


def _verify(db: Session, user_id: int, o: Objective) -> tuple[bool, str]:
    """Check a platform-verified objective against real records of this learner. Returns (met, evidence)."""
    cfg = o.config or {}
    if o.kind == "challenge":
        ch = db.execute(select(Challenge).where(Challenge.slug == cfg.get("slug"))).scalar_one_or_none()
        if not ch:
            return False, "challenge not found"
        ev = scored(db, user_id, "challenge", [ch.id]).get(ch.id)
        return (True, f"Solved '{ch.title}' at {ev.at.isoformat(timespec='seconds')}Z") if ev else (False, f"'{ch.title}' not solved yet")
    if o.kind == "vuln_finding":
        from app.cyber_range.models import Lab
        from app.vuln.models import ScanFinding, Vulnerability
        row = db.execute(select(ScanFinding.id, Lab.name, ScanFinding.node_key).join(Vulnerability, Vulnerability.id == ScanFinding.vulnerability_id)
                         .join(Lab, Lab.id == ScanFinding.lab_id)
                         .where(Vulnerability.code == cfg.get("code"), Lab.owner_id == user_id).limit(1)).first()
        return (True, f"Finding #{row[0]} on {row[2]} in lab '{row[1]}'") if row else (False, f"no {cfg.get('code')} finding in a lab you own")
    if o.kind == "assessment":
        from app.redteam.models import Assessment, Scenario
        row = db.execute(select(Assessment.id, Assessment.title).join(Scenario, Scenario.id == Assessment.scenario_id)
                         .where(Scenario.code == cfg.get("scenario"), Assessment.requested_by == user_id, Assessment.status == "completed").limit(1)).first()
        return (True, f"Assessment #{row[0]} '{row[1]}' completed") if row else (False, f"no completed {cfg.get('scenario')} assessment requested by you")
    if o.kind == "sensor":
        from app.cyber_range.models import Lab, LabSensor
        q = select(LabSensor.kind, Lab.name).join(Lab, Lab.id == LabSensor.lab_id).where(Lab.owner_id == user_id, LabSensor.status == "running")
        if cfg.get("sensor") in ("zeek", "suricata"):
            q = q.where(LabSensor.kind == cfg["sensor"])
        row = db.execute(q.limit(1)).first()
        return (True, f"{row[0]} sensor running in lab '{row[1]}'") if row else (False, "no running sensor in a lab you own")
    if o.kind == "alert_closed":
        from app.blueteam.models import Alert
        row = db.execute(select(Alert.id, Alert.status).where(Alert.assignee_id == user_id, Alert.status.in_(("resolved", "false_positive")),
                                                              Alert.resolution.is_not(None), Alert.resolution != "").limit(1)).first()
        return (True, f"Alert #{row[0]} closed as {row[1]}") if row else (False, "no alert assigned to you has been closed with a resolution yet")
    if o.kind == "incident_closed":
        from app.blueteam.models import Incident
        row = db.execute(select(Incident.id, Incident.title).where((Incident.owner_id == user_id) | (Incident.created_by == user_id),
                                                                   Incident.status == "closed").limit(1)).first()
        return (True, f"Incident #{row[0]} '{row[1]}' closed") if row else (False, "no incident owned or created by you is closed yet")
    return False, "answer required"


def check_mission(db: Session, p, mission_id: int) -> list[dict]:
    """Verify every platform-checked objective and score the ones newly met."""
    m = visible_mission(db, p, mission_id)
    objs = objectives_of(db, m.id)
    done = scored(db, p.id, "objective", [o.id for o in objs])
    out = []
    for o in objs:
        if o.id in done:
            out.append({"id": o.id, "met": True, "evidence": done[o.id].detail.get("evidence", ""), "new": False})
            continue
        if o.kind == "answer":
            out.append({"id": o.id, "met": False, "evidence": "answer required", "new": False})
            continue
        met, evidence = _verify(db, p.id, o)
        new = False
        if met and m.is_published and not is_author(p, m):
            new = _award(db, p, source="objective", ref_id=o.id, category="mission", points=o.points,
                         detail={"mission": m.title, "objective": o.title, "evidence": evidence}) is not None
            if new:
                record(db, "training.objective.met", actor=p, resource_type="mission", resource_id=m.id, details={"objective": o.id, "evidence": evidence})
        out.append({"id": o.id, "met": met, "evidence": evidence, "new": new})
    return out


def answer_objective(db: Session, p, mission_id: int, objective_id: int, value: str) -> dict:
    m = visible_mission(db, p, mission_id)
    o = db.get(Objective, objective_id)
    if not o or o.mission_id != m.id or o.kind != "answer":
        raise NotFound("Objective not found")
    if not value or len(value) > 512:
        raise AppError("Enter an answer (at most 512 characters)", code="validation_error", status_code=422)
    if scored(db, p.id, "objective", [o.id]):
        return {"correct": True, "already_met": True}
    if not rate_limiter.hit(f"mission:{p.id}:{o.id}", WRONG_LIMIT, WRONG_WINDOW):
        raise TooManyRequests("Too many attempts. Wait a few minutes before answering again.")
    if not answer_matches(o.config or {}, value):
        record(db, "training.answer.wrong", actor=p, resource_type="mission", resource_id=m.id, outcome="failure", details={"objective": o.id})
        return {"correct": False}
    if not m.is_published or is_author(p, m):
        return {"correct": True, "scored": False, "reason": "Authors and unpublished missions do not score."}
    _award(db, p, source="objective", ref_id=o.id, category="mission", points=o.points,
           detail={"mission": m.title, "objective": o.title, "evidence": "correct answer submitted"})
    record(db, "training.objective.met", actor=p, resource_type="mission", resource_id=m.id, details={"objective": o.id, "evidence": "answer"})
    return {"correct": True, "scored": True, "points": o.points}


def mission_progress(db: Session, user_id: int) -> dict[int, dict]:
    rows = db.execute(select(Objective.mission_id, func.count(Objective.id), func.count(ScoreEvent.id))
                      .outerjoin(ScoreEvent, (ScoreEvent.ref_id == Objective.id) & (ScoreEvent.source == "objective") & (ScoreEvent.user_id == user_id))
                      .group_by(Objective.mission_id)).all()
    return {mid: {"objectives": total, "met": met} for mid, total, met in rows}


# ------------------------------------------------------------------ practice labs
def launch_practice_lab(db: Session, p, *, template: str, title: str) -> dict:
    """Create the learner's own isolated lab from a fixed builtin template and deploy it via the normal lab engine (same
    safety checks, quotas and kill switch). Only `lab.operate` is needed: the learner gets a private copy of a vetted
    template, not general topology-editing rights."""
    from app.cyber_range import service as labs
    from app.network import service as networks
    from app.network.templates import TEMPLATES
    if not p.has("lab.operate"):
        raise Forbidden("Practice labs need permission to operate labs", details={"missing": ["lab.operate"]})
    if template not in TEMPLATES:
        raise NotFound("Unknown lab template")
    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    name = f"Latihan: {title}"[:100] + f" {stamp}"
    net = networks.create_from_template(db, p, name=name, description=f"Lab latihan untuk '{title}'", visibility="private", template=template,
                                       avoid_running=True)
    db.flush()
    lab = labs.create_lab(db, p, network_id=net.id, name=name, description=f"Lab latihan terisolasi untuk '{title}'")
    db.commit()
    inst = labs.deploy(db, p, lab.id)
    return {"lab_id": lab.id, "network_id": net.id, "instance_status": inst.status}


# ------------------------------------------------------------------ summary


def my_summary(db: Session, p) -> dict:
    total = int(db.execute(select(func.coalesce(func.sum(ScoreEvent.points), 0)).where(ScoreEvent.user_id == p.id)).scalar_one())
    by_source = dict(db.execute(select(ScoreEvent.source, func.count()).where(ScoreEvent.user_id == p.id).group_by(ScoreEvent.source)).all())
    by_cat = dict(db.execute(select(ScoreEvent.category, func.sum(ScoreEvent.points)).where(ScoreEvent.user_id == p.id).group_by(ScoreEvent.category)).all())
    missions = mission_progress(db, p.id)
    published = set(db.execute(select(Mission.id).where(Mission.is_published.is_(True))).scalars())
    recent = db.execute(select(ScoreEvent).where(ScoreEvent.user_id == p.id).order_by(ScoreEvent.at.desc()).limit(10)).scalars().all()
    return {"points": total, "solves": by_source.get("challenge", 0), "objectives_met": by_source.get("objective", 0),
            "missions_completed": sum(1 for mid, v in missions.items() if mid in published and v["objectives"] and v["met"] == v["objectives"]),
            "by_category": {k: int(v) for k, v in by_cat.items()},
            "recent": [{"source": e.source, "points": e.points, "category": e.category, "first_blood": e.first_blood, "detail": e.detail, "at": e.at} for e in recent]}


def counts(db: Session) -> dict:
    return {"challenges_published": db.execute(select(func.count()).select_from(Challenge).where(Challenge.is_published.is_(True))).scalar_one(),
            "missions_published": db.execute(select(func.count()).select_from(Mission).where(Mission.is_published.is_(True))).scalar_one(),
            "ctf_solves": db.execute(select(func.count()).select_from(ScoreEvent).where(ScoreEvent.source == "challenge")).scalar_one()}

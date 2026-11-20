"""SOAR playbook engine.

Rules this module keeps:
* Only actions from ACTIONS can appear in a playbook. There is no script, shell or HTTP step.
* Every action that changes state outside the alert's own triage fields ("approval": True) pauses the run until a person
  with incident.respond (the local operator) approves that exact step. Approval is recorded with the time and note, and audited.
* Containment is reversible and stays inside the platform: a watchlist indicator (can be retired) or stopping a lab
  (can be started again). Nothing reaches production networks or hosts.
* Automatic triggers run only the non-approval steps (collect, enrich, acknowledge, note) and then wait.
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam import service as soc
from app.blueteam.models import Alert, AlertEvent, Incident, SecurityEvent
from app.core.database import utcnow
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.logging import log
from app.soar.models import RUN_OPEN, Playbook, PlaybookRun

CONTAINMENT_SOURCE = "SOAR containment watchlist"
MAX_STEPS = 12
MAX_AUTO_RUNS_PER_BATCH = 20


class StepError(Exception):
    pass


# ------------------------------------------------------------------ action catalogue
def _p_none(params: dict) -> dict:
    if params:
        raise ValueError("this step takes no parameters")
    return {}


def _p_note(params: dict) -> dict:
    text = str(params.get("text", "")).strip()
    if not text or len(text) > 2000 or set(params) - {"text"}:
        raise ValueError("params.text (1-2000 characters) is required")
    return {"text": text}


def _p_close(params: dict) -> dict:
    st = params.get("status", "false_positive")
    if st not in ("resolved", "false_positive") or set(params) - {"status", "resolution"}:
        raise ValueError("status must be resolved or false_positive")
    res = str(params.get("resolution", "")).strip() or "Closed by SOAR playbook after human approval."
    return {"status": st, "resolution": res[:2000]}


def _p_watch(params: dict) -> dict:
    if set(params) - {"fields", "days"}:
        raise ValueError("only params.fields and params.days are allowed")
    fields = params.get("fields", ["src_ip"])
    if not isinstance(fields, list) or not fields or any(f not in ("src_ip", "dst_ip") for f in fields):
        raise ValueError("fields must be a list of src_ip / dst_ip")
    days = int(params.get("days", 7))
    if not 1 <= days <= 90:
        raise ValueError("days must be 1-90")
    return {"fields": sorted(set(fields)), "days": days}


def _collect(db: Session, run: PlaybookRun, alert: Alert, p, params) -> dict:
    rows = db.execute(select(SecurityEvent.src_ip, SecurityEvent.dst_ip, SecurityEvent.host, SecurityEvent.user, SecurityEvent.signature)
                      .join(AlertEvent, AlertEvent.event_id == SecurityEvent.id).where(AlertEvent.alert_id == alert.id).limit(500)).all()
    facts = {"src_ip": sorted({r.src_ip for r in rows if r.src_ip})[:50], "dst_ip": sorted({r.dst_ip for r in rows if r.dst_ip})[:50],
             "host": sorted({r.host for r in rows if r.host})[:50], "user": sorted({r.user for r in rows if r.user})[:50],
             "signature": sorted({r.signature for r in rows if r.signature})[:20], "events": len(rows)}
    run.facts = {**(run.facts or {}), **facts}
    return {k: v for k, v in facts.items()}


def _enrich(db: Session, run: PlaybookRun, alert: Alert, p, params) -> dict:
    from app.core import geoip
    from app.intel.service import lookup_values
    f = run.facts or {}
    if "src_ip" not in f:
        _collect(db, run, alert, p, {})
        f = run.facts
    values = (f.get("src_ip") or []) + (f.get("dst_ip") or []) + (f.get("host") or [])
    intel = [{"type": i.type, "value": i.value, "confidence": i.confidence, "severity": i.severity, "tags": i.tags or [], "is_demo": i.is_demo}
             for i in lookup_values(db, values)[:50]]
    geo = []
    for ip in (f.get("src_ip") or [])[:20]:
        g = geoip.lookup(ip)
        geo.append({"ip": ip, "private": g.get("private"), "country": g.get("country"), "city": g.get("city")})
    labs = _labs_for(db, (f.get("src_ip") or []) + (f.get("dst_ip") or []))
    run.facts = {**f, "intel": intel, "geo": geo, "labs": [{"lab_id": lab_id, "ips": ips} for lab_id, ips in labs.items()]}
    return {"intel_matches": len(intel), "intel": intel[:10], "geo": geo, "labs": run.facts["labs"]}


def _ack(db: Session, run: PlaybookRun, alert: Alert, p, params) -> dict:
    if alert.status != "new":
        return {"changed": False, "status": alert.status}
    alert.status, alert.acknowledged_at = "acknowledged", alert.acknowledged_at or utcnow()
    return {"changed": True, "status": alert.status}


def _note(db: Session, run: PlaybookRun, alert: Alert, p, params) -> dict:
    if alert.incident_id:
        inc = db.get(Incident, alert.incident_id)
        soc.entry(db, inc, p, "note", f"[SOAR {run.id}] {params['text']}", {"soar_run": run.id})
        return {"incident_id": inc.id}
    return {"incident_id": None, "note": "no incident yet; the note is kept on this run"}


def _escalate(db: Session, run: PlaybookRun, alert: Alert, p, params) -> dict:
    if alert.incident_id:
        return {"incident_id": alert.incident_id, "created": False}
    inc = Incident(title=alert.title[:255], severity=alert.severity, status="open", owner_id=p.id, created_by=p.id, is_demo=alert.is_demo,
                   summary=f"Opened by SOAR run #{run.id} from alert #{alert.id} ({alert.rule.code}) after approval by {p.username}.")
    db.add(inc)
    db.flush()
    soc.entry(db, inc, p, "created", inc.summary, {"soar_run": run.id})
    soc.link_alerts(db, p, inc, [alert.id])
    record(db, "soc.incident.create", actor=p, resource_type="incident", resource_id=inc.id, details={"from_alert": alert.id, "soar_run": run.id})
    return {"incident_id": inc.id, "created": True}


def _watchlist(db: Session, run: PlaybookRun, alert: Alert, p, params) -> dict:
    from datetime import timedelta

    from app.intel import service as intel
    f = run.facts or {}
    if "src_ip" not in f:
        f = {**f, **_collect(db, run, alert, p, {})}
    ips = sorted({ip for fld in params["fields"] for ip in (f.get(fld) or [])})[:50]
    if not ips:
        raise StepError("no IP addresses were collected from this alert")
    src = intel.source(db, CONTAINMENT_SOURCE + (" (DEMO)" if alert.is_demo else ""), "manual", demo=alert.is_demo,
                       description="Addresses placed on watch by approved SOAR runs. Retire an indicator to lift the watch.")
    exp = utcnow() + timedelta(days=params["days"])
    items = [{"type": "ip", "value": ip, "confidence": 90, "severity": max(alert.severity, 3), "tags": ["soar", f"alert-{alert.id}"] + (["DEMO"] if alert.is_demo else []),
              "description": f"SOAR run #{run.id} (alert #{alert.id}), approved by {p.username}", "valid_until": exp} for ip in ips]
    res = intel.upsert(db, src, items, p.id)
    if res["errors"]:
        raise StepError("; ".join(str(e) for e in res["errors"][:3]))
    record(db, "intel.indicator.watchlist", actor=p, resource_type="soar_run", resource_id=run.id, details={"ips": ips, "days": params["days"]})
    return {"watchlisted": ips, "created": res["created"], "updated": res["updated"], "expires_at": exp}


def _labs_for(db: Session, ips: list[str]) -> dict[int, list[str]]:
    from app.cyber_range.models import LabContainer, LabInstance
    want = set(ips)
    if not want:
        return {}
    out: dict[int, set] = {}
    rows = db.execute(select(LabInstance.lab_id, LabContainer.addresses).join(LabContainer, LabContainer.instance_id == LabInstance.id)
                      .where(LabInstance.status == "running")).all()
    for lab_id, addrs in rows:
        hit = want & set((addrs or {}).values())
        if hit:
            out.setdefault(lab_id, set()).update(hit)
    return {k: sorted(v) for k, v in out.items()}


def _stop_lab(db: Session, run: PlaybookRun, alert: Alert, p, params) -> dict:
    """Same checks as the lab Stop button (the approver must be allowed to operate the lab); dispatch happens after commit."""
    from app.core.database import on_commit
    from app.cyber_range import runtime
    from app.cyber_range import service as labs
    f = run.facts or {}
    labs_hit = _labs_for(db, (f.get("src_ip") or []) + (f.get("dst_ip") or []))
    if not labs_hit:
        raise StepError("no running lab owns the addresses in this alert")
    stopped, errors, to_dispatch = [], [], []
    for lab_id in sorted(labs_hit):
        try:
            lab = labs.get_lab(db, p, lab_id, operate=True, lock=True)
            inst = labs.current_instance(db, lab, lock=True)
            if inst is None or inst.status != "running":
                raise Conflict("lab is not running")
            inst.status = "stopping"
            labs._event(db, lab, inst, "lab.stop.requested", f"Stop requested by {p.username} via SOAR run #{run.id}")
            record(db, "lab.stop", actor=p, resource_type="lab", resource_id=lab.id, details={"instance": inst.id, "soar_run": run.id})
            stopped.append(lab_id)
            to_dispatch.append(inst.id)
        except AppError as e:
            errors.append({"lab_id": lab_id, "error": e.message})
    if not stopped:
        raise StepError("; ".join(f"lab {e['lab_id']}: {e['error']}" for e in errors))

    def _go():
        for iid in to_dispatch:
            runtime.dispatch(iid, runtime.OPS["stopping"])

    on_commit(db, _go)
    return {"stopped": stopped, "errors": errors}


def _close(db: Session, run: PlaybookRun, alert: Alert, p, params) -> dict:
    old = alert.status
    alert.status, alert.resolution, alert.closed_at = params["status"], f"[SOAR {run.id}] {params['resolution']}", utcnow()
    alert.acknowledged_at = alert.acknowledged_at or utcnow()
    record(db, "soc.alert.update", actor=p, resource_type="alert", resource_id=alert.id, details={"status": [old, alert.status], "soar_run": run.id})
    if alert.incident_id:
        soc.entry(db, db.get(Incident, alert.incident_id), p, "alert_updated", f"Alert #{alert.id} {alert.status}", {"alert_id": alert.id, "soar_run": run.id})
    return {"status": alert.status}


ACTIONS: dict[str, dict] = {
    "collect_iocs": {"approval": False, "params": _p_none, "run": _collect, "label": "Kumpulkan observable dari event alert"},
    "enrich": {"approval": False, "params": _p_none, "run": _enrich, "label": "Perkaya dengan threat intel, GeoIP dan lab terkait"},
    "ack_alert": {"approval": False, "params": _p_none, "run": _ack, "label": "Tandai alert sebagai diakui"},
    "add_note": {"approval": False, "params": _p_note, "run": _note, "label": "Tambah catatan ke timeline insiden"},
    "escalate_incident": {"approval": True, "params": _p_none, "run": _escalate, "label": "Buat insiden dan tautkan alert"},
    "watchlist_ip": {"approval": True, "params": _p_watch, "run": _watchlist, "label": "Masukkan IP ke watchlist intel (berlaku sementara)"},
    "stop_lab": {"approval": True, "params": _p_none, "run": _stop_lab, "label": "Hentikan lab yang memiliki alamat tersebut (dapat dijalankan lagi)"},
    "close_alert": {"approval": True, "params": _p_close, "run": _close, "label": "Tutup alert (resolved / false positive)"},
}


def catalogue() -> list[dict]:
    return [{"action": k, "approval": v["approval"], "label": v["label"]} for k, v in ACTIONS.items()]


# ------------------------------------------------------------------ validation and seed
def validate_playbook(trigger: dict, steps: list[dict]) -> tuple[dict, list[dict]]:
    if not isinstance(trigger, dict) or trigger.get("mode") not in ("manual", "auto"):
        raise AppError("trigger.mode must be manual or auto", code="validation_error", status_code=422)
    extra = set(trigger) - {"mode", "rule_codes", "min_severity"}
    if extra:
        raise AppError(f"Unknown trigger fields: {', '.join(sorted(extra))}", code="validation_error", status_code=422)
    codes = trigger.get("rule_codes") or []
    if not isinstance(codes, list) or len(codes) > 50 or not all(isinstance(c, str) and 0 < len(c) <= 40 for c in codes):
        raise AppError("trigger.rule_codes must be a list of rule codes", code="validation_error", status_code=422)
    sev = int(trigger.get("min_severity", 3))
    if not 0 <= sev <= 4:
        raise AppError("trigger.min_severity must be 0-4", code="validation_error", status_code=422)
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_STEPS:
        raise AppError(f"A playbook needs 1-{MAX_STEPS} steps", code="validation_error", status_code=422)
    out = []
    for i, s in enumerate(steps):
        if not isinstance(s, dict) or s.get("action") not in ACTIONS or set(s) - {"action", "params"}:
            raise AppError(f"Step {i + 1}: unknown action (allowed: {', '.join(ACTIONS)})", code="validation_error", status_code=422)
        try:
            params = ACTIONS[s["action"]]["params"](s.get("params") or {})
        except (ValueError, TypeError) as e:
            raise AppError(f"Step {i + 1} ({s['action']}): {e}", code="validation_error", status_code=422) from None
        out.append({"action": s["action"], "params": params})
    return {"mode": trigger["mode"], "rule_codes": sorted(set(codes)), "min_severity": sev}, out


BUILTIN = [
    ("PB-TRIAGE-01", "Triage otomatis alert tinggi",
     "Saat alert high/critical baru muncul: kumpulkan observable, perkaya dengan intel dan GeoIP, akui alert. "
     "Pembuatan insiden menunggu persetujuan analis.",
     {"mode": "auto", "rule_codes": [], "min_severity": 3},
     [{"action": "collect_iocs"}, {"action": "enrich"}, {"action": "ack_alert"}, {"action": "escalate_incident"}], False),
    ("PB-CONTAIN-01", "Kontainmen lab (watchlist + hentikan lab)",
     "Untuk serangan di lab: perkaya, lalu dengan persetujuan masukkan IP penyerang ke watchlist intel 7 hari dan hentikan lab terkait. "
     "Kedua langkah dapat dibatalkan (retire indikator, jalankan lab lagi).",
     {"mode": "manual", "rule_codes": [], "min_severity": 0},
     [{"action": "collect_iocs"}, {"action": "enrich"}, {"action": "escalate_incident"}, {"action": "watchlist_ip", "params": {"fields": ["src_ip"], "days": 7}},
      {"action": "stop_lab"}, {"action": "add_note", "params": {"text": "Kontainmen lab selesai melalui playbook PB-CONTAIN-01."}}], True),
    ("PB-FP-01", "Tutup sebagai false positive",
     "Kumpulkan dan perkaya bukti, lalu setelah disetujui tutup alert sebagai false positive dengan catatan.",
     {"mode": "manual", "rule_codes": [], "min_severity": 0},
     [{"action": "collect_iocs"}, {"action": "enrich"}, {"action": "close_alert", "params": {"status": "false_positive"}}], True),
]


def seed(db: Session) -> dict:
    n = 0
    for code, name, desc, trig, steps, enabled in BUILTIN:
        pb = db.execute(select(Playbook).where(Playbook.code == code)).scalar_one_or_none()
        t, s = validate_playbook(trig, steps)
        if pb is None:
            db.add(Playbook(code=code, name=name, description=desc, trigger=t, steps=s, is_enabled=enabled, builtin=True))
            n += 1
        else:
            pb.name, pb.description, pb.steps = name, desc, s
    db.flush()
    return {"playbooks_created": n}


# ------------------------------------------------------------------ execution
def _step_view(steps: list[dict]) -> list[dict]:
    return [{"action": s["action"], "params": s.get("params") or {}, "approval": ACTIONS[s["action"]]["approval"], "status": "pending"} for s in steps]


def start(db: Session, pb: Playbook, alert: Alert, p, trigger: str = "manual") -> PlaybookRun:
    if not pb.is_enabled:
        raise Conflict("This playbook is disabled")
    dup = db.execute(select(PlaybookRun.id).where(PlaybookRun.playbook_id == pb.id, PlaybookRun.alert_id == alert.id,
                                                  PlaybookRun.status.in_(RUN_OPEN))).scalar_one_or_none()
    if dup:
        raise Conflict(f"Run #{dup} of this playbook is still open for this alert", code="run_open")
    run = PlaybookRun(playbook_id=pb.id, alert_id=alert.id, status="running", trigger=trigger, current_step=0, steps=_step_view(pb.steps), facts={},
                      is_demo=alert.is_demo, requested_by=getattr(p, "id", None))
    db.add(run)
    pb.runs_total += 1
    db.flush()
    record(db, "soar.run.start", actor=p, actor_label=None if p else "system:soar", resource_type="soar_run", resource_id=run.id,
           details={"playbook": pb.code, "alert": alert.id, "trigger": trigger})
    advance(db, run, p)
    return run


def _set_step(run: PlaybookRun, i: int, **kw) -> None:
    steps = [dict(s) for s in run.steps]
    steps[i] = {**steps[i], **kw}
    run.steps = steps   # reassign so the JSON column is flagged dirty


def advance(db: Session, run: PlaybookRun, p, approved_step: int | None = None) -> None:
    """Run steps from current_step until the end, a failure, or a step that needs approval."""
    alert = db.get(Alert, run.alert_id)
    while run.current_step < len(run.steps):
        i = run.current_step
        step = run.steps[i]
        spec = ACTIONS[step["action"]]
        if spec["approval"] and approved_step != i:
            run.status = "awaiting_approval"
            _set_step(run, i, status="awaiting_approval")
            return
        actor = p
        if spec["approval"] and p is None:
            raise Forbidden("Approval steps need a person")
        try:
            with db.begin_nested():
                result = spec["run"](db, run, alert, actor, step.get("params") or {})
        except StepError as e:
            _set_step(run, i, status="failed", error=str(e)[:500], at=utcnow().isoformat())
            run.status, run.error, run.finished_at = "failed", f"step {i + 1} ({step['action']}): {e}"[:2000], utcnow()
            record(db, "soar.step", outcome="failure", actor=p, actor_label=None if p else "system:soar", resource_type="soar_run", resource_id=run.id,
                   details={"step": i + 1, "action": step["action"], "error": str(e)[:300]})
            return
        _set_step(run, i, status="done", result=_jsonable(result), at=utcnow().isoformat(), by=getattr(p, "username", None) or "system")
        record(db, "soar.step", actor=p, actor_label=None if p else "system:soar", resource_type="soar_run", resource_id=run.id,
               details={"step": i + 1, "action": step["action"], "approved": spec["approval"]})
        run.current_step = i + 1
        approved_step = None
    run.status, run.finished_at = "completed", utcnow()


def _jsonable(v):
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return v


def get_run(db: Session, run_id: int, lock: bool = False) -> PlaybookRun:
    q = select(PlaybookRun).where(PlaybookRun.id == run_id)
    run = db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
    if not run:
        raise NotFound("Playbook run not found")
    return run


def decide(db: Session, run: PlaybookRun, p, step: int, approve: bool, note: str) -> PlaybookRun:
    if run.status != "awaiting_approval":
        raise Conflict("This run is not waiting for approval", code="invalid_state")
    if step != run.current_step:
        raise Conflict("That step is not the one waiting for approval; reload the run", code="stale_step")
    i = run.current_step
    _set_step(run, i, decision={"approved": approve, "by": p.username, "at": utcnow().isoformat(), "note": note})
    record(db, "soar.approval", actor=p, resource_type="soar_run", resource_id=run.id,
           details={"step": i + 1, "action": run.steps[i]["action"], "approved": approve, "note": note[:300]})
    if not approve:
        _set_step(run, i, status="rejected")
        steps = [dict(s) for s in run.steps]
        for s in steps[i + 1:]:
            s["status"] = "skipped"
        run.steps = steps
        run.status, run.finished_at = "rejected", utcnow()
        return run
    run.status = "running"
    advance(db, run, p, approved_step=i)
    return run


def cancel(db: Session, run: PlaybookRun, p) -> PlaybookRun:
    if run.status not in RUN_OPEN:
        raise Conflict("Only open runs can be cancelled", code="invalid_state")
    steps = [dict(s) for s in run.steps]
    for s in steps[run.current_step:]:
        s["status"] = "skipped"
    run.steps, run.status, run.finished_at = steps, "cancelled", utcnow()
    record(db, "soar.run.cancel", actor=p, resource_type="soar_run", resource_id=run.id)
    return run


def auto_trigger(db: Session, alerts: list[dict]) -> int:
    """Start matching auto playbooks for newly created alerts. Called inside the ingest transaction; never raises."""
    new = [a for a in alerts if a.get("created")]
    if not new:
        return 0
    pbs = [pb for pb in db.execute(select(Playbook).where(Playbook.is_enabled.is_(True))).scalars() if pb.trigger.get("mode") == "auto"]
    if not pbs:
        return 0
    n = 0
    for a in new:
        if n >= MAX_AUTO_RUNS_PER_BATCH:
            break
        alert = db.get(Alert, a["id"])
        for pb in pbs:
            t = pb.trigger
            if alert.severity < t.get("min_severity", 3) or (t.get("rule_codes") and alert.rule.code not in t["rule_codes"]):
                continue
            try:
                with db.begin_nested():
                    start(db, pb, alert, None, trigger="auto")
                n += 1
            except Exception:  # noqa: BLE001 - a playbook must never break ingest
                log.exception("soar_auto_trigger_failed", playbook=pb.code, alert=alert.id)
    return n

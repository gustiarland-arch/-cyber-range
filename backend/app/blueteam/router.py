import asyncio
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case, func, literal_column, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam import service as svc
from app.blueteam import sigma
from app.blueteam.attack import TACTICS, TECHNIQUES, technique_name
from app.blueteam.models import (ALERT_OPEN, ALERT_STATUSES, INCIDENT_STATUSES, SOURCE_KINDS, Alert, AlertEvent, DetectionRule, Incident,
                                 IncidentEntry, LogSource, SecurityEvent)
from app.blueteam.normalize import split_lines
from app.blueteam.rules import GROUP_FIELDS, GROUP_OPS, OPS, RULE_FIELDS, matches, validate_rule
from app.core.database import SessionLocal, get_db, utcnow
from app.core.errors import AppError, Conflict, NotFound, Unauthorized
from app.iam.deps import Principal, effective_permissions, principal_from_token, require
from app.iam.models import Permission, Role, User

router = APIRouter(prefix="/soc", tags=["soc"])
VIEW = Depends(require("blueteam.alerts.view"))
TRIAGE = Depends(require("blueteam.alerts.triage"))
RULES = Depends(require("blueteam.rules.manage"))
SOURCES = Depends(require("blueteam.sources.manage"))
INC_VIEW = Depends(require("incident.view"))
RESPOND = Depends(require("incident.respond"))
SEV_NAMES = ("info", "low", "medium", "high", "critical")


def _window(frm: datetime | None, to: datetime | None, default_hours=24):
    end = (to.replace(tzinfo=None) if to else utcnow())
    start = frm.replace(tzinfo=None) if frm else end - timedelta(hours=default_hours)
    if start >= end:
        raise AppError("'from' must be before 'to'", code="validation_error", status_code=422)
    if end - start > timedelta(days=90):
        raise AppError("Time range is limited to 90 days", code="validation_error", status_code=422)
    return start, end


def _ev_out(e: SecurityEvent, raw=False):
    d = {k: getattr(e, k) for k in ("id", "source_id", "occurred_at", "ingested_at", "dataset", "category", "action", "outcome", "severity",
                                    "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "host", "user", "signature", "signature_id",
                                    "message", "is_demo")}
    if raw:
        d["raw"] = e.raw
    return d


def _alert_out(a: Alert, users=None):
    return {"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "group_key": a.group_key, "rule_id": a.rule_id,
            "rule": a.rule.name, "rule_code": a.rule.code, "mitre_tactic": a.rule.mitre_tactic, "mitre_technique": a.rule.mitre_technique,
            "first_seen": a.first_seen, "last_seen": a.last_seen, "event_count": a.event_count, "is_demo": a.is_demo,
            "assignee_id": a.assignee_id, "assignee": (users or {}).get(a.assignee_id), "incident_id": a.incident_id,
            "resolution": a.resolution, "created_at": a.created_at, "acknowledged_at": a.acknowledged_at, "closed_at": a.closed_at}


def _usernames(db, ids):
    ids = {i for i in ids if i}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all()) if ids else {}


# ------------------------------------------------------------------ SLA and SOC metrics (v1.4)
@router.get("/sla")
def sla_report(db: Session = Depends(get_db), _p: Principal = VIEW, days: int = Query(30, ge=1, le=365), include_demo: bool = True):
    from app.blueteam import sla
    out = sla.report(db, days, include_demo)
    names = _usernames(db, [b["assignee_id"] for b in out["breaches"]])
    for b in out["breaches"]:
        b["assignee"] = names.get(b["assignee_id"])
    return out


# ------------------------------------------------------------------ overview (Defense Center)
@router.get("/overview")
def overview(db: Session = Depends(get_db), _p: Principal = VIEW, include_demo: bool = True):
    now = utcnow()
    day = now - timedelta(hours=24)
    demo_a = [] if include_demo else [Alert.is_demo.is_(False)]
    demo_e = [] if include_demo else [SecurityEvent.is_demo.is_(False)]
    open_by_sev = dict(db.execute(select(Alert.severity, func.count()).where(Alert.status.in_(ALERT_OPEN), *demo_a).group_by(Alert.severity)).all())
    hour = func.date_format(SecurityEvent.occurred_at, "%Y-%m-%d %H:00")
    ev_hours = db.execute(select(hour.label("h"), func.count()).where(SecurityEvent.occurred_at >= day, *demo_e).group_by("h").order_by("h")).all()
    al_hours = db.execute(select(func.date_format(Alert.first_seen, "%Y-%m-%d %H:00").label("h"), func.count())
                          .where(Alert.first_seen >= day, *demo_a).group_by("h").order_by("h")).all()
    mttr = db.execute(select(func.avg(func.timestampdiff(literal_column("SECOND"), Alert.created_at, Alert.acknowledged_at)))
                      .where(Alert.acknowledged_at.is_not(None), Alert.created_at >= now - timedelta(days=30), *demo_a)).scalar()
    rules = db.execute(select(DetectionRule)).scalars().all()
    tactics: dict[str, dict] = {}
    for r in rules:
        if r.mitre_tactic:
            t = tactics.setdefault(r.mitre_tactic, {"tactic": r.mitre_tactic, "rules": 0, "enabled": 0, "techniques": set()})
            t["rules"] += 1
            t["enabled"] += int(r.is_enabled)
            t["techniques"].add(r.mitre_technique)
    srcs = db.execute(select(LogSource).order_by(LogSource.id)).scalars().all()
    ev24 = dict(db.execute(select(SecurityEvent.source_id, func.count()).where(SecurityEvent.occurred_at >= day).group_by(SecurityEvent.source_id)).all())
    attackers = db.execute(select(SecurityEvent.src_ip, func.count(), func.max(SecurityEvent.severity)).where(
        SecurityEvent.occurred_at >= day, SecurityEvent.severity >= 2, SecurityEvent.src_ip.is_not(None), *demo_e)
        .group_by(SecurityEvent.src_ip).order_by(func.count().desc()).limit(8)).all()
    return {
        "open_alerts": {SEV_NAMES[k]: v for k, v in open_by_sev.items()}, "open_alerts_total": sum(open_by_sev.values()),
        "open_incidents": db.execute(select(func.count()).select_from(Incident).where(Incident.status != "closed")).scalar_one(),
        "events_24h": sum(n for _, n in ev_hours), "alerts_24h": sum(n for _, n in al_hours),
        "blocked_24h": db.execute(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.occurred_at >= day, SecurityEvent.action.in_(("blocked", "drop")), *demo_e)).scalar_one(),
        "mean_time_to_ack_s": round(float(mttr), 1) if mttr is not None else None,
        "events_by_hour": [{"hour": h, "count": n} for h, n in ev_hours], "alerts_by_hour": [{"hour": h, "count": n} for h, n in al_hours],
        "events_by_category": [{"category": c, "count": n} for c, n in db.execute(select(SecurityEvent.category, func.count()).where(SecurityEvent.occurred_at >= day, *demo_e).group_by(SecurityEvent.category))],
        "top_rules": [{"code": r.code, "name": r.name, "hits": r.hits, "last_hit_at": r.last_hit_at} for r in sorted(rules, key=lambda r: -r.hits)[:6] if r.hits],
        "coverage": [{**t, "techniques": sorted(x for x in t["techniques"] if x)} for t in tactics.values()],
        "sources": [{"id": s.id, "name": s.name, "kind": s.kind, "is_demo": s.is_demo, "is_enabled": s.is_enabled, "last_event_at": s.last_event_at,
                     "events_24h": ev24.get(s.id, 0), "events_total": s.events_total} for s in srcs],
        "top_attackers": [{"ip": ip, "events": n, "max_severity": sev} for ip, n, sev in attackers],
    }


# ------------------------------------------------------------------ events / search
@router.get("/events")
def search_events(db: Session = Depends(get_db), _p: Principal = VIEW, q: str = Query("", max_length=1000),
                  frm: datetime | None = Query(None, alias="from"), to: datetime | None = None, include_demo: bool = True,
                  page: int = Query(1, ge=1, le=500), page_size: int = Query(50, ge=1, le=200), stats: bool = True):
    start, end = _window(frm, to)
    where, errors = svc.event_filters(q, start, end, include_demo=include_demo)
    if errors:
        raise AppError("Invalid query: " + "; ".join(errors), code="invalid_query", status_code=422)
    total = db.execute(select(func.count()).select_from(SecurityEvent).where(where)).scalar_one()
    rows = db.execute(select(SecurityEvent).where(where).order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    out = {"total": total, "page": page, "page_size": page_size, "from": start, "to": end, "items": [_ev_out(e) for e in rows]}
    if stats:
        out["histogram"] = svc.histogram(db, where, start, end)
        out["facets"] = svc.facets(db, where)
    return out


@router.get("/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    e = db.get(SecurityEvent, event_id)
    if not e:
        raise NotFound("Event not found")
    out = _ev_out(e, raw=True)
    out["source"] = db.get(LogSource, e.source_id).name
    out["alerts"] = [{"id": a.id, "title": a.title, "status": a.status} for a in db.execute(
        select(Alert).join(AlertEvent, AlertEvent.alert_id == Alert.id).where(AlertEvent.event_id == e.id)).scalars()]
    return out


# ------------------------------------------------------------------ ingestion
class IngestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    records: list = Field(max_length=svc.MAX_BATCH)
    kind: str | None = None
    dataset: str | None = Field(default=None, max_length=32)


@router.post("/ingest")
async def ingest_http(request: Request):
    """Sensor ingestion. Authenticated by the source's ingest key (header X-Ingest-Key), not by a user session.
    Body: {"records": [...], "kind": optional, "dataset": optional} or NDJSON / syslog lines as text/plain."""
    if int(request.headers.get("content-length") or 0) > 10 * 1024 * 1024:
        raise AppError("Payload too large (max 10 MB)", code="payload_too_large", status_code=413)
    body = await request.body()
    if len(body) > 10 * 1024 * 1024:
        raise AppError("Payload too large (max 10 MB)", code="payload_too_large", status_code=413)
    with SessionLocal() as db:
        src = svc.source_by_key(db, request.headers.get("x-ingest-key", ""))
        if src is None:
            raise Unauthorized("Unknown or disabled ingest key", code="invalid_ingest_key")
        ctype = request.headers.get("content-type", "")
        kind = request.query_params.get("kind") or src.kind
        if kind not in SOURCE_KINDS or kind == "platform":
            raise AppError("Unsupported kind", code="validation_error", status_code=422)
        if ctype.startswith("application/json"):
            try:
                b = IngestBody.model_validate(json.loads(body))
            except Exception as e:  # noqa: BLE001
                raise AppError(f"Invalid body: {str(e)[:300]}", code="validation_error", status_code=422) from None
            records, kind, dataset = b.records, b.kind or kind, b.dataset
        else:
            records, dataset = split_lines(kind, body.decode("utf-8", errors="replace")), request.query_params.get("dataset")
        return await asyncio.to_thread(svc.ingest, db, src, records, kind=kind, dataset_hint=dataset)


class SourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=128)
    kind: str = Field(pattern="^(zeek|suricata|wazuh|syslog|json)$")
    description: str = Field(default="", max_length=2000)
    lab_id: int | None = None


def _src_out(s: LogSource):
    return {"id": s.id, "name": s.name, "kind": s.kind, "description": s.description, "lab_id": s.lab_id, "key_prefix": s.key_prefix,
            "has_key": bool(s.key_hash), "is_demo": s.is_demo, "is_enabled": s.is_enabled, "last_event_at": s.last_event_at,
            "events_total": s.events_total, "created_at": s.created_at, "builtin": s.kind == "platform" or s.is_demo}


def _shipper_config(request: Request, s: LogSource, key: str) -> str:
    base = str(request.base_url).rstrip("/")
    return (f"# CYBER RANGE log shipper configuration for source '{s.name}' ({s.kind})\n"
            "# Keep this file private: it contains the ingest key. The platform stores only its hash and cannot show it again.\n"
            f"CR_INGEST_URL={base}/api/v1/soc/ingest\nCR_INGEST_KIND={s.kind}\nCR_INGEST_KEY={key}\n")


@router.get("/sources")
def list_sources(db: Session = Depends(get_db), _p: Principal = VIEW):
    return [_src_out(s) for s in db.execute(select(LogSource).order_by(LogSource.id)).scalars()]


@router.post("/sources", status_code=201)
def create_source(body: SourceIn, request: Request, db: Session = Depends(get_db), p: Principal = SOURCES):
    src, key = svc.create_source(db, p, name=body.name, kind=body.kind, description=body.description, lab_id=body.lab_id)
    db.commit()
    # The key leaves the server exactly once, inside a config file the UI saves to disk without rendering it.
    return {"source": _src_out(src), "config_filename": f"cr-shipper-{src.id}.env", "config": _shipper_config(request, src, key)}


@router.post("/sources/{source_id}/rotate-key")
def rotate(source_id: int, request: Request, db: Session = Depends(get_db), p: Principal = SOURCES):
    s = db.get(LogSource, source_id)
    if not s or s.kind == "platform" or s.is_demo:
        raise NotFound("Source not found")
    key = svc.rotate_key(db, p, s)
    db.commit()
    return {"source": _src_out(s), "config_filename": f"cr-shipper-{s.id}.env", "config": _shipper_config(request, s, key)}


@router.patch("/sources/{source_id}")
def toggle_source(source_id: int, body: dict, db: Session = Depends(get_db), p: Principal = SOURCES):
    s = db.get(LogSource, source_id)
    if not s:
        raise NotFound("Source not found")
    if not isinstance(body.get("is_enabled"), bool):
        raise AppError("is_enabled must be a boolean", code="validation_error", status_code=422)
    s.is_enabled = body["is_enabled"]
    record(db, "soc.source.update", actor=p, resource_type="log_source", resource_id=s.id, details={"is_enabled": s.is_enabled})
    db.commit()
    return _src_out(s)


class UploadIn(BaseModel):
    content: str = Field(max_length=10 * 1024 * 1024)
    dataset: str | None = Field(default=None, max_length=32)
    filename: str = Field(default="upload", max_length=255)


@router.post("/sources/{source_id}/upload")
def upload(source_id: int, body: UploadIn, db: Session = Depends(get_db), p: Principal = SOURCES):
    s = db.get(LogSource, source_id)
    if not s or s.kind == "platform" or s.is_demo:
        raise NotFound("Source not found")
    res = svc.ingest(db, s, split_lines(s.kind, body.content), dataset_hint=body.dataset)
    record(db, "soc.source.upload", actor=p, resource_type="log_source", resource_id=s.id,
           details={"filename": body.filename, **{k: v for k, v in res.items() if k != "errors"}})
    db.commit()
    return res


PCAP_MAX = 50 * 1024 * 1024


@router.post("/pcap/replay")
async def pcap_replay(file: UploadFile = File(...), lab_id: int | None = Form(None), shift_to_now: bool = Form(True),
                      db: Session = Depends(get_db), p: Principal = SOURCES):
    """Replay a captured .pcap into the SIEM as Zeek-style events, so detection runs against real packet captures instead
    of only the platform's own red team records. Reuses the normal ingest/normalize/detect pipeline; events land under a
    dedicated 'PCAP replay' source (per lab). shift_to_now moves the capture into the live window."""
    from app.blueteam import pcap_replay as pr
    data = await file.read()
    if not data:
        raise AppError("File kosong", code="validation_error", status_code=422)
    if len(data) > PCAP_MAX:
        raise AppError(f"File melebihi {PCAP_MAX // (1024 * 1024)} MB", code="payload_too_large", status_code=413)
    try:
        parsed = await asyncio.to_thread(pr.to_zeek_records, data, shift_to_now=shift_to_now)
    except pr.PcapError as e:
        raise AppError(f"Tidak bisa membaca pcap: {e}", code="invalid_pcap", status_code=422) from None
    if not parsed["records"]:
        return {"source": None, "stats": parsed["stats"], "accepted": 0, "alerts": 0,
                "note": "Tidak ada lalu lintas IPv4 yang bisa diekstrak (TCP/UDP/ICMP) dari capture ini."}
    name = f"PCAP replay (lab {lab_id})" if lab_id else "PCAP replay"
    src = db.execute(select(LogSource).where(LogSource.name == name)).scalar_one_or_none()
    if src is None:
        src, _ = svc.create_source(db, p, name=name, kind="zeek", description="Event dari replay file .pcap", lab_id=lab_id)
    elif not src.is_enabled:
        src.is_enabled = True
    res = svc.ingest(db, src, parsed["records"], kind="zeek")
    record(db, "soc.pcap.replay", actor=p, resource_type="log_source", resource_id=src.id,
           details={"filename": file.filename, "lab_id": lab_id, "stats": parsed["stats"],
                    **{k: v for k, v in res.items() if k != "errors"}})
    db.commit()
    return {"source": _src_out(src), "stats": parsed["stats"], **res}


@router.post("/demo")
def load_demo(db: Session = Depends(get_db), p: Principal = RULES):
    return svc.load_demo(db, p)


@router.delete("/demo")
def purge_demo(db: Session = Depends(get_db), p: Principal = RULES):
    return svc.purge_demo(db, p)


# ------------------------------------------------------------------ rules
class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    code: str = Field(pattern=r"^[A-Z][A-Z0-9-]{2,63}$")
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(default="", max_length=4000)
    severity: int = Field(ge=0, le=4)
    kind: str = "match"
    conditions: list
    threshold: dict | None = None
    group_by: str | None = None
    mitre_tactic: str | None = Field(default=None, max_length=64)
    mitre_technique: str | None = Field(default=None, pattern=r"^T\d{4}(\.\d{3})?$")
    is_enabled: bool = True


def _rule_out(r: DetectionRule, source=False):
    d = {k: getattr(r, k) for k in ("id", "code", "name", "description", "severity", "kind", "conditions", "threshold", "group_by", "mitre_tactic",
                                    "mitre_technique", "is_enabled", "is_builtin", "origin", "version", "hits", "last_hit_at", "created_at", "updated_at")}
    d["mitre_name"] = technique_name(r.mitre_technique)
    if source:
        d["source_text"] = r.source_text
    return d


def _check_rule(b: RuleIn):
    errs = validate_rule(b.kind, b.conditions, b.threshold, b.group_by)
    if errs:
        raise AppError("Invalid rule", code="invalid_rule", status_code=422, details=errs)


@router.get("/rules/meta")
def rules_meta(_p: Principal = VIEW):
    return {"fields": RULE_FIELDS, "ops": OPS, "group_ops": GROUP_OPS, "group_fields": GROUP_FIELDS, "severities": SEV_NAMES,
            "tactics": [n for _, n in TACTICS], "techniques": [{"id": k, "name": v[0], "tactics": v[1]} for k, v in sorted(TECHNIQUES.items())]}


@router.get("/rules/{rule_id}/source")
def rule_source(rule_id: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    r = db.get(DetectionRule, rule_id)
    if not r:
        raise NotFound("Rule not found")
    return _rule_out(r, source=True)


class SigmaIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str = Field(min_length=10, max_length=sigma.MAX_SOURCE)
    enable: bool = False
    overwrite: bool = False


def _sigma_results(db, body: SigmaIn) -> list[dict]:
    try:
        res = sigma.parse(body.source)
    except sigma.SigmaError as e:
        raise AppError(f"Could not parse Sigma: {e}", code="invalid_sigma", status_code=422) from e
    existing = {r.code: r for r in db.execute(select(DetectionRule).where(DetectionRule.code.in_([x["rule"]["code"] for x in res if x["ok"]] or ["-"]))).scalars()}
    for x in res:
        if x["ok"]:
            e = existing.get(x["rule"]["code"])
            x["exists"] = bool(e)
            x["existing_origin"] = e.origin if e else None
            x["rule"]["mitre_name"] = technique_name(x["rule"]["mitre_technique"])
    return res


@router.post("/rules/sigma/preview")
def sigma_preview(body: SigmaIn, db: Session = Depends(get_db), _p: Principal = RULES):
    """Convert Sigma YAML without saving anything: shows the resulting rules, warnings and per-rule errors."""
    return {"results": _sigma_results(db, body)}


@router.post("/rules/sigma/import")
def sigma_import(body: SigmaIn, db: Session = Depends(get_db), p: Principal = RULES):
    """Create rules from Sigma. Imported rules start disabled unless `enable` is set, so an analyst can backtest them first."""
    res = _sigma_results(db, body)
    docs = body.source.split("\n---")
    created, updated, skipped = [], [], []
    for x in res:
        if not x["ok"]:
            continue
        r = {k: v for k, v in x["rule"].items() if k != "mitre_name"}
        src = docs[x["index"]].strip().removeprefix("---").strip() if len(docs) == len(res) else body.source
        if x["exists"]:
            if not body.overwrite or x["existing_origin"] != "sigma":
                skipped.append({"code": r["code"], "reason": "exists" if x["existing_origin"] == "sigma" else "code used by a non-Sigma rule"})
                continue
            row = db.execute(select(DetectionRule).where(DetectionRule.code == r["code"])).scalar_one()
            for k, v in r.items():
                setattr(row, k, v)
            row.source_text, row.version = src[:60000], row.version + 1
            updated.append(r["code"])
        else:
            db.add(DetectionRule(**r, is_enabled=body.enable, origin="sigma", source_text=src[:60000], created_by=p.id))
            created.append(r["code"])
    record(db, "soc.rule.sigma_import", actor=p, resource_type="detection_rule",
           details={"created": created, "updated": updated, "skipped": [s["code"] for s in skipped], "errors": sum(1 for x in res if not x["ok"]), "enabled": body.enable})
    db.commit()
    return {"created": created, "updated": updated, "skipped": skipped, "errors": [{"index": x["index"], "title": x["title"], "error": x["error"]} for x in res if not x["ok"]]}


@router.get("/attack/matrix")
def attack_matrix(db: Session = Depends(get_db), p: Principal = VIEW, days: int = Query(30, ge=1, le=365)):
    """ATT&CK matrix with detection coverage (enabled rules per technique), alert volume and, for red team viewers, purple-team results."""
    from app.redteam.actions import ACTIONS
    rules = db.execute(select(DetectionRule)).scalars().all()
    since = utcnow() - timedelta(days=days)
    alerts = dict(db.execute(select(DetectionRule.mitre_technique, func.count()).join(Alert, Alert.rule_id == DetectionRule.id)
                             .where(Alert.first_seen >= since, DetectionRule.mitre_technique.is_not(None)).group_by(DetectionRule.mitre_technique)).all())
    purple_rows = {}
    if p.has("redteam.assessment.view"):
        from app.redteam.purple import summary
        purple_rows = {r["technique"]: r for r in summary(db, days)["techniques"]}
    cells: dict[str, dict] = {}

    def cell(tid: str) -> dict:
        tid = tid.upper()
        if tid not in cells:
            name, tactics = TECHNIQUES.get(tid, (None, []))
            cells[tid] = {"id": tid, "name": name or technique_name(tid) or tid, "tactics": list(tactics), "rules": [], "enabled_rules": 0,
                          "alerts": 0, "simulated_by": [], "purple": None}
        return cells[tid]
    for tid in TECHNIQUES:
        cell(tid)
    for r in rules:
        if r.mitre_technique:
            c = cell(r.mitre_technique)
            if r.mitre_tactic and r.mitre_tactic not in c["tactics"]:
                c["tactics"].append(r.mitre_tactic)
            c["rules"].append({"id": r.id, "code": r.code, "name": r.name, "enabled": r.is_enabled, "origin": r.origin})
            c["enabled_rules"] += int(r.is_enabled)
    for k, a in ACTIONS.items():
        c = cell(a["mitre"])
        c["simulated_by"].append(k)
        if a["tactic"] not in c["tactics"]:
            c["tactics"].append(a["tactic"])
    for tid, n in alerts.items():
        cell(tid)["alerts"] += n
    for tid, row in purple_rows.items():
        if tid:
            cell(tid)["purple"] = {k: row[k] for k in ("attacked", "detected", "detected_same", "sensor", "verdict", "detection_rate")}
    # a rule on a parent technique covers its sub-techniques and vice versa for display of "covered"
    for c in cells.values():
        parent = cells.get(c["id"].split(".")[0])
        c["covered"] = c["enabled_rules"] > 0 or (parent is not None and parent is not c and parent["enabled_rules"] > 0)
    tactics = []
    for tid, name in TACTICS:
        techs = sorted((c for c in cells.values() if name in c["tactics"]), key=lambda c: c["id"])
        tactics.append({"id": tid, "name": name, "techniques": techs, "covered": sum(1 for c in techs if c["covered"]), "total": len(techs)})
    allc = list(cells.values())
    return {"tactics": tactics, "days": days, "totals": {"techniques": len(allc), "covered": sum(1 for c in allc if c["covered"]),
                                                       "simulated": sum(1 for c in allc if c["simulated_by"]),
                                                       "rules_mapped": sum(1 for r in rules if r.mitre_technique), "rules": len(rules)},
            "purple_included": bool(purple_rows) or p.has("redteam.assessment.view")}


@router.get("/rules")
def list_rules(db: Session = Depends(get_db), _p: Principal = VIEW):
    return [_rule_out(r) for r in db.execute(select(DetectionRule).order_by(DetectionRule.code)).scalars()]


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, db: Session = Depends(get_db), p: Principal = RULES):
    _check_rule(body)
    if db.execute(select(DetectionRule.id).where(DetectionRule.code == body.code)).first():
        raise Conflict("A rule with this code exists")
    r = DetectionRule(**body.model_dump(), created_by=p.id)
    db.add(r)
    db.flush()
    record(db, "soc.rule.create", actor=p, resource_type="detection_rule", resource_id=r.id, details={"code": r.code})
    db.commit()
    return _rule_out(r)


@router.put("/rules/{rule_id}")
def update_rule(rule_id: int, body: RuleIn, db: Session = Depends(get_db), p: Principal = RULES):
    _check_rule(body)
    r = db.get(DetectionRule, rule_id)
    if not r:
        raise NotFound("Rule not found")
    if body.code != r.code:
        raise AppError("A rule's code cannot change", code="validation_error", status_code=422)
    if r.kind == "intel":
        raise AppError("This rule is driven by threat intelligence; enable or disable it here and manage indicators in Threat Intelligence",
                       code="rule_not_editable", status_code=409)
    before = _rule_out(r)
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    r.version += 1
    record(db, "soc.rule.update", actor=p, resource_type="detection_rule", resource_id=r.id,
           details={"code": r.code, "version": r.version, "changed": sorted(k for k in body.model_dump() if before[k] != getattr(r, k))})
    db.commit()
    return _rule_out(r)


@router.patch("/rules/{rule_id}")
def toggle_rule(rule_id: int, body: dict, db: Session = Depends(get_db), p: Principal = RULES):
    r = db.get(DetectionRule, rule_id)
    if not r:
        raise NotFound("Rule not found")
    if not isinstance(body.get("is_enabled"), bool):
        raise AppError("is_enabled must be a boolean", code="validation_error", status_code=422)
    r.is_enabled = body["is_enabled"]
    record(db, "soc.rule.toggle", actor=p, resource_type="detection_rule", resource_id=r.id, details={"code": r.code, "is_enabled": r.is_enabled})
    db.commit()
    return _rule_out(r)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db), p: Principal = RULES):
    r = db.get(DetectionRule, rule_id)
    if not r:
        raise NotFound("Rule not found")
    if r.is_builtin:
        raise Conflict("Built-in rules can be disabled but not deleted")
    if db.execute(select(Alert.id).where(Alert.rule_id == r.id).limit(1)).first():
        raise Conflict("The rule has alerts; disable it instead to keep their history")
    record(db, "soc.rule.delete", actor=p, resource_type="detection_rule", resource_id=r.id, details={"code": r.code})
    db.delete(r)
    db.commit()


class RuleTest(BaseModel):
    kind: str = "match"
    conditions: list
    threshold: dict | None = None
    group_by: str | None = None
    hours: int = Field(default=24, ge=1, le=168)


@router.post("/rules/test")
def test_rule(body: RuleTest, db: Session = Depends(get_db), _p: Principal = RULES):
    """Backtest a rule definition against stored events without saving it or creating alerts."""
    errs = validate_rule(body.kind, body.conditions, body.threshold, body.group_by)
    if errs:
        raise AppError("Invalid rule", code="invalid_rule", status_code=422, details=errs)
    start = utcnow() - timedelta(hours=body.hours)
    q = select(SecurityEvent).where(SecurityEvent.occurred_at >= start)
    for c in body.conditions:
        if c["op"] == "eq" and c["field"] in ("category", "dataset", "outcome", "protocol", "action"):
            q = q.where(getattr(SecurityEvent, c["field"]) == c["value"])
    scanned = db.execute(q.order_by(SecurityEvent.occurred_at).limit(50000)).scalars().all()
    hits = [e for e in scanned if matches(body.conditions, _ev_out(e))]
    groups = {}
    if body.kind == "threshold":
        t = body.threshold
        by: dict = {}
        for e in hits:
            g = getattr(e, t["group_by"])
            if g is not None:
                by.setdefault(g, []).append(e)
        for g, evs in by.items():
            j = 0
            for i, e in enumerate(evs):  # sliding window over time-ordered events
                while evs[j].occurred_at < e.occurred_at - timedelta(seconds=t["window_seconds"]):
                    j += 1
                win = evs[j:i + 1]
                n = len({getattr(x, t["distinct"]) for x in win}) if t.get("distinct") else len(win)
                if n >= t["count"]:
                    groups[str(g)] = max(groups.get(str(g), 0), n)
    return {"scanned": len(scanned), "matched_events": len(hits), "would_alert_groups": groups if body.kind == "threshold" else None,
            "would_alert": len(groups) if body.kind == "threshold" else len({str(getattr(e, body.group_by)) if body.group_by else "" for e in hits}),
            "sample": [_ev_out(e) for e in hits[-10:]]}


# ------------------------------------------------------------------ alerts
@router.get("/assignees")
def assignees(db: Session = Depends(get_db), _p: Principal = TRIAGE):
    rows = db.execute(select(User).where(User.is_active.is_(True), User.deleted_at.is_(None))).scalars().all()
    return [{"id": u.id, "username": u.username, "full_name": u.full_name} for u in rows
            if {"blueteam.alerts.triage", "incident.respond"} & effective_permissions(u)]


@router.get("/alerts")
def list_alerts(db: Session = Depends(get_db), p: Principal = VIEW, status: str = Query("open"), severity: int | None = Query(None, ge=0, le=4),
                q: str = Query("", max_length=200), include_demo: bool = True, mine: bool = False,
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    w = []
    if status == "open":
        w.append(Alert.status.in_(ALERT_OPEN))
    elif status != "all":
        if status not in ALERT_STATUSES:
            raise AppError("Unknown status", code="validation_error", status_code=422)
        w.append(Alert.status == status)
    if severity is not None:
        w.append(Alert.severity >= severity)
    if q:
        w.append(Alert.title.like(f"%{q}%"))
    if not include_demo:
        w.append(Alert.is_demo.is_(False))
    if mine:
        w.append(Alert.assignee_id == p.id)
    total = db.execute(select(func.count()).select_from(Alert).where(*w)).scalar_one()
    rows = db.execute(select(Alert).where(*w).order_by(case((Alert.status == "new", 0), else_=1), Alert.severity.desc(), Alert.last_seen.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    users = _usernames(db, [a.assignee_id for a in rows])
    counts = dict(db.execute(select(Alert.status, func.count()).group_by(Alert.status)).all())
    return {"total": total, "page": page, "page_size": page_size, "counts": counts, "items": [_alert_out(a, users) for a in rows]}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db), _p: Principal = VIEW):
    a = svc.get_alert(db, alert_id)
    out = _alert_out(a, _usernames(db, [a.assignee_id]))
    out["rule_description"] = a.rule.description
    out["events"] = [_ev_out(e) for e in db.execute(select(SecurityEvent).join(AlertEvent, AlertEvent.event_id == SecurityEvent.id)
                                                    .where(AlertEvent.alert_id == a.id).order_by(SecurityEvent.occurred_at.desc()).limit(200)).scalars()]
    return out


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str | None = None
    assignee_id: int | None = None
    assign_to_me: bool = False
    unassign: bool = False
    resolution: str | None = Field(default=None, max_length=4000)


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, db: Session = Depends(get_db), p: Principal = TRIAGE):
    a = svc.get_alert(db, alert_id, lock=True)
    changes = {}
    if body.status:
        if body.status not in ALERT_STATUSES:
            raise AppError("Unknown status", code="validation_error", status_code=422)
        if body.status in ("resolved", "false_positive") and not (body.resolution or "").strip():
            raise AppError("A resolution note is required to close an alert", code="validation_error", status_code=422)
        changes["status"] = [a.status, body.status]
        a.status = body.status
        if body.status != "new" and not a.acknowledged_at:
            a.acknowledged_at = utcnow()
        a.closed_at = utcnow() if body.status in ("resolved", "false_positive") else None
        if body.resolution:
            a.resolution = body.resolution
    if body.assign_to_me or body.assignee_id is not None or body.unassign:
        target = None if body.unassign else p.id if body.assign_to_me else body.assignee_id
        if target is not None:
            u = db.get(User, target)
            if not u or not ({"blueteam.alerts.triage", "incident.respond"} & effective_permissions(u)):
                raise AppError("Assignee must be an active analyst or responder", code="validation_error", status_code=422)
        changes["assignee"] = [a.assignee_id, target]
        a.assignee_id = target
        if target and a.status == "new":
            a.status, a.acknowledged_at = "acknowledged", a.acknowledged_at or utcnow()
    if not changes:
        raise AppError("Nothing to change", code="validation_error", status_code=422)
    record(db, "soc.alert.update", actor=p, resource_type="alert", resource_id=a.id, details=changes)
    if a.incident_id:
        inc = db.get(Incident, a.incident_id)
        svc.entry(db, inc, p, "alert_updated", f"Alert #{a.id} {a.status}", {"alert_id": a.id, **changes})
    db.commit()
    svc.publish("alert", {"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "event_count": a.event_count, "is_demo": a.is_demo, "created": False})
    return _alert_out(a, _usernames(db, [a.assignee_id]))


class Escalate(BaseModel):
    incident_id: int | None = None
    title: str | None = Field(default=None, max_length=255)


@router.post("/alerts/{alert_id}/escalate")
def escalate(alert_id: int, body: Escalate, db: Session = Depends(get_db), p: Principal = RESPOND):
    a = svc.get_alert(db, alert_id)
    if body.incident_id:
        inc = db.get(Incident, body.incident_id)
        if not inc or inc.status == "closed":
            raise NotFound("Open incident not found")
    else:
        inc = Incident(title=(body.title or a.title)[:255], severity=a.severity, status="open", owner_id=p.id, created_by=p.id, is_demo=a.is_demo,
                       summary=f"Opened from alert #{a.id} ({a.rule.code} {a.rule.name}).")
        db.add(inc)
        db.flush()
        svc.entry(db, inc, p, "created", inc.summary)
        record(db, "soc.incident.create", actor=p, resource_type="incident", resource_id=inc.id, details={"from_alert": a.id})
    svc.link_alerts(db, p, inc, [a.id])
    record(db, "soc.alert.escalate", actor=p, resource_type="alert", resource_id=a.id, details={"incident": inc.id})
    db.commit()
    svc.publish("incident", {"id": inc.id, "title": inc.title, "severity": inc.severity, "status": inc.status})
    return {"incident_id": inc.id}


# ------------------------------------------------------------------ incidents
def _inc_out(i: Incident, users=None, alerts=0):
    return {"id": i.id, "title": i.title, "summary": i.summary, "severity": i.severity, "status": i.status, "owner_id": i.owner_id,
            "owner": (users or {}).get(i.owner_id), "created_by": i.created_by, "is_demo": i.is_demo, "created_at": i.created_at,
            "updated_at": i.updated_at, "closed_at": i.closed_at, "alert_count": alerts}


@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db), _p: Principal = INC_VIEW, status: str = Query("active")):
    w = [Incident.status != "closed"] if status == "active" else [] if status == "all" else [Incident.status == status]
    rows = db.execute(select(Incident).where(*w).order_by(Incident.severity.desc(), Incident.updated_at.desc()).limit(500)).scalars().all()
    counts = dict(db.execute(select(Alert.incident_id, func.count()).where(Alert.incident_id.in_([r.id for r in rows] or [0])).group_by(Alert.incident_id)).all())
    users = _usernames(db, [r.owner_id for r in rows])
    return [_inc_out(r, users, counts.get(r.id, 0)) for r in rows]


class IncidentIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    title: str = Field(min_length=3, max_length=255)
    summary: str = Field(default="", max_length=10000)
    severity: int = Field(ge=0, le=4)
    alert_ids: list[int] = Field(default_factory=list, max_length=100)


@router.post("/incidents", status_code=201)
def create_incident(body: IncidentIn, db: Session = Depends(get_db), p: Principal = RESPOND):
    inc = Incident(title=body.title, summary=body.summary, severity=body.severity, status="open", owner_id=p.id, created_by=p.id)
    db.add(inc)
    db.flush()
    svc.entry(db, inc, p, "created", body.summary or "Incident opened")
    if body.alert_ids:
        svc.link_alerts(db, p, inc, body.alert_ids)
        inc.is_demo = all(svc.get_alert(db, i).is_demo for i in body.alert_ids)
    record(db, "soc.incident.create", actor=p, resource_type="incident", resource_id=inc.id, details={"alerts": body.alert_ids})
    db.commit()
    svc.publish("incident", {"id": inc.id, "title": inc.title, "severity": inc.severity, "status": inc.status})
    return _inc_out(inc)


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db), _p: Principal = INC_VIEW):
    inc = db.get(Incident, incident_id)
    if not inc:
        raise NotFound("Incident not found")
    alerts = db.execute(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.first_seen)).scalars().all()
    entries = db.execute(select(IncidentEntry).where(IncidentEntry.incident_id == inc.id).order_by(IncidentEntry.id)).scalars().all()
    users = _usernames(db, [inc.owner_id, *[a.assignee_id for a in alerts], *[e.author_id for e in entries]])
    out = _inc_out(inc, users, len(alerts))
    out["alerts"] = [_alert_out(a, users) for a in alerts]
    out["timeline"] = [{"id": e.id, "at": e.at, "author": users.get(e.author_id), "kind": e.kind, "body": e.body, "data": e.data} for e in entries]
    # Affected assets / indicators, derived from linked events (no fabricated data)
    ev = db.execute(select(SecurityEvent).join(AlertEvent, AlertEvent.event_id == SecurityEvent.id)
                    .where(AlertEvent.alert_id.in_([a.id for a in alerts] or [0])).limit(2000)).scalars().all()
    out["indicators"] = {"src_ips": sorted({e.src_ip for e in ev if e.src_ip}), "dst_ips": sorted({e.dst_ip for e in ev if e.dst_ip}),
                         "users": sorted({e.user for e in ev if e.user}), "hosts": sorted({e.host for e in ev if e.host})}
    out["first_event_at"] = min((e.occurred_at for e in ev), default=None)
    return out


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str | None = None
    severity: int | None = Field(default=None, ge=0, le=4)
    owner_id: int | None = None
    summary: str | None = Field(default=None, max_length=10000)
    note: str | None = Field(default=None, max_length=10000)


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, body: IncidentUpdate, db: Session = Depends(get_db), p: Principal = RESPOND):
    inc = db.execute(select(Incident).where(Incident.id == incident_id).with_for_update()).scalar_one_or_none()
    if not inc:
        raise NotFound("Incident not found")
    changes = {}
    if body.status and body.status != inc.status:
        if body.status not in INCIDENT_STATUSES:
            raise AppError("Unknown status", code="validation_error", status_code=422)
        if body.status == "closed" and not (body.note or "").strip():
            raise AppError("Closing an incident needs a closing note", code="validation_error", status_code=422)
        changes["status"] = [inc.status, body.status]
        svc.entry(db, inc, p, "status", f"{inc.status} → {body.status}", {"from": inc.status, "to": body.status})
        inc.status = body.status
        inc.closed_at = utcnow() if body.status == "closed" else None
    if body.severity is not None and body.severity != inc.severity:
        changes["severity"] = [inc.severity, body.severity]
        svc.entry(db, inc, p, "severity", f"{SEV_NAMES[inc.severity]} → {SEV_NAMES[body.severity]}")
        inc.severity = body.severity
    if body.owner_id is not None and body.owner_id != inc.owner_id:
        u = db.get(User, body.owner_id)
        if not u or "incident.respond" not in effective_permissions(u):
            raise AppError("Owner must be an incident responder", code="validation_error", status_code=422)
        changes["owner"] = [inc.owner_id, u.id]
        svc.entry(db, inc, p, "assigned", f"Owner set to {u.username}")
        inc.owner_id = u.id
    if body.summary is not None and body.summary != inc.summary:
        changes["summary"] = True
        inc.summary = body.summary
    if body.note:
        svc.entry(db, inc, p, "note", body.note)
        changes["note"] = True
    if not changes:
        raise AppError("Nothing to change", code="validation_error", status_code=422)
    record(db, "soc.incident.update", actor=p, resource_type="incident", resource_id=inc.id, details=changes)
    db.commit()
    svc.publish("incident", {"id": inc.id, "title": inc.title, "severity": inc.severity, "status": inc.status})
    return get_incident(inc.id, db, p)


@router.post("/incidents/{incident_id}/alerts")
def link(incident_id: int, body: dict, db: Session = Depends(get_db), p: Principal = RESPOND):
    inc = db.get(Incident, incident_id)
    if not inc or inc.status == "closed":
        raise NotFound("Open incident not found")
    ids = body.get("alert_ids")
    if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids) or not 0 < len(ids) <= 100:
        raise AppError("alert_ids must be a list of 1-100 ids", code="validation_error", status_code=422)
    n = svc.link_alerts(db, p, inc, ids)
    record(db, "soc.incident.link", actor=p, resource_type="incident", resource_id=inc.id, details={"alerts": ids})
    db.commit()
    return {"linked": n}


# ------------------------------------------------------------------ realtime stream
@router.websocket("/stream")
async def stream(ws: WebSocket):
    """Realtime SOC feed. The client sends {"token": "<access token>"} as its first message (tokens never go in URLs)."""
    await ws.accept()
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=10)
        with SessionLocal() as db:
            p = principal_from_token(db, str(first.get("token", "")))
            if not p.has("blueteam.alerts.view"):
                await ws.send_json({"type": "error", "data": {"code": "permission_denied"}})
                await ws.close(code=4403)
                return
    except (TimeoutError, Unauthorized, ValueError, KeyError, AttributeError):
        await ws.close(code=4401)
        return
    except WebSocketDisconnect:
        return
    import redis.asyncio as aioredis

    from app.core.config import get_settings
    r = aioredis.from_url(get_settings().redis_url, decode_responses=True)
    ps = r.pubsub()
    await ps.subscribe(svc.CHANNEL)
    await ws.send_json({"type": "hello", "data": {"user": p.username}})

    async def pump():
        while True:
            msg = await ps.get_message(ignore_subscribe_messages=True, timeout=15)
            if msg and msg.get("type") == "message":
                await ws.send_text(msg["data"])
            else:
                await ws.send_json({"type": "ping"})

    async def drain():
        while True:
            await ws.receive_text()  # client messages are ignored; detects disconnects

    tasks = [asyncio.create_task(pump()), asyncio.create_task(drain())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        await ps.unsubscribe(svc.CHANNEL)
        await ps.aclose()
        await r.aclose()


__all__ = ["Permission", "Role"]



# ------------------------------------------------------------------ GeoIP attack map
@router.get("/geo/attackers")
def geo_attackers(db: Session = Depends(get_db), _p: Principal = VIEW, hours: int = Query(24, ge=1, le=720), include_demo: bool = True,
                  min_severity: int = Query(0, ge=0, le=4)):
    """Top source addresses of security events with offline GeoIP (CR_GEOIP_DB). Private/lab addresses are listed separately."""
    from app.core import geoip
    since = utcnow() - timedelta(hours=hours)
    w = [SecurityEvent.occurred_at >= since, SecurityEvent.src_ip.is_not(None), SecurityEvent.severity >= min_severity]
    if not include_demo:
        w.append(SecurityEvent.is_demo.is_(False))
    rows = db.execute(select(SecurityEvent.src_ip, func.count(), func.max(SecurityEvent.severity), func.max(SecurityEvent.occurred_at),
                             func.max(case((SecurityEvent.is_demo.is_(True), 1), else_=0)))
                      .where(*w).group_by(SecurityEvent.src_ip).order_by(func.count().desc()).limit(500)).all()
    points, private, unknown = [], [], []
    for ip, n, sev, last, demo in rows:
        g = geoip.lookup(ip)
        item = {"ip": ip, "events": n, "max_severity": sev, "last_seen": last, "is_demo": bool(demo), "country": g.get("country"),
                "country_name": g.get("country_name"), "city": g.get("city"), "lat": g.get("lat"), "lon": g.get("lon")}
        (private if g.get("private") else points if g.get("lat") is not None else unknown).append(item)
    countries: dict[str, dict] = {}
    for p in points:
        c = countries.setdefault(p["country"] or "?", {"country": p["country"], "name": p["country_name"], "events": 0, "sources": 0})
        c["events"] += p["events"]
        c["sources"] += 1
    return {"geoip": geoip.status(), "hours": hours, "points": points, "private": private[:100], "unresolved": unknown[:100],
            "countries": sorted(countries.values(), key=lambda c: -c["events"])}

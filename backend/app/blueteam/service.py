"""SOC pipeline: ingest -> normalize -> store (idempotent) -> detect -> alert -> realtime publish."""
import hashlib
import json
import secrets
import shlex
from datetime import timedelta

from sqlalchemy import and_, func, insert, not_, or_, select, update, text
from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.audit.service import record
from app.blueteam import normalize as norm
from app.blueteam.models import (ALERT_OPEN, Alert, AlertEvent, DetectionRule, Incident, IncidentEntry, LogSource,
                                 SecurityEvent)
from app.blueteam.rules import AD_FAILED_LOGON, AD_FAILED_LOGON_V13, BUILTIN_RULES, matches
from app.core.database import utcnow
from app.core.errors import AppError, Conflict, NotFound
from app.core.logging import log

PLATFORM_SOURCE = "CYBER RANGE platform"
DEMO_SOURCE = "DEMO dataset"
CHANNEL = "cr:soc"
MAX_BATCH = 5000
MAX_LINKS_PER_ALERT = 200


# ------------------------------------------------------------------ realtime
def publish(kind: str, data: dict) -> None:
    try:
        from app.core.redis_client import get_redis
        get_redis().publish(CHANNEL, json.dumps({"type": kind, "data": data}, default=str))
    except Exception:  # noqa: BLE001 - realtime is best effort, the database is the source of truth
        log.warning("soc_publish_failed", kind=kind)


# ------------------------------------------------------------------ sources
def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_ingest_key() -> str:
    return "cri_" + secrets.token_urlsafe(32)


def create_source(db: Session, p, *, name: str, kind: str, description: str = "", lab_id: int | None = None) -> tuple[LogSource, str]:
    if db.execute(select(LogSource.id).where(LogSource.name == name)).first():
        raise Conflict("A log source with this name exists")
    key = new_ingest_key()
    src = LogSource(name=name, kind=kind, description=description, lab_id=lab_id, key_prefix=key[:10], key_hash=_hash_key(key), created_by=p.id)
    db.add(src)
    db.flush()
    record(db, "soc.source.create", actor=p, resource_type="log_source", resource_id=src.id, details={"name": name, "kind": kind})
    return src, key


def rotate_key(db: Session, p, src: LogSource) -> str:
    key = new_ingest_key()
    src.key_prefix, src.key_hash = key[:10], _hash_key(key)
    record(db, "soc.source.rotate_key", actor=p, resource_type="log_source", resource_id=src.id)
    return key


def source_by_key(db: Session, key: str) -> LogSource | None:
    if not key or not key.startswith("cri_"):
        return None
    return db.execute(select(LogSource).where(LogSource.key_hash == _hash_key(key), LogSource.is_enabled.is_(True))).scalar_one_or_none()


def builtin_source(db: Session, name: str, kind: str, demo: bool = False) -> LogSource:
    src = db.execute(select(LogSource).where(LogSource.name == name)).scalar_one_or_none()
    if src is None:
        desc = ("Security-relevant platform audit events (logins, permission denials, lab safety actions), forwarded automatically."
                if kind == "platform" else "Synthetic sample data for demonstrations. Every event and alert from it is labelled DEMO.")
        src = LogSource(name=name, kind=kind, description=desc, is_demo=demo)
        db.add(src)
        db.flush()
    return src


def seed(db: Session) -> dict:
    have = {r.code: r for r in db.execute(select(DetectionRule).where(DetectionRule.is_builtin.is_(True))).scalars()}
    have_codes = {c for (c,) in db.execute(select(DetectionRule.code))}
    n = 0
    for r in BUILTIN_RULES:
        if r["code"] in have and have[r["code"]].description != r["description"]:
            have[r["code"]].description = r["description"]   # keep built-in descriptions current (e.g. translations)
        if r["code"] in ("CR-AD-001", "CR-AD-002") and r["code"] in have and have[r["code"]].conditions == AD_FAILED_LOGON_V13:
            have[r["code"]].conditions = AD_FAILED_LOGON     # 1.4: also count Windows Kerberos failures
        if r["code"] not in have_codes:
            db.add(DetectionRule(**r, is_builtin=True, origin="builtin"))
            n += 1
    builtin_source(db, PLATFORM_SOURCE, "platform")
    db.flush()
    return {"rules_created": n}


# ------------------------------------------------------------------ ingest
def _event_dict(e: SecurityEvent) -> dict:
    return {k: getattr(e, k) for k in ("id", "source_id", "occurred_at", "dataset", "category", "action", "outcome", "severity", "src_ip",
                                       "src_port", "dst_ip", "dst_port", "protocol", "host", "user", "signature", "signature_id", "message", "is_demo")}


def ingest(db: Session, src: LogSource, records: list, *, kind: str | None = None, dataset_hint: str | None = None) -> dict:
    """Normalize and store records. Returns counts; never raises for individual bad records."""
    if len(records) > MAX_BATCH:
        raise AppError(f"Batch too large (max {MAX_BATCH} records)", code="batch_too_large", status_code=413)
    kind = kind or src.kind
    accepted, duplicates, skipped, rejected = [], 0, 0, []
    now = utcnow()
    for i, raw in enumerate(records):
        if isinstance(raw, dict) and "__invalid_line__" in raw:
            rejected.append({"index": i, "reason": f"line {raw['__invalid_line__']} is not valid JSON"})
            continue
        try:
            if kind == "zeek":
                ev = norm.zeek(raw, (dataset_hint or "").removeprefix("zeek.") or None)
            else:
                ev = norm.normalize(kind, raw)
        except norm.Skip:
            skipped += 1
            continue
        except (norm.NormalizeError, ValueError, TypeError, KeyError) as e:
            if len(rejected) < 50:
                rejected.append({"index": i, "reason": str(e)[:200]})
            continue
        row = {**ev, "source_id": src.id, "event_uid": norm.uid_for(raw), "ingested_at": now, "is_demo": src.is_demo,
               "raw": raw if isinstance(raw, dict) else {"line": raw}}
        res = db.execute(insert(SecurityEvent).prefix_with("IGNORE").values(**row))
        if res.rowcount == 1:
            row["id"] = res.inserted_primary_key[0]
            accepted.append(row)
        else:
            duplicates += 1
    if accepted:
        src.events_total = (src.events_total or 0) + len(accepted)
        src.last_event_at = max(src.last_event_at or accepted[0]["occurred_at"], max(a["occurred_at"] for a in accepted))
    alerts = detect(db, accepted) if accepted else []
    if accepted:
        from app.intel.service import match_events  # threat-intel sightings share the ingest transaction
        alerts += match_events(db, accepted)
    if alerts:
        _after_alerts(db, alerts)
    db.commit()
    if accepted:
        latest = sorted(accepted, key=lambda r: r["occurred_at"])[-20:]
        publish("events", {"source": src.name, "count": len(accepted), "latest": [{k: v for k, v in r.items() if k != "raw"} for r in latest]})
    for a in alerts:
        publish("alert", a)
    return {"accepted": len(accepted), "duplicates": duplicates, "skipped": skipped, "rejected": len(rejected),
            "errors": rejected, "alerts": len(alerts)}


def _after_alerts(db: Session, alerts: list[dict]) -> None:
    """Notifications and SOAR auto-playbooks for alerts created in this batch. Both are best effort and never fail ingest."""
    new = [a for a in alerts if a.get("created")]
    if not new:
        return
    from app.soar.service import auto_trigger
    auto_trigger(db, new)


# ------------------------------------------------------------------ detection
def _threshold_hit(db: Session, rule: DetectionRule, ev: dict) -> bool:
    t = rule.threshold
    g = ev.get(t["group_by"])
    if g is None:
        return False
    col = getattr(SecurityEvent, t["group_by"])
    start = ev["occurred_at"] - timedelta(seconds=t["window_seconds"])
    q = select(SecurityEvent).where(col == g, SecurityEvent.occurred_at.between(start, ev["occurred_at"]),
                                    SecurityEvent.is_demo.is_(ev["is_demo"]))
    for c in rule.conditions:  # push simple equality filters into SQL
        if c["op"] == "eq" and c["field"] in ("category", "dataset", "outcome", "protocol", "action"):
            q = q.where(getattr(SecurityEvent, c["field"]) == c["value"])
    rows = db.execute(q.order_by(SecurityEvent.occurred_at.desc()).limit(5000)).scalars().all()
    hits = [r for r in rows if matches(rule.conditions, _event_dict(r))]
    n = len({getattr(r, t["distinct"]) for r in hits}) if t.get("distinct") else len(hits)
    return n >= t["count"]


def _upsert_alert(db: Session, rule: DetectionRule, ev: dict, group_key: str) -> tuple[Alert, bool]:
    a = db.execute(select(Alert).where(Alert.rule_id == rule.id, Alert.group_key == group_key, Alert.status.in_(ALERT_OPEN),
                                       Alert.is_demo.is_(ev["is_demo"])).with_for_update().limit(1)).scalar_one_or_none()
    created = a is None
    if created:
        label = f" · {rule.threshold['group_by'] if rule.kind == 'threshold' else rule.group_by}={group_key}" if group_key else ""
        a = Alert(rule_id=rule.id, title=f"{rule.name}{label}"[:255], severity=rule.severity, status="new", group_key=group_key,
                  first_seen=ev["occurred_at"], last_seen=ev["occurred_at"], event_count=0, is_demo=ev["is_demo"])
        db.add(a)
        db.flush()
    a.event_count += 1
    a.last_seen = max(a.last_seen, ev["occurred_at"])
    a.first_seen = min(a.first_seen, ev["occurred_at"])
    # Keep the most recent MAX_LINKS_PER_ALERT events linked (a rolling window), not the first ones: a long-lived open
    # alert (e.g. one attacker address across many lab exercises) must still link new evidence, or later detections
    # become invisible to the purple team view, the assessment report and alert-based forensics/SOAR.
    res = db.execute(insert(AlertEvent).prefix_with("IGNORE").values(alert_id=a.id, event_id=ev["id"]))
    if res.rowcount and a.event_count > MAX_LINKS_PER_ALERT:
        db.execute(text("DELETE FROM alert_events WHERE alert_id = :a ORDER BY event_id LIMIT 1"), {"a": a.id})
    rule.hits += 1
    rule.last_hit_at = utcnow()
    return a, created


def detect(db: Session, events: list[dict]) -> list[dict]:
    rules = db.execute(select(DetectionRule).where(DetectionRule.is_enabled.is_(True))).scalars().all()
    touched: dict[int, dict] = {}
    for ev in sorted(events, key=lambda e: e["occurred_at"]):
        for rule in rules:
            if rule.kind not in ("match", "threshold"):  # e.g. "intel": evaluated by the threat-intel matcher
                continue
            if not matches(rule.conditions, ev):
                continue
            if rule.kind == "threshold":
                if not _threshold_hit(db, rule, ev):
                    continue
                gk = str(ev.get(rule.threshold["group_by"]))
            else:
                gk = str(ev.get(rule.group_by) or "") if rule.group_by else ""
            a, created = _upsert_alert(db, rule, ev, gk[:255])
            touched[a.id] = {"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "event_count": a.event_count,
                             "is_demo": a.is_demo, "created": created or touched.get(a.id, {}).get("created", False), "last_seen": a.last_seen}
    return list(touched.values())


# ------------------------------------------------------------------ platform telemetry (real, from the audit log)
def forward_platform_audit(db: Session, limit: int = 2000) -> int:
    src = builtin_source(db, PLATFORM_SOURCE, "platform")
    db.execute(select(LogSource).where(LogSource.id == src.id).with_for_update())
    rows = db.execute(select(AuditLog).where(AuditLog.id > src.cursor).order_by(AuditLog.id).limit(limit)).scalars().all()
    recs = []
    for r in rows:
        a = r.action
        base = {"event_uid": f"audit-{r.id}", "timestamp": r.occurred_at.isoformat() + "Z", "src_ip": r.ip_address, "user": r.actor_label[:128],
                "action": a, "outcome": "success" if r.outcome == "success" else "failure", "host": "cyber-range"}
        if a.startswith("auth."):
            login = (r.details or {}).get("login") if r.outcome != "success" else None
            recs.append({**base, "dataset": "platform.auth", "category": "auth", "severity": "low" if r.outcome != "success" else "info",
                         "user": (login or r.actor_label)[:128], "message": f"{a} {r.outcome} for {login or r.actor_label}"})
        elif a == "authz.denied":
            recs.append({**base, "dataset": "platform.authz", "category": "platform", "severity": "low", "signature": (r.resource_id or "")[:255],
                         "message": f"permission denied for {r.actor_label} on {r.resource_type} {r.resource_id} missing={(r.details or {}).get('missing')}"})
        elif a.startswith("lab."):
            sig = None
            if a == "lab.killswitch":
                sig = "engaged" if (r.details or {}).get("engaged") else "released"
            recs.append({**base, "dataset": "platform.lab", "category": "platform", "severity": "high" if sig == "engaged" else "info",
                         "signature": sig, "message": f"{a} by {r.actor_label} on {r.resource_type} {r.resource_id}"})
        elif a.startswith(("iam.", "system.settings")):
            recs.append({**base, "dataset": "platform.admin", "category": "platform", "severity": "info",
                         "message": f"{a} by {r.actor_label} on {r.resource_type} {r.resource_id}"})
    if rows:
        src.cursor = rows[-1].id
    if recs:
        return ingest(db, src, recs, kind="json")["accepted"]
    db.commit()
    return 0


# ------------------------------------------------------------------ DEMO dataset (synthetic, labelled)
def demo_records(now=None) -> list[tuple[str, object]]:
    """Synthetic sensor output using documentation address ranges (RFC 5737). Labelled DEMO end to end."""
    now = now or utcnow()
    t = lambda s: (now - timedelta(seconds=s)).isoformat() + "Z"  # noqa: E731
    out = []
    for i in range(8):  # SSH brute force from 203.0.113.45 against the LAN workstation
        out.append(("syslog", f"<38>1 {t(300 - i * 5)} ws-1 sshd 2211 - - Failed password for invalid user admin{i} from 203.0.113.45 port {50000 + i} ssh2"))
    out.append(("syslog", f"<38>1 {t(250)} ws-1 sshd 2211 - - Accepted publickey for analyst from 10.10.0.5 port 52044 ssh2"))
    for p in range(20, 46):  # port scan seen by Zeek
        out.append(("zeek", {"_path": "conn", "ts": (now - timedelta(seconds=200 - p)).timestamp(), "uid": f"CdemoScan{p}", "id.orig_h": "198.51.100.23",
                             "id.orig_p": 41000 + p, "id.resp_h": "172.16.10.10", "id.resp_p": p, "proto": "tcp", "conn_state": "REJ"}))
    out.append(("suricata", {"timestamp": t(180), "flow_id": 1001, "event_type": "alert", "src_ip": "198.51.100.23", "src_port": 41080,
                             "dest_ip": "172.16.10.10", "dest_port": 80, "proto": "TCP", "app_proto": "http",
                             "alert": {"action": "allowed", "signature_id": 2006546, "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected", "category": "Web Application Attack", "severity": 1}}))
    out.append(("suricata", {"timestamp": t(170), "flow_id": 1002, "event_type": "http", "src_ip": "198.51.100.23", "src_port": 41081,
                             "dest_ip": "172.16.10.10", "dest_port": 80, "proto": "TCP",
                             "http": {"hostname": "portal.corp.example", "url": "/search?q=1%27%20union%20select%20user,password%20from%20users--", "http_method": "GET", "status": 500, "http_user_agent": "sqlmap/1.8"}}))
    out.append(("suricata", {"timestamp": t(165), "flow_id": 1003, "event_type": "drop", "src_ip": "198.51.100.23", "src_port": 41090,
                             "dest_ip": "10.20.0.10", "dest_port": 3306, "proto": "TCP",
                             "alert": {"action": "blocked", "signature_id": 2010937, "signature": "ET SCAN Suspicious inbound to mySQL port 3306", "category": "Potentially Bad Traffic", "severity": 2}}))
    out.append(("zeek", {"_path": "dns", "ts": (now - timedelta(seconds=120)).timestamp(), "uid": "CdemoDns1", "id.orig_h": "10.10.0.22", "id.orig_p": 53211,
                         "id.resp_h": "10.10.0.1", "id.resp_p": 53, "proto": "udp", "query": "update-check.invoice-portal.xyz", "qtype_name": "A", "rcode_name": "NOERROR", "answers": ["192.0.2.66"]}))
    out.append(("zeek", {"_path": "notice", "ts": (now - timedelta(seconds=100)).timestamp(), "note": "Scan::Port_Scan", "msg": "198.51.100.23 scanned at least 25 unique ports of host 172.16.10.10 in 0m26s",
                         "src": "198.51.100.23", "dst": "172.16.10.10"}))
    for i in range(3):
        out.append(("wazuh", {"timestamp": t(60 - i * 10), "id": f"demo.{i}", "rule": {"level": 5, "description": "sudo: incorrect password attempt", "id": "5401", "groups": ["syslog", "sudo"]},
                              "agent": {"name": "fin-ws-2", "ip": "10.10.0.22"}, "data": {"srcuser": "jdoe", "dstuser": "root"},
                              "full_log": "jdoe : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/bash"}))
    return out


def load_demo(db: Session, p) -> dict:
    src = builtin_source(db, DEMO_SOURCE, "json", demo=True)
    totals = {"accepted": 0, "duplicates": 0, "alerts": 0, "rejected": 0}
    by_kind: dict[str, list] = {}
    for kind, rec in demo_records():
        by_kind.setdefault(kind, []).append(rec)
    for kind, recs in by_kind.items():
        r = ingest(db, src, recs, kind=kind)
        for k in totals:
            totals[k] += r[k]
    record(db, "soc.demo.load", actor=p, resource_type="log_source", resource_id=src.id, details=totals)
    db.commit()
    return totals


def purge_demo(db: Session, p) -> dict:
    src = db.execute(select(LogSource).where(LogSource.name == DEMO_SOURCE)).scalar_one_or_none()
    if not src:
        return {"events": 0, "alerts": 0}
    alerts = db.execute(select(Alert.id).where(Alert.is_demo.is_(True))).scalars().all()
    db.execute(update(Alert).where(Alert.id.in_(alerts or [0])).values(incident_id=None))
    db.execute(AlertEvent.__table__.delete().where(AlertEvent.alert_id.in_(alerts or [0])))
    db.execute(Alert.__table__.delete().where(Alert.id.in_(alerts or [0])))
    n = db.execute(SecurityEvent.__table__.delete().where(SecurityEvent.source_id == src.id)).rowcount
    db.execute(Incident.__table__.delete().where(Incident.is_demo.is_(True)))
    src.events_total, src.last_event_at = 0, None
    record(db, "soc.demo.purge", actor=p, resource_type="log_source", resource_id=src.id, details={"events": n, "alerts": len(alerts)})
    db.commit()
    return {"events": n, "alerts": len(alerts)}


# ------------------------------------------------------------------ search
ALIASES = {"src": "src_ip", "src_ip": "src_ip", "dst": "dst_ip", "dst_ip": "dst_ip", "sport": "src_port", "port": "dst_port", "dport": "dst_port",
           "dst_port": "dst_port", "src_port": "src_port", "user": "user", "host": "host", "sig": "signature", "signature": "signature",
           "sid": "signature_id", "cat": "category", "category": "category", "dataset": "dataset", "action": "action", "outcome": "outcome",
           "proto": "protocol", "protocol": "protocol", "source": "source_id"}


def parse_query(q: str):
    """`field:value` terms (AND), `-field:value` negation, `ip:x` (either side), `sev>=N`, `*` wildcards, free text on message."""
    clauses, errors = [], []
    try:
        tokens = shlex.split(q or "")
    except ValueError:
        return [], ["unbalanced quotes"]
    for tok in tokens:
        neg = tok.startswith("-") and ":" in tok
        t = tok[1:] if neg else tok
        c = None
        if t.startswith(("sev>=", "severity>=")):
            try:
                c = SecurityEvent.severity >= int(t.split(">=")[1])
            except ValueError:
                errors.append(f"bad severity in {tok}")
        elif ":" in t and t.split(":", 1)[0].lower() in (*ALIASES, "ip"):
            f, v = t.split(":", 1)
            f = f.lower()
            if f == "ip":
                c = or_(SecurityEvent.src_ip == v, SecurityEvent.dst_ip == v)
            else:
                col = getattr(SecurityEvent, ALIASES[f])
                if "*" in v:
                    c = col.like(v.replace("%", r"\%").replace("_", r"\_").replace("*", "%"))
                elif f in ("port", "dport", "dst_port", "sport", "src_port", "source"):
                    try:
                        c = col == int(v)
                    except ValueError:
                        errors.append(f"{f} needs a number")
                else:
                    c = col == v
        else:
            like = "%" + t.replace("%", r"\%").replace("_", r"\_") + "%"
            c = or_(SecurityEvent.message.like(like), SecurityEvent.signature.like(like))
        if c is not None:
            clauses.append(not_(c) if neg else c)
    return clauses, errors


def event_filters(q: str, start, end, *, include_demo: bool = True):
    clauses, errors = parse_query(q)
    w = [SecurityEvent.occurred_at >= start, SecurityEvent.occurred_at <= end, *clauses]
    if not include_demo:
        w.append(SecurityEvent.is_demo.is_(False))
    return and_(*w), errors


def histogram(db: Session, where, start, end) -> dict:
    span = (end - start).total_seconds()
    step = 60 if span <= 3 * 3600 else 300 if span <= 24 * 3600 else 3600 if span <= 7 * 86400 else 86400
    bucket = func.floor(func.unix_timestamp(SecurityEvent.occurred_at) / step) * step
    rows = db.execute(select(bucket.label("b"), func.count()).where(where).group_by("b").order_by("b")).all()
    return {"step_seconds": step, "buckets": [{"t": int(b), "count": n} for b, n in rows]}


def facets(db: Session, where, fields=("src_ip", "dst_ip", "category", "dataset", "signature")) -> dict:
    out = {}
    for f in fields:
        col = getattr(SecurityEvent, f)
        out[f] = [{"value": v, "count": n} for v, n in db.execute(
            select(col, func.count()).where(where, col.is_not(None)).group_by(col).order_by(func.count().desc()).limit(6))]
    return out


# ------------------------------------------------------------------ alerts & incidents
def get_alert(db: Session, alert_id: int, lock=False) -> Alert:
    q = select(Alert).where(Alert.id == alert_id)
    a = db.execute(q.with_for_update() if lock else q).scalar_one_or_none()
    if not a:
        raise NotFound("Alert not found")
    return a


def entry(db: Session, inc: Incident, p, kind: str, body: str = "", data: dict | None = None) -> None:
    db.add(IncidentEntry(incident_id=inc.id, author_id=p.id if p else None, kind=kind, body=body, data=data))


def link_alerts(db: Session, p, inc: Incident, alert_ids: list[int]) -> int:
    n = 0
    for aid in alert_ids:
        a = get_alert(db, aid, lock=True)
        if a.incident_id == inc.id:
            continue
        a.incident_id = inc.id
        if a.status == "new":
            a.status, a.acknowledged_at = "in_progress", utcnow()
        inc.severity = max(inc.severity, a.severity)
        entry(db, inc, p, "alert_linked", a.title, {"alert_id": a.id})
        n += 1
    return n


def counts_for_dashboard(db: Session, since) -> dict:
    """Real (non-DEMO) SOC figures for the command center."""
    import ipaddress
    real_e = SecurityEvent.is_demo.is_(False)
    ips = set()
    for col in (SecurityEvent.src_ip, SecurityEvent.dst_ip):
        ips |= {v for (v,) in db.execute(select(col).where(real_e, SecurityEvent.occurred_at >= since, col.is_not(None)).distinct().limit(20000))}
    assets = {i for i in ips if ipaddress.ip_address(i).is_private}
    hosts = {v for (v,) in db.execute(select(SecurityEvent.host).where(real_e, SecurityEvent.occurred_at >= since, SecurityEvent.category.in_(("auth", "host")),
                                                                         SecurityEvent.host.is_not(None)).distinct().limit(20000))}
    return {
        "total_alerts": db.execute(select(func.count()).select_from(Alert).where(Alert.is_demo.is_(False), Alert.first_seen >= since)).scalar_one(),
        "critical_alerts": db.execute(select(func.count()).select_from(Alert).where(Alert.is_demo.is_(False), Alert.first_seen >= since, Alert.severity >= 4)).scalar_one(),
        "open_alerts": db.execute(select(func.count()).select_from(Alert).where(Alert.is_demo.is_(False), Alert.status.in_(ALERT_OPEN))).scalar_one(),
        "open_incidents": db.execute(select(func.count()).select_from(Incident).where(Incident.is_demo.is_(False), Incident.status != "closed")).scalar_one(),
        "assets_monitored": len(assets | hosts),
        "threats_blocked": db.execute(select(func.count()).select_from(SecurityEvent).where(real_e, SecurityEvent.occurred_at >= since,
                                                                                            SecurityEvent.action.in_(("blocked", "drop")))).scalar_one(),
        # Sensor sources (not platform/DEMO) and how many delivered events in the last hour.
        "sensor_sources": db.execute(select(func.count()).select_from(LogSource).where(LogSource.kind != "platform", LogSource.is_demo.is_(False),
                                                                                       LogSource.is_enabled.is_(True))).scalar_one(),
        "sensor_sources_active": db.execute(select(func.count()).select_from(LogSource).where(
            LogSource.kind != "platform", LogSource.is_demo.is_(False), LogSource.is_enabled.is_(True),
            LogSource.last_event_at >= utcnow() - timedelta(hours=1))).scalar_one(),
    }

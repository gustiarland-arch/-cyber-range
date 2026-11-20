"""Threat intelligence service: import, matching against events (live and retro-hunt), sightings and alerts."""
import ipaddress
from datetime import timedelta

from sqlalchemy import func, insert, or_, select, update
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam.models import Alert, DetectionRule, SecurityEvent
from app.core.database import utcnow
from app.core.errors import AppError
from app.intel import normalize as nz
from app.intel.models import INDICATOR_TYPES, Indicator, IntelSource, Sighting

MANUAL_SOURCE = "Analyst submissions"
DEMO_SOURCE = "DEMO threat feed"
TI_RULE = "CR-TI-001"
MAX_IMPORT = 20000


def source(db: Session, name: str, kind: str = "manual", demo: bool = False, description: str = "") -> IntelSource:
    s = db.execute(select(IntelSource).where(IntelSource.name == name)).scalar_one_or_none()
    if s is None:
        s = IntelSource(name=name, kind=kind, is_demo=demo, description=description)
        db.add(s)
        db.flush()
    return s


def seed(db: Session) -> dict:
    source(db, MANUAL_SOURCE, "manual", description="Indicators added by analysts in the platform.")
    return {}


def upsert(db: Session, src: IntelSource, items: list[dict], actor_id: int | None = None) -> dict:
    """Insert or refresh indicators for one source. Invalid items are reported, never silently dropped."""
    if len(items) > MAX_IMPORT:
        raise AppError(f"At most {MAX_IMPORT} indicators per import", code="import_too_large", status_code=413)
    created = updated = 0
    errors, ids = [], []
    now = utcnow()
    for i, it in enumerate(items):
        try:
            t = (it.get("type") or nz.detect_type(it["value"])).lower()
            if t not in INDICATOR_TYPES:
                raise nz.IndicatorError(f"unknown type {t!r}")
            val = nz.normalize(t, it["value"])
            conf = int(it.get("confidence", src.default_confidence))
            sev = int(it.get("severity", 2))
            if not (0 <= conf <= 100 and 0 <= sev <= 4):
                raise nz.IndicatorError("confidence must be 0-100 and severity 0-4")
        except (nz.IndicatorError, KeyError, ValueError, TypeError) as e:
            if len(errors) < 100:
                errors.append(f"item {i + 1}: {e}")
            continue
        key = nz.value_key(val)
        ind = db.execute(select(Indicator).where(Indicator.source_id == src.id, Indicator.type == t, Indicator.value_key == key)).scalar_one_or_none()
        tags = sorted({str(x)[:48] for x in (it.get("tags") or [])})[:20]
        if ind is None:
            ind = Indicator(source_id=src.id, type=t, value=val, value_key=key, confidence=conf, severity=sev, tags=tags,
                            description=str(it.get("description") or "")[:4000], first_seen=it.get("first_seen") or now, last_seen=now,
                            valid_until=it.get("valid_until"), is_demo=src.is_demo, external_id=it.get("external_id"), created_by=actor_id)
            db.add(ind)
            created += 1
        else:
            ind.last_seen, ind.confidence, ind.severity, ind.is_active = now, conf, sev, True
            ind.tags = sorted(set(ind.tags or []) | set(tags))[:20]
            if it.get("description"):
                ind.description = str(it["description"])[:4000]
            if "valid_until" in it:
                ind.valid_until = it["valid_until"]
            updated += 1
        db.flush()
        ids.append(ind.id)
    src.indicators_total = db.execute(select(func.count()).select_from(Indicator).where(Indicator.source_id == src.id)).scalar_one()
    src.last_import_at = now
    return {"created": created, "updated": updated, "errors": errors, "ids": ids}


# ------------------------------------------------------------------ matching
def _parents(domain: str) -> list[str]:
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts) - 1)]


def _lookup(db: Session, events: list[dict]) -> list[tuple[dict, Indicator, str]]:
    per_event = {}
    keys: dict[str, set] = {}
    for ev in events:
        c = nz.candidates(ev)
        extra = [("domain", p, f) for (t, v, f) in c if t == "domain" for p in _parents(v)]
        per_event[ev["id"]] = c + extra
        for t, v, _f in per_event[ev["id"]]:
            keys.setdefault(t, set()).add(nz.value_key(v))
    if not keys:
        return []
    now = utcnow()
    active = [Indicator.is_active.is_(True), or_(Indicator.valid_until.is_(None), Indicator.valid_until > now)]
    conds = [(Indicator.type == t) & Indicator.value_key.in_(list(vs)[:5000]) for t, vs in keys.items()]
    found = db.execute(select(Indicator).where(*active, or_(*conds))).scalars().all()
    index: dict[tuple, list] = {}
    for ind in found:
        index.setdefault((ind.type, ind.value_key), []).append(ind)
    cidrs = db.execute(select(Indicator).where(*active, Indicator.type == "cidr")).scalars().all() if "ip" in keys else []
    nets = [(ipaddress.ip_network(c.value), c) for c in cidrs]
    out = []
    for ev in events:
        seen = set()
        for t, v, f in per_event[ev["id"]]:
            hits = list(index.get((t, nz.value_key(v)), []))
            if t == "ip" and nets:
                ip = ipaddress.ip_address(v)
                hits += [c for n, c in nets if ip.version == n.version and ip in n]
            for ind in hits:
                if ind.is_demo and not ev.get("is_demo"):
                    continue  # DEMO intel never flags real telemetry
                if ind.id not in seen:
                    seen.add(ind.id)
                    out.append((ev, ind, f))
    return out


def match_events(db: Session, events: list[dict], via: str = "ingest") -> list[dict]:
    """Record sightings for newly stored events and raise CR-TI-001 alerts. Called from SOC ingest inside its transaction."""
    from app.blueteam.service import _upsert_alert
    hits = _lookup(db, events)
    if not hits:
        return []
    rule = db.execute(select(DetectionRule).where(DetectionRule.code == TI_RULE)).scalar_one_or_none()
    touched = {}
    for ev, ind, field in hits:
        res = db.execute(insert(Sighting).prefix_with("IGNORE").values(indicator_id=ind.id, event_id=ev["id"], field=field,
                                                                         seen_at=ev["occurred_at"], via=via, is_demo=bool(ev.get("is_demo"))))
        if res.rowcount != 1:
            continue
        ind.sightings_count += 1
        ind.last_sighted_at = max(ind.last_sighted_at or ev["occurred_at"], ev["occurred_at"])
        if rule is None or not rule.is_enabled or ind.confidence < 30:
            continue  # low-confidence intel is recorded as sightings only
        a, created = _upsert_alert(db, rule, {**ev, "is_demo": bool(ev.get("is_demo"))}, f"{ind.type}:{ind.value}"[:255])
        a.severity = max(a.severity, ind.severity)
        touched[a.id] = {"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "event_count": a.event_count,
                         "is_demo": a.is_demo, "created": created or touched.get(a.id, {}).get("created", False), "last_seen": a.last_seen}
    return list(touched.values())


def retro_hunt(db: Session, p, days: int = 7, indicator_ids: list[int] | None = None) -> dict:
    """Scan stored events from the last `days` for current indicators. Idempotent: existing sightings are not duplicated."""
    since = utcnow() - timedelta(days=days)
    from app.blueteam.service import _event_dict
    scanned = 0
    alerts: dict[int, dict] = {}
    before = db.execute(select(func.count()).select_from(Sighting)).scalar_one()
    q = select(SecurityEvent).where(SecurityEvent.occurred_at >= since).order_by(SecurityEvent.id)
    if indicator_ids:
        inds = db.execute(select(Indicator).where(Indicator.id.in_(indicator_ids))).scalars().all()
        ips = [i.value for i in inds if i.type == "ip"]
        if inds and len(ips) == len(inds):  # pure IP hunt: push the filter into SQL
            q = q.where(or_(SecurityEvent.src_ip.in_(ips), SecurityEvent.dst_ip.in_(ips)))
    last = 0
    while True:
        rows = db.execute(q.where(SecurityEvent.id > last).limit(2000)).scalars().all()
        if not rows:
            break
        last = rows[-1].id
        evs = [{**_event_dict(r), "raw": r.raw} for r in rows]
        scanned += len(evs)
        for a in match_events(db, evs, via="retrohunt"):
            alerts[a["id"]] = a
        db.flush()
        if scanned >= 200000:
            break
    new = db.execute(select(func.count()).select_from(Sighting)).scalar_one() - before
    record(db, "intel.retrohunt", actor=p, resource_type="indicator", resource_id=",".join(map(str, indicator_ids or []))[:64] or "all",
           details={"days": days, "scanned": scanned, "new_sightings": new, "alerts": len(alerts)})
    db.commit()
    return {"scanned": scanned, "new_sightings": new, "alerts": len(alerts)}


def expire(db: Session) -> int:
    n = db.execute(update(Indicator).where(Indicator.is_active.is_(True), Indicator.valid_until.is_not(None), Indicator.valid_until < utcnow())
                   .values(is_active=False)).rowcount
    db.commit()
    return n


def lookup_values(db: Session, values: list[str]) -> list[Indicator]:
    keys = set()
    for v in values:
        try:
            t = nz.detect_type(v)
            keys.add((t, nz.value_key(nz.normalize(t, v))))
        except nz.IndicatorError:
            continue
    if not keys:
        return []
    return db.execute(select(Indicator).where(or_(*[(Indicator.type == t) & (Indicator.value_key == k) for t, k in keys]))).scalars().all()


# ------------------------------------------------------------------ DEMO feed (labelled, matches the SOC DEMO dataset)
DEMO_ITEMS = [
    {"type": "ip", "value": "198.51.100.23", "confidence": 80, "severity": 3, "tags": ["DEMO", "ssh-bruteforce"], "description": "DEMO: scanning and SSH brute-force source"},
    {"type": "ip", "value": "203.0.113.45", "confidence": 70, "severity": 3, "tags": ["DEMO", "web-attack"], "description": "DEMO: web exploitation attempts"},
    {"type": "domain", "value": "invoice-portal.xyz", "confidence": 75, "severity": 3, "tags": ["DEMO", "phishing"], "description": "DEMO: phishing landing domain"},
    {"type": "cidr", "value": "192.0.2.0/24", "confidence": 40, "severity": 1, "tags": ["DEMO"], "description": "DEMO: documentation range used by the sample dataset"},
]


def load_demo(db: Session, p) -> dict:
    src = source(db, DEMO_SOURCE, "demo", demo=True, description="Synthetic indicators for demonstrations. Labelled DEMO; they only ever match DEMO events.")
    res = upsert(db, src, DEMO_ITEMS, p.id)
    hunt = retro_hunt(db, p, days=30, indicator_ids=res["ids"])
    record(db, "intel.demo.load", actor=p, resource_type="intel_source", resource_id=src.id, details={"created": res["created"], **hunt})
    db.commit()
    return {"created": res["created"], "updated": res["updated"], **hunt}


def purge_demo(db: Session, p) -> dict:
    src = db.execute(select(IntelSource).where(IntelSource.name == DEMO_SOURCE)).scalar_one_or_none()
    if not src:
        return {"indicators": 0}
    n = db.execute(Indicator.__table__.delete().where(Indicator.source_id == src.id)).rowcount
    db.delete(src)
    record(db, "intel.demo.purge", actor=p, resource_type="intel_source", resource_id=src.id, details={"indicators": n})
    db.commit()
    return {"indicators": n}


def counts_for_dashboard(db: Session, since) -> dict:
    return {
        "intel_active_indicators": db.execute(select(func.count()).select_from(Indicator).where(Indicator.is_active.is_(True), Indicator.is_demo.is_(False))).scalar_one(),
        "intel_sightings": db.execute(select(func.count()).select_from(Sighting).where(Sighting.seen_at >= since, Sighting.is_demo.is_(False))).scalar_one(),
    }


def alert_ids_for_indicator(db: Session, ind: Indicator) -> list[int]:
    rule = db.execute(select(DetectionRule.id).where(DetectionRule.code == TI_RULE)).scalar_one_or_none()
    if not rule:
        return []
    return list(db.execute(select(Alert.id).where(Alert.rule_id == rule, Alert.group_key == f"{ind.type}:{ind.value}"[:255])).scalars())

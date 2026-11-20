"""Threat Intelligence API: indicators with provenance, imports, relationships, sightings, retro-hunt."""
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam.models import SecurityEvent
from app.core.database import get_db, utcnow
from app.core.errors import AppError, Conflict, NotFound
from app.iam.deps import Principal, require
from app.intel import normalize as nz
from app.intel import service as svc
from app.intel import feeds as fd
from app.intel.models import FEED_TYPES, INDICATOR_TYPES, RELATION_KINDS, Indicator, IndicatorRelation, IntelFeed, IntelSource, Sighting

router = APIRouter(prefix="/intel", tags=["intel"])
VIEW = Depends(require("intel.view"))
MANAGE = Depends(require("intel.manage"))


def _src_out(s: IntelSource):
    return {k: getattr(s, k) for k in ("id", "name", "kind", "description", "reference_url", "default_confidence", "is_demo",
                                       "indicators_total", "last_import_at", "created_at")}


def _ind_out(i: Indicator, sources: dict):
    return {"id": i.id, "type": i.type, "value": i.value, "source": sources.get(i.source_id), "source_id": i.source_id, "confidence": i.confidence,
            "severity": i.severity, "tags": i.tags or [], "description": i.description, "first_seen": i.first_seen, "last_seen": i.last_seen,
            "valid_until": i.valid_until, "is_active": i.is_active, "is_demo": i.is_demo, "sightings_count": i.sightings_count,
            "last_sighted_at": i.last_sighted_at, "external_id": i.external_id, "updated_at": i.updated_at}


def _sources(db):
    return dict(db.execute(select(IntelSource.id, IntelSource.name)).all())


@router.get("/overview")
def overview(days: int = Query(7, ge=1, le=90), include_demo: bool = True, db: Session = Depends(get_db), _p: Principal = VIEW):
    since = utcnow() - timedelta(days=days)
    demo = [] if include_demo else [Indicator.is_demo.is_(False)]
    sdemo = [] if include_demo else [Sighting.is_demo.is_(False)]
    by_type = dict(db.execute(select(Indicator.type, func.count()).where(Indicator.is_active.is_(True), *demo).group_by(Indicator.type)).all())
    b = func.date_format(Sighting.seen_at, "%Y-%m-%d")
    series = dict(db.execute(select(b, func.count()).where(Sighting.seen_at >= since, *sdemo).group_by(b)).all())
    labels = [(since + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days + 1)]
    srcs = _sources(db)
    top = db.execute(select(Indicator, func.count(Sighting.id).label("n")).join(Sighting, Sighting.indicator_id == Indicator.id)
                     .where(Sighting.seen_at >= since, *sdemo).group_by(Indicator.id).order_by(func.count(Sighting.id).desc()).limit(10)).all()
    recent = db.execute(select(Sighting, Indicator, SecurityEvent).join(Indicator, Indicator.id == Sighting.indicator_id)
                        .join(SecurityEvent, SecurityEvent.id == Sighting.event_id).where(*sdemo).order_by(Sighting.id.desc()).limit(15)).all()
    by_field = dict(db.execute(select(Sighting.field, func.count()).where(Sighting.seen_at >= since, *sdemo).group_by(Sighting.field)).all())
    by_source = db.execute(select(Indicator.source_id, func.count(Sighting.id)).join(Sighting, Sighting.indicator_id == Indicator.id)
                           .where(Sighting.seen_at >= since, *sdemo).group_by(Indicator.source_id)).all()
    return {
        "days": days, "active_by_type": {t: by_type.get(t, 0) for t in INDICATOR_TYPES}, "active_total": sum(by_type.values()),
        "sightings": {"labels": labels, "counts": [series.get(lbl, 0) for lbl in labels], "total": sum(series.values())},
        "sightings_by_field": by_field,
        "sightings_by_source": [{"source": srcs.get(s), "count": n} for s, n in by_source],
        "top_sighted": [{**_ind_out(i, srcs), "window_sightings": n} for i, n in top],
        "recent_sightings": [{"id": s.id, "seen_at": s.seen_at, "field": s.field, "via": s.via, "is_demo": s.is_demo,
                              "indicator": {"id": i.id, "type": i.type, "value": i.value, "severity": i.severity},
                              "event": {"id": e.id, "dataset": e.dataset, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "message": e.message[:200]}}
                             for s, i, e in recent],
        "sources": [_src_out(s) for s in db.execute(select(IntelSource).order_by(IntelSource.name)).scalars()],
    }


@router.get("/indicators")
def list_indicators(q: str = "", type: str = "", source_id: int | None = None, status: str = Query("active", pattern="^(active|inactive|all)$"),
                    sighted: bool = False, include_demo: bool = True, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                    db: Session = Depends(get_db), _p: Principal = VIEW):
    w = []
    if q:
        like = "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"
        w.append(or_(Indicator.value.like(like), Indicator.description.like(like)))
    if type:
        w.append(Indicator.type == type)
    if source_id:
        w.append(Indicator.source_id == source_id)
    if status != "all":
        w.append(Indicator.is_active.is_(status == "active"))
    if sighted:
        w.append(Indicator.sightings_count > 0)
    if not include_demo:
        w.append(Indicator.is_demo.is_(False))
    total = db.execute(select(func.count()).select_from(Indicator).where(*w)).scalar_one()
    rows = db.execute(select(Indicator).where(*w).order_by(Indicator.last_sighted_at.desc(), Indicator.updated_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    srcs = _sources(db)
    return {"total": total, "page": page, "page_size": page_size, "items": [_ind_out(i, srcs) for i in rows]}


@router.get("/indicators/{iid}")
def get_indicator(iid: int, db: Session = Depends(get_db), p: Principal = VIEW):
    i = db.get(Indicator, iid)
    if not i:
        raise NotFound("Indicator not found")
    srcs = _sources(db)
    out = _ind_out(i, srcs)
    rels = db.execute(select(IndicatorRelation).where(or_(IndicatorRelation.from_id == i.id, IndicatorRelation.to_id == i.id))).scalars().all()
    other = {x.id: x for x in db.execute(select(Indicator).where(Indicator.id.in_({r.from_id for r in rels} | {r.to_id for r in rels} | {0}))).scalars()}
    out["relations"] = [{"id": r.id, "kind": r.kind, "note": r.note, "direction": "out" if r.from_id == i.id else "in",
                         "other": _ind_out(other[r.to_id if r.from_id == i.id else r.from_id], srcs)} for r in rels]
    same = db.execute(select(Indicator).where(Indicator.type == i.type, Indicator.value_key == i.value_key, Indicator.id != i.id)).scalars().all()
    out["other_sources"] = [_ind_out(x, srcs) for x in same]
    sights = []
    if p.has("blueteam.alerts.view"):  # event content follows SOC permissions
        rows = db.execute(select(Sighting, SecurityEvent).join(SecurityEvent, SecurityEvent.id == Sighting.event_id)
                          .where(Sighting.indicator_id == i.id).order_by(Sighting.seen_at.desc()).limit(100)).all()
        sights = [{"id": s.id, "seen_at": s.seen_at, "field": s.field, "via": s.via, "is_demo": s.is_demo,
                   "event": {"id": e.id, "dataset": e.dataset, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port, "message": e.message[:300]}}
                  for s, e in rows]
        out["alert_ids"] = svc.alert_ids_for_indicator(db, i)
    out["sightings"] = sights
    out["sightings_visible"] = p.has("blueteam.alerts.view")
    return out


class IndicatorIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    value: str = Field(min_length=1, max_length=2048)
    type: str | None = None
    confidence: int = Field(default=50, ge=0, le=100)
    severity: int = Field(default=2, ge=0, le=4)
    tags: list[str] = Field(default_factory=list, max_length=20)
    description: str = Field(default="", max_length=4000)
    valid_until: datetime | None = None
    source_id: int | None = None


@router.post("/indicators", status_code=201)
def create_indicator(body: IndicatorIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    src = db.get(IntelSource, body.source_id) if body.source_id else svc.source(db, svc.MANUAL_SOURCE)
    if not src or src.is_demo:
        raise AppError("Choose a non-DEMO source", code="invalid_source", status_code=422)
    item = body.model_dump(exclude={"source_id"})
    if item["valid_until"]:
        item["valid_until"] = item["valid_until"].replace(tzinfo=None)
    res = svc.upsert(db, src, [item], p.id)
    if res["errors"]:
        raise AppError(res["errors"][0].split(": ", 1)[-1], code="invalid_indicator", status_code=422, details=res["errors"])
    ind = db.get(Indicator, res["ids"][0])
    record(db, "intel.indicator.create" if res["created"] else "intel.indicator.refresh", actor=p, resource_type="indicator", resource_id=ind.id,
           details={"type": ind.type, "source": src.name})
    db.commit()
    hunt = svc.retro_hunt(db, p, days=7, indicator_ids=[ind.id])
    return {**_ind_out(ind, _sources(db)), "retrohunt": hunt}


class IndicatorPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: int | None = Field(default=None, ge=0, le=4)
    tags: list[str] | None = Field(default=None, max_length=20)
    description: str | None = Field(default=None, max_length=4000)
    valid_until: datetime | None = None
    is_active: bool | None = None


@router.patch("/indicators/{iid}")
def patch_indicator(iid: int, body: IndicatorPatch, db: Session = Depends(get_db), p: Principal = MANAGE):
    i = db.get(Indicator, iid)
    if not i:
        raise NotFound("Indicator not found")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        if k == "valid_until" and v is not None:
            v = v.replace(tzinfo=None)
        if k == "tags":
            v = sorted({str(t)[:48] for t in v})
        setattr(i, k, v)
    record(db, "intel.indicator.update", actor=p, resource_type="indicator", resource_id=i.id, details={"changed": sorted(changes)})
    db.commit()
    return _ind_out(i, _sources(db))


@router.delete("/indicators/{iid}", status_code=204)
def delete_indicator(iid: int, db: Session = Depends(get_db), p: Principal = MANAGE):
    i = db.get(Indicator, iid)
    if not i:
        raise NotFound("Indicator not found")
    if i.sightings_count:
        raise Conflict("The indicator has sightings; deactivate it instead to keep the history")
    record(db, "intel.indicator.delete", actor=p, resource_type="indicator", resource_id=i.id, details={"type": i.type})
    db.delete(i)
    db.commit()


class RelationIn(BaseModel):
    to_id: int
    kind: str = Field(pattern="^(" + "|".join(RELATION_KINDS) + ")$")
    note: str = Field(default="", max_length=512)


@router.post("/indicators/{iid}/relations", status_code=201)
def add_relation(iid: int, body: RelationIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    if iid == body.to_id or not db.get(Indicator, iid) or not db.get(Indicator, body.to_id):
        raise AppError("Both indicators must exist and differ", code="invalid_relation", status_code=422)
    if db.execute(select(IndicatorRelation.id).where(IndicatorRelation.from_id == iid, IndicatorRelation.to_id == body.to_id, IndicatorRelation.kind == body.kind)).first():
        raise Conflict("This relationship exists")
    r = IndicatorRelation(from_id=iid, to_id=body.to_id, kind=body.kind, note=body.note, created_by=p.id)
    db.add(r)
    db.flush()
    record(db, "intel.relation.create", actor=p, resource_type="indicator", resource_id=iid, details={"to": body.to_id, "kind": body.kind})
    db.commit()
    return {"id": r.id}


@router.delete("/relations/{rid}", status_code=204)
def delete_relation(rid: int, db: Session = Depends(get_db), p: Principal = MANAGE):
    r = db.get(IndicatorRelation, rid)
    if not r:
        raise NotFound("Relationship not found")
    record(db, "intel.relation.delete", actor=p, resource_type="indicator", resource_id=r.from_id, details={"to": r.to_id, "kind": r.kind})
    db.delete(r)
    db.commit()


# ------------------------------------------------------------------ sources and imports
@router.get("/sources")
def list_sources(db: Session = Depends(get_db), _p: Principal = VIEW):
    return [_src_out(s) for s in db.execute(select(IntelSource).order_by(IntelSource.name)).scalars()]


class SourceIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=128)
    description: str = Field(default="", max_length=2000)
    reference_url: str | None = Field(default=None, max_length=512, pattern=r"^https?://\S+$")
    default_confidence: int = Field(default=50, ge=0, le=100)


@router.post("/sources", status_code=201)
def create_source(body: SourceIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    if db.execute(select(IntelSource.id).where(IntelSource.name == body.name)).first():
        raise Conflict("A source with this name exists")
    s = IntelSource(**body.model_dump(), kind="feed", created_by=p.id)
    db.add(s)
    db.flush()
    record(db, "intel.source.create", actor=p, resource_type="intel_source", resource_id=s.id, details={"name": s.name})
    db.commit()
    return _src_out(s)


class ImportIn(BaseModel):
    format: str = Field(pattern="^(text|csv|stix|misp)$")
    text: str = Field(min_length=1, max_length=5_000_000)
    retrohunt_days: int = Field(default=7, ge=0, le=90)


@router.post("/sources/{sid}/import")
def import_indicators(sid: int, body: ImportIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    src = db.get(IntelSource, sid)
    if not src:
        raise NotFound("Source not found")
    if src.is_demo:
        raise AppError("The DEMO feed is managed by the platform", code="invalid_source", status_code=422)
    items, parse_errors = nz.parse(body.format, body.text)
    res = svc.upsert(db, src, items, p.id)
    errors = (parse_errors + res["errors"])[:100]
    record(db, "intel.import", actor=p, resource_type="intel_source", resource_id=src.id,
           details={"format": body.format, "created": res["created"], "updated": res["updated"], "errors": len(parse_errors) + len(res["errors"])})
    db.commit()
    hunt = svc.retro_hunt(db, p, days=body.retrohunt_days, indicator_ids=res["ids"]) if body.retrohunt_days and res["ids"] else None
    return {"parsed": len(items), "created": res["created"], "updated": res["updated"], "errors": errors, "retrohunt": hunt}


class HuntIn(BaseModel):
    days: int = Field(default=7, ge=1, le=90)
    indicator_ids: list[int] | None = Field(default=None, max_length=5000)


@router.post("/retrohunt")
def retrohunt(body: HuntIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    return svc.retro_hunt(db, p, days=body.days, indicator_ids=body.indicator_ids)


@router.get("/lookup")
def lookup(value: list[str] = Query(default_factory=list, max_length=50), event_id: int | None = None, db: Session = Depends(get_db), _p: Principal = VIEW):
    """Which indicators know these values, or which indicators were sighted in one event."""
    srcs = _sources(db)
    if event_id:
        rows = db.execute(select(Indicator, Sighting.field).join(Sighting, Sighting.indicator_id == Indicator.id).where(Sighting.event_id == event_id)).all()
        return [{**_ind_out(i, srcs), "field": f} for i, f in rows]
    return [_ind_out(i, srcs) for i in svc.lookup_values(db, value)]


@router.post("/demo")
def demo_load(db: Session = Depends(get_db), p: Principal = MANAGE):
    return svc.load_demo(db, p)


@router.delete("/demo")
def demo_purge(db: Session = Depends(get_db), p: Principal = MANAGE):
    return svc.purge_demo(db, p)


@router.get("/meta")
def meta(_p: Principal = VIEW):
    return {"types": INDICATOR_TYPES, "relation_kinds": RELATION_KINDS, "formats": ["text", "csv", "stix"]}




# ------------------------------------------------------------------ scheduled feeds (MISP, TAXII 2.1, STIX/text/CSV URL)
def _feed_out(f: IntelFeed, src_name: str | None = None):
    return {"id": f.id, "source_id": f.source_id, "source": src_name, "feed_type": f.feed_type, "url": f.url, "collection_id": f.collection_id,
            "auth_env": f.auth_env, "auth_scheme": f.auth_scheme, "auth_configured": bool(f.auth_scheme == "none" or (f.auth_env and os.environ.get(f.auth_env))),
            "interval_minutes": f.interval_minutes, "verify_tls": f.verify_tls, "is_enabled": f.is_enabled, "cursor": f.cursor,
            "last_run_at": f.last_run_at, "last_status": f.last_status, "last_error": f.last_error, "last_count": f.last_count, "created_at": f.created_at}


class FeedIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=128)
    feed_type: str
    url: str = Field(min_length=8, max_length=512, pattern=r"^https?://\S+$")
    collection_id: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    auth_scheme: str = Field(default="none", pattern="^(none|misp|bearer|basic)$")
    auth_env: str | None = Field(default=None, max_length=64)
    interval_minutes: int = Field(default=60, ge=5, le=10080)
    verify_tls: bool = True
    default_confidence: int = Field(default=60, ge=0, le=100)
    is_enabled: bool = True


def _check_feed(b: FeedIn):
    if b.feed_type not in FEED_TYPES:
        raise AppError(f"feed_type must be one of {', '.join(FEED_TYPES)}", code="validation_error", status_code=422)
    if b.auth_scheme != "none" and not (b.auth_env and fd.ENV_RX.match(b.auth_env)):
        raise AppError("Name the environment variable that holds the secret, e.g. CR_FEED_MISP_KEY (CR_FEED_ + letters, digits, _)",
                       code="validation_error", status_code=422)
    if b.feed_type == "taxii21" and not b.collection_id:
        raise AppError("A TAXII feed needs a collection id", code="validation_error", status_code=422)
    try:
        fd.check_url(b.url)
    except fd.FeedError as e:
        raise AppError(f"Feed URL rejected: {e}", code="invalid_feed_url", status_code=422) from None


@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db), _p: Principal = VIEW):
    names = _sources(db)
    return {"feeds": [_feed_out(f, names.get(f.source_id)) for f in db.execute(select(IntelFeed).order_by(IntelFeed.id)).scalars()],
            "types": FEED_TYPES, "allow_private": fd.allow_private()}


@router.post("/feeds", status_code=201)
def create_feed(body: FeedIn, db: Session = Depends(get_db), p: Principal = MANAGE):
    _check_feed(body)
    if db.execute(select(IntelSource.id).where(IntelSource.name == body.name)).first():
        raise Conflict("A source with this name exists")
    src = IntelSource(name=body.name, kind="feed", description=f"{body.feed_type} feed {body.url}"[:2000], reference_url=body.url,
                      default_confidence=body.default_confidence, created_by=p.id)
    db.add(src)
    db.flush()
    f = IntelFeed(source_id=src.id, created_by=p.id, **body.model_dump(exclude={"name", "default_confidence"}))
    db.add(f)
    db.flush()
    record(db, "intel.feed.create", actor=p, resource_type="intel_feed", resource_id=f.id, details={"type": f.feed_type, "url": f.url})
    db.commit()
    return _feed_out(f, src.name)


@router.patch("/feeds/{fid}")
def patch_feed(fid: int, body: dict, db: Session = Depends(get_db), p: Principal = MANAGE):
    f = db.get(IntelFeed, fid)
    if not f:
        raise NotFound("Feed not found")
    allowed = {"is_enabled": bool, "interval_minutes": int, "verify_tls": bool}
    for k, v in body.items():
        if k not in allowed or not isinstance(v, allowed[k]) or (k == "interval_minutes" and not 5 <= v <= 10080):
            raise AppError(f"Field {k} cannot be set this way", code="validation_error", status_code=422)
        setattr(f, k, v)
    record(db, "intel.feed.update", actor=p, resource_type="intel_feed", resource_id=f.id, details=body)
    db.commit()
    return _feed_out(f, _sources(db).get(f.source_id))


@router.post("/feeds/{fid}/run")
def run_feed_now(fid: int, db: Session = Depends(get_db), p: Principal = MANAGE):
    f = db.get(IntelFeed, fid)
    if not f:
        raise NotFound("Feed not found")
    return {"result": fd.run_feed(db, f, p), "feed": _feed_out(db.get(IntelFeed, fid), _sources(db).get(f.source_id))}


@router.delete("/feeds/{fid}", status_code=204)
def delete_feed(fid: int, db: Session = Depends(get_db), p: Principal = MANAGE):
    f = db.get(IntelFeed, fid)
    if not f:
        raise NotFound("Feed not found")
    record(db, "intel.feed.delete", actor=p, resource_type="intel_feed", resource_id=f.id, details={"url": f.url})
    db.delete(f)   # the source and its indicators stay (provenance); deactivate them separately if needed
    db.commit()

"""Scheduled threat-intel feeds: MISP (restSearch), TAXII 2.1 collections and plain STIX/text/CSV URLs.

* Secrets never enter the database or the UI: a feed names an environment variable (CR_FEED_<NAME>) on the worker.
* Feeds may only point at private/loopback addresses when CR_INTEL_FEED_ALLOW_PRIVATE=true (many MISP servers live on
  the LAN, but by default the platform refuses to be used as a proxy into internal networks).
* Each run pulls what changed since the last successful run (TAXII `added_after`, MISP `timestamp`), upserts the
  indicators into the feed's source and retro-hunts them against the last 7 days of events.
"""
import ipaddress
import json
import os
import re
import socket
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import SessionLocal, utcnow
from app.core.errors import AppError
from app.core.logging import log
from app.intel import normalize as nz
from app.intel import service as svc
from app.intel.models import IntelFeed, IntelSource

ENV_RX = re.compile(r"^CR_FEED_[A-Z0-9_]{1,40}$")
MAX_BYTES = 20 * 1024 * 1024
MAX_PAGES = 20
TAXII_ACCEPT = "application/taxii+json;version=2.1"


class FeedError(Exception):
    pass


def allow_private() -> bool:
    return os.environ.get("CR_INTEL_FEED_ALLOW_PRIVATE", "false").lower() in ("1", "true", "yes")


def check_url(url: str) -> None:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise FeedError("URL must start with http:// or https://")
    if u.username or u.password:
        raise FeedError("put credentials in an environment variable, not in the URL")
    if allow_private():
        return
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80))}
    except socket.gaierror as e:
        raise FeedError(f"cannot resolve {u.hostname}: {e}") from None
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise FeedError(f"{u.hostname} resolves to a private address ({a}); set CR_INTEL_FEED_ALLOW_PRIVATE=true to allow internal feeds")


def _headers(f: IntelFeed) -> dict:
    h = {"User-Agent": "cyber-range-intel/1.2"}
    if f.auth_scheme == "none":
        return h
    secret = os.environ.get(f.auth_env or "", "")
    if not secret:
        raise FeedError(f"environment variable {f.auth_env} is not set on the worker")
    if f.auth_scheme == "misp":
        h["Authorization"] = secret
    elif f.auth_scheme == "bearer":
        h["Authorization"] = f"Bearer {secret}"
    elif f.auth_scheme == "basic":
        import base64
        h["Authorization"] = "Basic " + base64.b64encode(secret.encode()).decode()   # secret is "user:password"
    return h


def _client(f: IntelFeed) -> httpx.Client:
    return httpx.Client(timeout=30, verify=f.verify_tls, follow_redirects=False, headers=_headers(f))


def _read(resp: httpx.Response) -> bytes:
    if resp.status_code >= 400:
        raise FeedError(f"HTTP {resp.status_code} from {resp.request.url.host}: {resp.text[:200]}")
    body = resp.content
    if len(body) > MAX_BYTES:
        raise FeedError("feed response larger than 20 MB")
    return body


def fetch(f: IntelFeed) -> tuple[list[dict], list[str], str | None]:
    """Return (items, parse errors, new cursor)."""
    check_url(f.url)
    started = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    with _client(f) as c:
        if f.feed_type == "taxii21":
            if not f.collection_id:
                raise FeedError("a TAXII feed needs a collection id")
            url = f.url.rstrip("/") + f"/collections/{f.collection_id}/objects/"
            params = {"limit": "1000"}
            if f.cursor:
                params["added_after"] = f.cursor
            objs, nxt = [], None
            for _ in range(MAX_PAGES):
                if nxt:
                    params["next"] = nxt
                r = c.get(url, params=params, headers={"Accept": TAXII_ACCEPT})
                env = json.loads(_read(r) or b"{}")
                objs += env.get("objects") or []
                nxt = env.get("next")
                if not env.get("more") or not nxt:
                    break
            items, errors = nz.parse_stix(json.dumps({"type": "bundle", "objects": objs})) if objs else ([], [])
            if not objs:
                errors = []
            return items, errors, r.headers.get("X-TAXII-Date-Added-Last") or started
        if f.feed_type == "misp":
            url = f.url.rstrip("/") + "/attributes/restSearch"
            since = f.cursor or str(int((datetime.now(UTC) - timedelta(days=30)).timestamp()))
            items, errors = [], []
            for page in range(1, MAX_PAGES + 1):
                r = c.post(url, json={"returnFormat": "json", "to_ids": True, "timestamp": since, "limit": 5000, "page": page,
                                      "includeEventTags": True}, headers={"Accept": "application/json", "Content-Type": "application/json"})
                doc = json.loads(_read(r) or b"{}")
                attrs = (doc.get("response") or {}).get("Attribute") or []
                i, e = nz.misp_attributes(attrs)
                items += i
                errors += e
                if len(attrs) < 5000:
                    break
            return items, errors, str(int(datetime.now(UTC).timestamp()))
        fmt = {"stix_url": "stix", "text_url": "text", "csv_url": "csv"}[f.feed_type]
        r = c.get(f.url)
        items, errors = nz.parse(fmt, _read(r).decode("utf-8", errors="replace"))
        return items, errors, started


def run_feed(db: Session, f: IntelFeed, actor=None) -> dict:
    src = db.get(IntelSource, f.source_id)
    f.last_run_at = utcnow()
    try:
        items, errors, cursor = fetch(f)
        res = svc.upsert(db, src, items, getattr(actor, "id", None))
        f.cursor, f.last_status, f.last_count = cursor, "ok", res["created"] + res["updated"]
        f.last_error = ("; ".join((errors + res["errors"])[:5]))[:4000] or None
        record(db, "intel.feed.run", actor=actor, resource_type="intel_feed", resource_id=f.id,
               details={"type": f.feed_type, "created": res["created"], "updated": res["updated"], "errors": len(errors) + len(res["errors"])})
        db.commit()
        hunt = svc.retro_hunt(db, actor, days=7, indicator_ids=res["ids"]) if res["ids"] else None
        return {"status": "ok", "parsed": len(items), "created": res["created"], "updated": res["updated"], "errors": (errors + res["errors"])[:50], "retrohunt": hunt}
    except (FeedError, httpx.HTTPError, ValueError, AppError) as e:
        db.rollback()
        f = db.get(IntelFeed, f.id)
        f.last_run_at, f.last_status, f.last_error = utcnow(), "error", str(e)[:4000]
        record(db, "intel.feed.run", outcome="failure", actor=actor, resource_type="intel_feed", resource_id=f.id, details={"error": str(e)[:300]})
        db.commit()
        return {"status": "error", "error": str(e)}


def poll_due() -> int:
    n = 0
    with SessionLocal() as db:
        now = utcnow()
        for f in db.execute(select(IntelFeed).where(IntelFeed.is_enabled.is_(True))).scalars().all():
            if f.last_run_at and f.last_run_at + timedelta(minutes=f.interval_minutes) > now:
                continue
            try:
                run_feed(db, f)
                n += 1
            except Exception:  # noqa: BLE001
                db.rollback()
                log.exception("intel_feed_failed", feed=f.id)
    return n

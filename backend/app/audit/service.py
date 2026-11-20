"""Audit logging service. Entries are append-only and hash-chained for tamper evidence."""
import hashlib
import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import AuditChainHead, AuditLog
from app.core.context import current_context
from app.core.database import SessionLocal, utcnow
from app.core.logging import log

GENESIS = "0" * 64


def _canonical(e: AuditLog) -> str:
    return json.dumps(
        {
            "occurred_at": e.occurred_at.isoformat(timespec="microseconds"),
            "actor_user_id": e.actor_user_id,
            "actor_label": e.actor_label,
            "action": e.action,
            "outcome": e.outcome,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "ip_address": e.ip_address,
            "request_id": e.request_id,
            "details": e.details,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def compute_hash(prev_hash: str, entry: AuditLog) -> str:
    return hashlib.sha256((prev_hash + _canonical(entry)).encode()).hexdigest()


def record(
    db: Session,
    action: str,
    *,
    outcome: str = "success",
    actor=None,
    actor_label: str | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    details: dict | None = None,
) -> AuditLog:
    """Append an audit entry inside the caller's transaction (caller commits)."""
    ctx = current_context()
    head = db.execute(select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update()).scalar_one()
    entry = AuditLog(
        occurred_at=utcnow(),
        actor_user_id=getattr(actor, "id", None),
        actor_label=actor_label or getattr(actor, "username", None) or "anonymous",
        action=action,
        outcome=outcome,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        ip_address=ctx.ip,
        user_agent=ctx.user_agent,
        request_id=ctx.request_id,
        details=details,
        prev_hash=head.last_hash,
    )
    entry.entry_hash = compute_hash(head.last_hash, entry)
    db.add(entry)
    db.flush()
    head.last_hash, head.last_id = entry.entry_hash, entry.id
    log.info("audit", action=action, outcome=outcome, actor=entry.actor_label, resource_type=resource_type, resource_id=entry.resource_id)
    return entry


def record_standalone(action: str, **kw) -> None:
    """Record in an independent transaction (e.g. a denied request whose main transaction is aborted)."""
    db = SessionLocal()
    try:
        actor = kw.pop("actor", None)
        if actor is not None:
            kw.setdefault("actor_label", actor.username)
            kw["actor"] = type("A", (), {"id": actor.id, "username": actor.username})()
        record(db, action, **kw)
        db.commit()
    except Exception:
        db.rollback()
        log.exception("audit_standalone_failed", action=action)
    finally:
        db.close()


def verify_chain(db: Session, limit: int | None = None) -> dict:
    """Recompute hashes from genesis. Returns first broken id if tampering is detected."""
    prev = GENESIS
    checked = 0
    q = select(AuditLog).order_by(AuditLog.id)
    if limit:
        q = q.limit(limit)
    for e in db.execute(q).scalars().yield_per(500):
        if e.prev_hash != prev or compute_hash(prev, e) != e.entry_hash:
            return {"valid": False, "checked": checked, "broken_at_id": e.id}
        prev = e.entry_hash
        checked += 1
    return {"valid": True, "checked": checked, "broken_at_id": None}


def parse_dt(v: str | None) -> datetime | None:
    return datetime.fromisoformat(v).replace(tzinfo=None) if v else None

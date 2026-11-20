"""Command Center overview. Only real data from MySQL; modules not yet built report available=false."""
import time
from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.health import check_mysql, check_redis, check_workers
from app.audit.models import AuditLog
from app.core.database import get_db, utcnow
from app.iam.deps import Principal, require
from app.iam.models import Role, User, UserSession
from app.network.service import counts_for_dashboard as network_counts
from app.cyber_range.service import counts_for_dashboard as lab_counts
from app.blueteam.service import counts_for_dashboard as soc_counts
from app.intel.service import counts_for_dashboard as intel_counts
from app.vuln.service import counts as vuln_counts
from app.malware.service import counts as malware_counts
from app.forensics.service import counts as forensics_counts
from app.training.service import counts as training_counts

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
_status_cache: dict = {"at": 0.0, "value": None}


def _cached_status(ttl: float = 15.0) -> dict:
    """Dependency status, cached briefly so dashboard polling does not hammer the broker."""
    if _status_cache["value"] is None or time.monotonic() - _status_cache["at"] > ttl:
        _status_cache["value"] = {"mysql": check_mysql()["status"], "redis": check_redis()["status"], "workers": check_workers()["status"]}
        _status_cache["at"] = time.monotonic()
    return _status_cache["value"]
RANGES = {"24h": (timedelta(hours=24), "hour"), "7d": (timedelta(days=7), "day"), "30d": (timedelta(days=30), "day")}
PENDING: dict[str, int] = {}


@router.get("/overview")
def overview(range: str = Query("24h", pattern="^(24h|7d|30d)$"), db: Session = Depends(get_db),
             p: Principal = Depends(require("dashboard.view"))):
    span, bucket = RANGES[range]
    now = utcnow()
    since = now - span
    in_range = AuditLog.occurred_at >= since

    def count(*where):
        return db.execute(select(func.count()).select_from(AuditLog).where(in_range, *where)).scalar_one()

    kpis = {
        "active_users": db.execute(select(func.count()).select_from(User).where(User.is_active.is_(True), User.deleted_at.is_(None))).scalar_one(),
        "active_sessions": db.execute(select(func.count()).select_from(UserSession).where(UserSession.revoked_at.is_(None), UserSession.expires_at > now)).scalar_one(),
        "roles": db.execute(select(func.count()).select_from(Role)).scalar_one(),
        "logins_success": count(AuditLog.action == "auth.login", AuditLog.outcome == "success"),
        "logins_failed": count(AuditLog.action == "auth.login", AuditLog.outcome == "failure"),
        "access_denied": count(AuditLog.outcome == "denied"),
        "audit_events": count(),
        **{f"topology_{k}": v for k, v in network_counts(db).items()},
        **lab_counts(db),
        **soc_counts(db, since),
        **intel_counts(db, since),
        **vuln_counts(db),
        **malware_counts(db),
        **forensics_counts(db),
        **training_counts(db),
        "locked_accounts": db.execute(select(func.count()).select_from(User).where(User.locked_until > now)).scalar_one(),
    }

    fmt = "%Y-%m-%d %H:00" if bucket == "hour" else "%Y-%m-%d"
    b = func.date_format(AuditLog.occurred_at, fmt)
    rows = db.execute(select(b.label("b"), AuditLog.outcome, func.count()).where(in_range).group_by("b", AuditLog.outcome).order_by("b")).all()
    # Build continuous buckets so the chart shows gaps as zero, not missing.
    step = timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    start = since.replace(minute=0, second=0, microsecond=0) if bucket == "hour" else since.replace(hour=0, minute=0, second=0, microsecond=0)
    labels, t = [], start
    while t <= now:
        labels.append(t.strftime(fmt))
        t += step
    series = {o: [0] * len(labels) for o in ("success", "failure", "denied")}
    idx = {lbl: i for i, lbl in enumerate(labels)}
    for label, outcome, n in rows:
        if label in idx and outcome in series:
            series[outcome][idx[label]] = n

    top_actions = [{"action": a, "count": n} for a, n in db.execute(
        select(AuditLog.action, func.count().label("n")).where(in_range).group_by(AuditLog.action).order_by(func.count().desc()).limit(8))]

    recent = None
    if p.has("audit.view"):  # resource-level: activity feed only for audit viewers
        recent = [{"id": r.id, "occurred_at": r.occurred_at, "actor": r.actor_label, "action": r.action, "outcome": r.outcome,
                   "resource_type": r.resource_type, "resource_id": r.resource_id}
                  for r in db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(10)).scalars()]

    status = _cached_status()
    return {
        "range": range, "generated_at": now, "kpis": kpis,
        "activity": {"bucket": bucket, "labels": labels, "series": series},
        "top_actions": top_actions, "recent_activity": recent, "system_status": status,
        "pending_modules": {k: {"available": False, "phase": v} for k, v in PENDING.items()},
    }

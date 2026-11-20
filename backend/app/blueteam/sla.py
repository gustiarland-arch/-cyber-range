"""SOC service levels: MTTD, MTTA, MTTR per severity and SLA breaches, computed only from stored alert/incident times.

* MTTD (time to detect)  = alert.created_at - alert.first_seen (first matching event).
* MTTA (time to acknowledge) = alert.acknowledged_at - alert.created_at.
* MTTR (time to resolve) = alert.closed_at - alert.created_at; for incidents closed_at - created_at.
* SLA targets (minutes to acknowledge / resolve) per severity come from CR_SLA_TARGETS, e.g.
  "critical=15/240;high=30/480"; severities not listed keep the defaults below.
* Nothing is estimated: an alert without an acknowledgement simply has no MTTA sample.
"""
from datetime import datetime, timedelta
from statistics import median

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blueteam.models import ALERT_OPEN, Alert, Incident
from app.core.config import get_settings
from app.core.database import utcnow
from app.core.logging import log

SEV_NAMES = ("info", "low", "medium", "high", "critical")
DEFAULT_TARGETS = {"critical": (15, 240), "high": (30, 480), "medium": (120, 1440), "low": (480, 4320), "info": (1440, 10080)}
MAX_ROWS = 50000
MAX_BREACHES = 100


def targets() -> dict[str, dict]:
    t = {k: list(v) for k, v in DEFAULT_TARGETS.items()}
    for part in (get_settings().sla_targets or "").split(";"):
        name, _, val = part.strip().partition("=")
        ack, _, res = val.partition("/")
        try:
            if name.strip().lower() in t and int(ack) > 0 and int(res) >= int(ack):
                t[name.strip().lower()] = [int(ack), int(res)]
                continue
        except ValueError:
            pass
        if part.strip():
            log.warning("sla_target_ignored", entry=part.strip()[:60])
    return {k: {"ack_min": a, "resolve_min": r} for k, (a, r) in t.items()}


def _secs(a: datetime | None, b: datetime | None) -> float | None:
    return (b - a).total_seconds() if a and b and b >= a else None


def _stats(xs: list[float]) -> dict:
    if not xs:
        return {"count": 0, "mean_s": None, "median_s": None, "p90_s": None}
    s = sorted(xs)
    return {"count": len(s), "mean_s": round(sum(s) / len(s), 1), "median_s": round(median(s), 1), "p90_s": round(s[min(len(s) - 1, int(0.9 * len(s)))], 1)}


def report(db: Session, days: int = 30, include_demo: bool = True) -> dict:
    now = utcnow()
    since = now - timedelta(days=days)
    tg = targets()
    demo = [] if include_demo else [Alert.is_demo.is_(False)]
    rows = db.execute(select(Alert.id, Alert.title, Alert.severity, Alert.status, Alert.first_seen, Alert.created_at, Alert.acknowledged_at,
                             Alert.closed_at, Alert.assignee_id, Alert.is_demo)
                      .where(Alert.created_at >= since, *demo).order_by(Alert.created_at.desc()).limit(MAX_ROWS)).all()
    inc = db.execute(select(Incident.created_at, Incident.closed_at).where(Incident.created_at >= since)).all()
    return {"days": days, "include_demo": include_demo, **compute(rows, inc, now, tg)}


def compute(rows, inc, now: datetime, tg: dict) -> dict:
    """Pure calculation over alert rows (id, title, severity, status, first_seen, created_at, acknowledged_at, closed_at,
    assignee_id, is_demo) and incident rows (created_at, closed_at)."""
    per = {n: {"detect": [], "ack": [], "resolve": [], "total": 0, "ack_met": 0, "ack_due": 0, "res_met": 0, "res_due": 0} for n in SEV_NAMES}
    breaches = []
    for r in rows:
        name = SEV_NAMES[max(0, min(4, r.severity))]
        b, t = per[name], tg[name]
        b["total"] += 1
        d, a, z = _secs(r.first_seen, r.created_at), _secs(r.created_at, r.acknowledged_at), _secs(r.created_at, r.closed_at)
        if d is not None:
            b["detect"].append(d)
        ack_deadline = r.created_at + timedelta(minutes=t["ack_min"])
        res_deadline = r.created_at + timedelta(minutes=t["resolve_min"])
        # an SLA is "due" once it has been met or its deadline has passed; alerts still inside the window are not counted yet
        ack_at = r.acknowledged_at or r.closed_at
        if ack_at is not None or now > ack_deadline:
            b["ack_due"] += 1
            b["ack_met"] += int(ack_at is not None and ack_at <= ack_deadline)
        if a is not None:
            b["ack"].append(a)
        if r.closed_at is not None or now > res_deadline:
            b["res_due"] += 1
            b["res_met"] += int(r.closed_at is not None and r.closed_at <= res_deadline)
        if z is not None:
            b["resolve"].append(z)
        if r.status in ALERT_OPEN:
            kind, deadline = (None, None)
            if r.acknowledged_at is None and now > ack_deadline:
                kind, deadline = "ack", ack_deadline
            if now > res_deadline:
                kind, deadline = "resolve", res_deadline
            if kind:
                breaches.append({"alert_id": r.id, "title": r.title, "severity": name, "status": r.status, "kind": kind, "deadline": deadline,
                                 "overdue_s": round((now - deadline).total_seconds()), "assignee_id": r.assignee_id, "is_demo": r.is_demo})
    breaches.sort(key=lambda x: (-SEV_NAMES.index(x["severity"]), -x["overdue_s"]))
    pct = lambda met, due: round(100 * met / due, 1) if due else None  # noqa: E731
    by_sev = [{"severity": n, "alerts": per[n]["total"], "target": tg[n], "mttd": _stats(per[n]["detect"]), "mtta": _stats(per[n]["ack"]),
               "mttr": _stats(per[n]["resolve"]), "ack_sla_pct": pct(per[n]["ack_met"], per[n]["ack_due"]),
               "resolve_sla_pct": pct(per[n]["res_met"], per[n]["res_due"])} for n in reversed(SEV_NAMES)]
    allv = lambda k: [x for n in SEV_NAMES for x in per[n][k]]  # noqa: E731
    inc_res = [s for s in (_secs(c, z) for c, z in inc) if s is not None]
    return {
        "generated_at": now, "targets": tg, "alerts": len(rows), "truncated": len(rows) >= MAX_ROWS,
        "overall": {"mttd": _stats(allv("detect")), "mtta": _stats(allv("ack")), "mttr": _stats(allv("resolve")),
                    "ack_sla_pct": pct(sum(per[n]["ack_met"] for n in SEV_NAMES), sum(per[n]["ack_due"] for n in SEV_NAMES)),
                    "resolve_sla_pct": pct(sum(per[n]["res_met"] for n in SEV_NAMES), sum(per[n]["res_due"] for n in SEV_NAMES))},
        "by_severity": by_sev,
        "incidents": {"opened": len(inc), "closed": len(inc_res), "mttr": _stats(inc_res)},
        "breaches": breaches[:MAX_BREACHES], "breaches_total": len(breaches),
    }

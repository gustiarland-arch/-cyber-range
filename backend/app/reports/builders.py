"""Report builders. Each returns a document model built only from persisted records:

    {"title", "subtitle", "sources": [str], "sections": [{"heading", "kv": [[k, v]], "text", "table": {"columns", "rows"}}],
     "primary": {"columns", "rows"}}   # `primary` is what the CSV export contains

Builders never invent values. DEMO records are labelled as such in the output.
"""
from datetime import timedelta

from sqlalchemy import Integer, func, select
from sqlalchemy.orm import Session

from app.core.database import utcnow
from app.core.errors import AppError, Forbidden, NotFound
from app.iam.models import User

SEV = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _users(db, ids):
    ids = {i for i in ids if i}
    return dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all()) if ids else {}


def _ts(d):
    return d.strftime("%Y-%m-%d %H:%M:%S UTC") if d else ""


def _need(p, *perms):
    missing = [x for x in perms if not p.has(x)]
    if missing:
        raise Forbidden("You do not have access to the data for this report", details={"missing": missing})


# ------------------------------------------------------------------ incident
def incident(db: Session, p, params: dict) -> dict:
    from app.blueteam.models import Alert, Incident, IncidentEntry
    _need(p, "incident.view")
    inc = db.get(Incident, int(params.get("incident_id") or 0))
    if not inc:
        raise NotFound("Incident not found")
    entries = db.execute(select(IncidentEntry).where(IncidentEntry.incident_id == inc.id).order_by(IncidentEntry.at)).scalars().all()
    alerts = db.execute(select(Alert).where(Alert.incident_id == inc.id).order_by(Alert.first_seen)).scalars().all()
    u = _users(db, [inc.owner_id, inc.created_by, *[e.author_id for e in entries]])
    timeline = [[_ts(e.at), e.kind, u.get(e.author_id, "system"), e.body] for e in entries]
    alert_rows = [[a.id, _ts(a.first_seen), _ts(a.last_seen), SEV.get(a.severity, a.severity), a.status, a.title, a.event_count, "DEMO" if a.is_demo else ""] for a in alerts]
    return {"title": f"Incident report #{inc.id}: {inc.title}", "subtitle": ("DEMO incident · " if inc.is_demo else "") + f"status {inc.status}",
            "sources": [f"incidents#{inc.id}", f"incident_entries ({len(entries)})", f"alerts linked ({len(alerts)})"],
            "sections": [
                {"heading": "Summary", "kv": [["Severity", SEV.get(inc.severity, inc.severity)], ["Status", inc.status], ["Owner", u.get(inc.owner_id, "unassigned")],
                                              ["Opened", _ts(inc.created_at)], ["Closed", _ts(inc.closed_at) or "open"], ["Created by", u.get(inc.created_by, "")],
                                              ["Demo data", "yes" if inc.is_demo else "no"]], "text": inc.summary},
                {"heading": "Linked alerts", "table": {"columns": ["Alert", "First seen", "Last seen", "Severity", "Status", "Title", "Events", "Label"], "rows": alert_rows}},
                {"heading": "Timeline", "table": {"columns": ["Time", "Kind", "Author", "Entry"], "rows": timeline}},
            ],
            "primary": {"columns": ["time", "kind", "author", "entry"], "rows": timeline}}


# ------------------------------------------------------------------ assessment
def assessment(db: Session, p, params: dict) -> dict:
    from app.redteam.models import Assessment, AssessmentEvent, Finding
    _need(p, "redteam.assessment.view")
    a = db.get(Assessment, int(params.get("assessment_id") or 0))
    if not a:
        raise NotFound("Assessment not found")
    evs = db.execute(select(AssessmentEvent).where(AssessmentEvent.assessment_id == a.id).order_by(AssessmentEvent.at)).scalars().all()
    fnd = db.execute(select(Finding).where(Finding.assessment_id == a.id).order_by(Finding.step_index, Finding.id)).scalars().all()
    u = _users(db, [a.requested_by, a.decided_by, *[e.actor_id for e in evs]])
    frows = [[f.step_index, f.kind, SEV.get(f.severity, f.severity), f.title, f.target_ip or "", f.port or ""] for f in fnd]
    targets = ", ".join(t.get("label") or t.get("node_key", "") for t in (a.scope or {}).get("targets", []))
    return {"title": f"Assessment report #{a.id}: {a.title}", "subtitle": f"{a.scenario.get('code', '')} · status {a.status}",
            "sources": [f"assessments#{a.id}", f"assessment_events ({len(evs)})", f"findings ({len(fnd)})", f"lab #{a.lab_id} runtime {a.runtime_id}"],
            "sections": [
                {"heading": "Authorisation", "kv": [["Scenario", f"{a.scenario.get('code', '')} {a.scenario.get('name', '')}"], ["Lab / runtime", f"#{a.lab_id} / {a.runtime_id}"],
                                                    ["Attacker node", f"{a.attacker_node} ({a.attacker_ip})"], ["Targets", targets],
                                                    ["Window", f"{_ts(a.window_start)} – {_ts(a.window_end)}"], ["Requested by", u.get(a.requested_by, "")],
                                                    ["Decision", f"{u.get(a.decided_by, '—')} {_ts(a.decided_at)}"], ["Status", a.status]],
                 "text": f"Justification: {a.justification}\nDecision comment: {a.decision_comment or '—'}"},
                {"heading": "Findings (observed, non-destructive)", "table": {"columns": ["Step", "Kind", "Severity", "Title", "Target", "Port"], "rows": frows}},
                {"heading": "Execution log", "table": {"columns": ["Time", "Kind", "Step", "Actor", "Message"],
                                                       "rows": [[_ts(e.at), e.kind, "" if e.step_index is None else e.step_index, u.get(e.actor_id, "system"), e.message] for e in evs]}},
            ],
            "primary": {"columns": ["step", "kind", "severity", "title", "target_ip", "port"], "rows": frows}}


# ------------------------------------------------------------------ lab run
def lab_run(db: Session, p, params: dict) -> dict:
    from app.cyber_range.models import Lab, LabEvent
    _need(p, "lab.view")
    lab = db.get(Lab, int(params.get("lab_id") or 0))
    if not lab or lab.deleted_at:
        raise NotFound("Lab not found")
    if lab.owner_id != p.id and not p.has("lab.manage"):
        raise Forbidden("Lab reports are limited to the lab owner or lab.manage", details={"missing": ["lab.manage"]})
    evs = db.execute(select(LabEvent).where(LabEvent.lab_id == lab.id).order_by(LabEvent.occurred_at)).scalars().all()
    u = _users(db, [lab.owner_id, *[i.requested_by for i in lab.instances]])
    inst_rows = [[i.id, i.runtime_id, i.status, u.get(i.requested_by, ""), _ts(i.created_at), _ts(i.started_at), _ts(i.stopped_at), _ts(i.destroyed_at),
                  len(i.containers)] for i in sorted(lab.instances, key=lambda x: x.id)]
    ev_rows = [[_ts(e.occurred_at), e.level, e.kind, e.message] for e in evs]
    t = lab.plan.get("totals", {})
    return {"title": f"Lab run report: {lab.name}", "subtitle": f"lab #{lab.id} · network v{lab.network_version}",
            "sources": [f"labs#{lab.id}", f"lab_instances ({len(inst_rows)})", f"lab_events ({len(ev_rows)})"],
            "sections": [
                {"heading": "Lab", "kv": [["Owner", u.get(lab.owner_id, "")], ["Created", _ts(lab.created_at)], ["Containers planned", t.get("containers", "")],
                                          ["Networks planned", t.get("networks", "")], ["Description", lab.description or "—"]]},
                {"heading": "Deployments", "table": {"columns": ["Instance", "Runtime", "Status", "Requested by", "Created", "Started", "Stopped", "Destroyed", "Containers"], "rows": inst_rows}},
                {"heading": "Lifecycle events", "table": {"columns": ["Time", "Level", "Kind", "Message"], "rows": ev_rows}},
            ],
            "primary": {"columns": ["time", "level", "kind", "message"], "rows": ev_rows}}


# ------------------------------------------------------------------ vulnerability
def vulnerability(db: Session, p, params: dict) -> dict:
    from app.cyber_range.models import Lab
    from app.vuln.models import ScanFinding, Vulnerability
    _need(p, "vuln.view")
    q = (select(ScanFinding, Vulnerability, Lab.name).join(Vulnerability, Vulnerability.id == ScanFinding.vulnerability_id)
         .join(Lab, Lab.id == ScanFinding.lab_id).order_by(ScanFinding.severity.desc(), ScanFinding.first_seen))
    scope = "all labs"
    if params.get("lab_id"):
        q = q.where(ScanFinding.lab_id == int(params["lab_id"]))
        scope = f"lab #{int(params['lab_id'])}"
    status = params.get("status") or "open_all"
    if status == "open_all":
        q = q.where(ScanFinding.status.in_(("open", "in_remediation", "fixed_pending_verification", "reopened")))
    elif status != "any":
        q = q.where(ScanFinding.status == status)
    rows = db.execute(q.limit(5000)).all()
    data = [[f.id, v.code, SEV.get(f.severity, f.severity), v.title, lab, f.asset_label or f.node_key, f.ip, f.port or "", f.status, _ts(f.first_seen), _ts(f.last_seen),
             f.times_seen, ", ".join(v.cves or [])] for f, v, lab in rows]
    by_sev = {}
    for r in data:
        by_sev[r[2]] = by_sev.get(r[2], 0) + 1
    return {"title": "Vulnerability report", "subtitle": f"{scope} · status filter: {status}",
            "sources": [f"scan_findings ({len(data)})", "vulnerabilities catalogue"],
            "sections": [
                {"heading": "Summary", "kv": [["Findings", len(data)], *[[f"Severity {k}", v] for k, v in sorted(by_sev.items())]],
                 "text": "Findings come from non-destructive checks run inside isolated labs. Version-based CVE entries are potential and need confirmation."},
                {"heading": "Findings", "table": {"columns": ["ID", "Code", "Severity", "Title", "Lab", "Asset", "IP", "Port", "Status", "First seen", "Last seen", "Seen", "CVEs"], "rows": data}},
            ],
            "primary": {"columns": ["id", "code", "severity", "title", "lab", "asset", "ip", "port", "status", "first_seen", "last_seen", "times_seen", "cves"], "rows": data}}


# ------------------------------------------------------------------ evidence (case)
def evidence(db: Session, p, params: dict) -> dict:
    from app.forensics import service as fx
    from app.forensics.models import CustodyEvent, Evidence, ForensicCase
    _need(p, "evidence.view")
    c = db.get(ForensicCase, int(params.get("case_id") or 0))
    if not c:
        raise NotFound("Case not found")
    ev = db.execute(select(Evidence).where(Evidence.case_id == c.id).order_by(Evidence.id)).scalars().all()
    cust = db.execute(select(CustodyEvent).where(CustodyEvent.evidence_id.in_([e.id for e in ev] or [-1])).order_by(CustodyEvent.evidence_id, CustodyEvent.seq)).scalars().all()
    u = _users(db, [c.lead_id, *[e.collected_by for e in ev], *[e.custodian_id for e in ev]])
    refs = {e.id: e.reference for e in ev}
    erows = []
    for e in ev:
        chain = fx.verify_chain(db, e)
        erows.append([e.reference, e.kind, e.title, e.filename, e.size, e.sha256, e.status, u.get(e.custodian_id, ""), u.get(e.collected_by, ""), _ts(e.collected_at),
                      "valid" if chain["valid"] else f"BROKEN at {chain['broken_at']}"])
    crows = [[refs[x.evidence_id], x.seq, _ts(x.at), x.action, x.actor_label, x.from_custodian or "", x.to_custodian or "", x.sha256_observed or "", x.entry_hash] for x in cust]
    return {"title": f"Evidence report {c.reference}: {c.title}", "subtitle": f"classification {c.classification} · status {c.status}",
            "sources": [f"forensic_cases#{c.id}", f"evidence ({len(ev)})", f"custody_events ({len(cust)}, hash chain re-verified at generation)"],
            "sections": [
                {"heading": "Case", "kv": [["Reference", c.reference], ["Classification", c.classification], ["Lead", u.get(c.lead_id, "—")], ["Incident", c.incident_id or "—"],
                                           ["Status", c.status], ["Closure note", c.closure_note or "—"]]},
                {"heading": "Evidence items", "table": {"columns": ["Reference", "Kind", "Title", "File", "Bytes", "SHA-256", "Status", "Custodian", "Collected by", "Collected at", "Custody chain"], "rows": erows}},
                {"heading": "Chain of custody", "table": {"columns": ["Evidence", "Seq", "Time", "Action", "Actor", "From", "To", "Observed SHA-256", "Entry hash"], "rows": crows}},
            ],
            "primary": {"columns": ["evidence", "seq", "time", "action", "actor", "from", "to", "sha256_observed", "entry_hash"], "rows": crows}}


# ------------------------------------------------------------------ training
def training(db: Session, p, params: dict) -> dict:
    from app.training.models import ScoreEvent
    _need(p, "training.manage")
    days = int(params.get("days") or 30)
    if days not in (7, 30, 90, 365):
        raise AppError("days must be one of 7, 30, 90, 365", code="validation_error", status_code=422)
    since = utcnow() - timedelta(days=days)
    rows = db.execute(select(User.username, ScoreEvent.source, func.count(), func.sum(ScoreEvent.points), func.sum(ScoreEvent.first_blood.cast(Integer)))
                      .join(User, User.id == ScoreEvent.user_id).where(ScoreEvent.at >= since)
                      .group_by(User.username, ScoreEvent.source)).all()
    per: dict[str, dict] = {}
    for uname, src, n, pts, fb in rows:
        d = per.setdefault(uname, {"points": 0, "challenge": 0, "objective": 0, "first_bloods": 0})
        if src in d:
            d[src] = n
        d["points"] += int(pts or 0)
        d["first_bloods"] += int(fb or 0)
    data = [[u, d["points"], d["challenge"], d["objective"], d["first_bloods"]] for u, d in sorted(per.items(), key=lambda x: -x[1]["points"])]
    evs = db.execute(select(ScoreEvent.at, User.username, ScoreEvent.source, ScoreEvent.category, ScoreEvent.points, ScoreEvent.detail)
                     .join(User, User.id == ScoreEvent.user_id).where(ScoreEvent.at >= since).order_by(ScoreEvent.at.desc()).limit(500)).all()
    return {"title": "Training report", "subtitle": f"last {days} days",
            "sources": [f"score_events since {_ts(since)} ({sum(r[2] + r[3] for r in data)} scoring actions)"],
            "sections": [
                {"heading": "Participants", "table": {"columns": ["User", "Points", "Challenges", "Objectives", "First bloods"], "rows": data}},
                {"heading": "Recent scoring activity", "table": {"columns": ["Time", "User", "Source", "Category", "Points", "Item"],
                                                                 "rows": [[_ts(a), u, s, c, pt, d.get("title") or d.get("objective") or ""] for a, u, s, c, pt, d in evs]}},
            ],
            "primary": {"columns": ["user", "points", "challenges", "objectives", "first_bloods"], "rows": data}}


BUILDERS = {"incident": incident, "assessment": assessment, "lab_run": lab_run, "vulnerability": vulnerability, "evidence": evidence, "training": training}

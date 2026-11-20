"""Vulnerability scan lifecycle and finding management.

Authorisation model: a scan may only target nodes of a RUNNING lab deployment that the requester owns (or any lab with
`lab.manage`); targets are resolved server-side to addresses inside the lab networks, and the scan runs from a node of
that same lab with `docker exec` (never from the host). The kill switch and the deployment identity are re-checked
before execution. Checks are non-destructive (see checks.py).
"""
import ipaddress
import os
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam import service as soc
from app.core.database import SessionLocal, utcnow
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.logging import log
from app.cyber_range.engine.driver import DriverError, get_driver
from app.cyber_range.engine.safety import kill_switch_engaged
from app.cyber_range.models import Lab, LabInstance
from app.vuln import checks
from app.vuln.models import FindingEvent, RemediationTask, ScanFinding, ScanJob, Vulnerability

ACTIVITY_SOURCE = "Vulnerability scanner (lab)"
OPEN_STATES = ("open", "in_remediation", "fixed_pending_verification")


def seed(db: Session) -> dict:
    have = {c: v for c, v in db.execute(select(Vulnerability.code, Vulnerability)).all()}
    n = 0
    for b in checks.BUILTIN:
        row = have.get(b["code"])
        data = {"cves": [], "references": [], **b, "is_builtin": True}
        if row is None:
            db.add(Vulnerability(**data))
            n += 1
        else:  # keep builtin definitions current
            for k, v in data.items():
                setattr(row, k, v)
    db.flush()
    return {"vulnerabilities_created": n}


def _running(db: Session, lab_id: int) -> tuple[Lab, LabInstance]:
    lab = db.execute(select(Lab).where(Lab.id == lab_id, Lab.deleted_at.is_(None))).scalar_one_or_none()
    if not lab:
        raise NotFound("Lab not found")
    inst = db.execute(select(LabInstance).where(LabInstance.lab_id == lab.id, LabInstance.status == "running")
                      .order_by(LabInstance.id.desc()).limit(1)).scalar_one_or_none()
    if not inst:
        raise Conflict("Scans can only target a running lab", code="lab_not_running")
    return lab, inst


def create_job(db: Session, p, *, name: str, lab_id: int, scanner_node: str, target_nodes: list[str], profile: str, ports: list[int] | None) -> ScanJob:
    lab, inst = _running(db, lab_id)
    if not (lab.owner_id == p.id or p.has("lab.manage")):
        raise Forbidden("You may only scan labs you own (or hold lab.manage)", details={"missing": ["lab.manage"]})
    if kill_switch_engaged(db):
        raise Conflict("The lab kill switch is engaged", code="kill_switch")
    if profile not in checks.PROFILES and profile != "custom":
        raise AppError("Unknown scan profile", code="validation_error", status_code=422)
    if profile == "custom":
        if not ports or len(ports) > 200 or not all(isinstance(x, int) and 1 <= x <= 65535 for x in ports):
            raise AppError("A custom profile needs 1-200 ports between 1 and 65535", code="validation_error", status_code=422)
        port_list = sorted(set(ports))
    else:
        port_list = checks.PROFILES[profile]
    containers = {c.node_key: c for c in inst.containers}
    plan = {c["node_key"]: c for c in lab.plan["containers"]}
    if scanner_node not in containers:
        raise AppError("The scanner node must be a deployed node of this lab", code="invalid_scope", status_code=422)
    if not target_nodes or len(target_nodes) > 50 or scanner_node in target_nodes:
        raise AppError("Choose 1-50 target nodes other than the scanner", code="invalid_scope", status_code=422)
    lab_cidrs = [ipaddress.ip_network(n["cidr"]) for n in lab.plan["networks"]]
    targets = []
    for key in dict.fromkeys(target_nodes):
        c = containers.get(key)
        if not c:
            raise AppError(f"Target {key} is not a deployed node of this lab", code="invalid_scope", status_code=422)
        ips = sorted(ip for ip in (c.addresses or {}).values() if any(ipaddress.ip_address(ip) in n for n in lab_cidrs))
        if not ips:
            raise AppError(f"Target {key} has no address inside the lab networks", code="invalid_scope", status_code=422)
        targets.append({"node_key": key, "label": plan.get(key, {}).get("label", key), "ips": ips})
    sc_ips = sorted((containers[scanner_node].addresses or {}).values())
    job = ScanJob(name=name, profile=profile, lab_id=lab.id, instance_id=inst.id, runtime_id=inst.runtime_id, scanner_node=scanner_node,
                  scanner_ip=sc_ips[0] if sc_ips else "", scope={"targets": targets, "lab_name": lab.name}, ports=port_list,
                  status="queued", requested_by=p.id, log=[{"at": utcnow().isoformat(), "msg": f"Queued by {p.username}"}])
    db.add(job)
    db.flush()
    record(db, "vuln.scan.start", actor=p, resource_type="scan_job", resource_id=job.id,
           details={"lab": lab.id, "runtime_id": inst.runtime_id, "scanner": scanner_node, "targets": [t["node_key"] for t in targets], "ports": len(port_list)})
    db.commit()
    if os.environ.get("CR_LAB_EXECUTION", "celery") == "inline":
        run(job.id)
    else:
        from app.core.celery_app import celery_app
        celery_app.send_task("app.vuln.tasks.run_scan", args=[job.id], queue="lab")
    return job


def _log(job: ScanJob, msg: str):
    job.log = [*job.log, {"at": utcnow().isoformat(), "msg": msg[:500]}][-200:]


def _finding_event(db, f: ScanFinding, kind: str, msg: str, job_id=None, actor=None):
    db.add(FindingEvent(finding_id=f.id, kind=kind, message=msg[:1024], job_id=job_id, actor_id=getattr(actor, "id", None)))


def _apply_results(db: Session, job: ScanJob, parsed: dict) -> dict:
    vulns = {v.code: v for v in db.execute(select(Vulnerability)).scalars()}
    by_ip = {ip: t for t in job.scope["targets"] for ip in t["ips"]}
    now = utcnow()
    new = redetected = reopened = verified = 0
    seen_keys = set()
    for ip, host in parsed.items():
        t = by_ip.get(ip)
        if not t:
            continue  # only addresses resolved into the approved scope are ever recorded
        for r in checks.evaluate(host):
            v = vulns.get(r["code"])
            if not v:
                continue
            key = (t["node_key"], v.id, r["port"])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            f = db.execute(select(ScanFinding).where(ScanFinding.lab_id == job.lab_id, ScanFinding.node_key == t["node_key"],
                                                     ScanFinding.vulnerability_id == v.id, ScanFinding.port == r["port"])).scalar_one_or_none()
            if f is None:
                f = ScanFinding(vulnerability_id=v.id, lab_id=job.lab_id, node_key=t["node_key"], asset_label=t["label"], ip=ip, port=r["port"],
                                severity=v.severity, status="open", source="scan", evidence=r["evidence"], first_job_id=job.id, last_job_id=job.id,
                                first_seen=now, last_seen=now, created_by=job.requested_by)
                db.add(f)
                db.flush()
                _finding_event(db, f, "detected", f"Detected by scan #{job.id}", job.id)
                new += 1
                continue
            f.last_seen, f.last_job_id, f.times_seen, f.evidence, f.ip = now, job.id, f.times_seen + 1, r["evidence"], ip
            if f.status in ("resolved", "fixed_pending_verification"):
                prev = f.status
                f.status, f.resolved_at = "open", None
                _finding_event(db, f, "reopened", f"Still present in scan #{job.id} (was {prev})", job.id)
                reopened += 1
            else:
                redetected += 1
    # Verification: findings on scanned assets/ports that were NOT observed this time.
    scanned_nodes = {t["node_key"] for t in job.scope["targets"]}
    for f in db.execute(select(ScanFinding).where(ScanFinding.lab_id == job.lab_id, ScanFinding.node_key.in_(scanned_nodes),
                                                  ScanFinding.source == "scan", ScanFinding.status.in_(OPEN_STATES))).scalars():
        if (f.node_key, f.vulnerability_id, f.port) in seen_keys:
            continue
        if f.port and f.port not in job.ports:
            continue  # this scan did not look at that port; no conclusion
        if f.status == "fixed_pending_verification":
            f.status, f.resolved_at, f.status_reason = "resolved", now, f"Not detected by verification scan #{job.id}"
            _finding_event(db, f, "verified", f"Fix verified: not detected by scan #{job.id}", job.id)
            for t in db.execute(select(RemediationTask).where(RemediationTask.finding_id == f.id, RemediationTask.status.in_(("open", "in_progress")))).scalars():
                t.status, t.completed_at = "done", now
            verified += 1
        else:
            _finding_event(db, f, "not_detected", f"Not detected by scan #{job.id}; mark it fixed to have the next scan verify it", job.id)
    return {"new": new, "redetected": redetected, "reopened": reopened, "verified": verified}


def _telemetry(db: Session, job: ScanJob, parsed: dict) -> int:
    src = soc.builtin_source(db, ACTIVITY_SOURCE, "json")
    if not src.description:
        src.description = "Probes sent by authorised vulnerability scans inside labs (one record per port probed)."
    ts = utcnow().isoformat() + "Z"
    recs = []
    for ip, h in parsed.items():
        for port in sorted(h["open"] | h["closed"]):
            ok = port in h["open"]
            recs.append({"timestamp": ts, "dataset": "vuln.scan", "src_ip": job.scanner_ip, "host": job.scanner_node, "user": f"scan-{job.id}",
                         "event_uid": f"vs{job.id}-{ip}-{port}", "category": "network", "action": "tcp_connect", "outcome": "success" if ok else "failure",
                         "dst_ip": ip, "dst_port": port, "protocol": "tcp", "message": f"vulnerability scan #{job.id}: {ip}:{port} {'open' if ok else 'closed'}"})
    return soc.ingest(db, src, recs[:5000], kind="json")["accepted"] if recs else 0


def run(job_id: int) -> str:
    d = get_driver()
    with SessionLocal() as db:
        job = db.execute(select(ScanJob).where(ScanJob.id == job_id).with_for_update()).scalar_one_or_none()
        if not job or job.status != "queued":
            return "skipped"
        inst = db.get(LabInstance, job.instance_id) if job.instance_id else None
        reason = ("aborted by user" if job.abort_requested else "kill switch engaged" if kill_switch_engaged(db) else
                  "lab deployment changed" if not inst or inst.status != "running" or inst.runtime_id != job.runtime_id else None)
        if reason:
            job.status, job.finished_at = "aborted", utcnow()
            _log(job, f"Not started: {reason}")
            db.commit()
            return job.status
        job.status, job.started_at = "running", utcnow()
        targets = [ip for t in job.scope["targets"] for ip in t["ips"]]
        job.progress = {"targets": len(targets), "ports": len(job.ports)}
        _log(job, f"Scanning {len(targets)} address(es) × {len(job.ports)} port(s) from {job.scanner_node} ({job.scanner_ip})")
        db.commit()
        try:
            sc = next((c for c in inst.containers if c.node_key == job.scanner_node), None)
            if not sc or not sc.docker_id:
                raise DriverError("scanner container is gone")
            argv, timeout = checks.build_script(targets, job.ports)
            code, out = d.exec(sc.docker_id, argv, timeout)
            parsed = checks.parse(out)
            db.refresh(job)
            stats = _apply_results(db, job, parsed)
            db.commit()
            nt = _telemetry(db, job, parsed)
            db.refresh(job)
            open_ports = sum(len(h["open"]) for h in parsed.values())
            job.summary = {**stats, "hosts_answered": sum(1 for h in parsed.values() if h["open"]), "open_ports": open_ports,
                           "telemetry": nt, "exit_code": code,
                           "services": {ip: sorted(h["open"]) for ip, h in parsed.items() if h["open"]}}
            job.status, job.finished_at = "completed", utcnow()
            _log(job, f"Completed: {open_ports} open port(s), {stats['new']} new, {stats['redetected']} re-detected, "
                      f"{stats['reopened']} reopened, {stats['verified']} fixes verified")
        except Exception as e:  # noqa: BLE001 - failures are recorded on the job
            db.rollback()
            job = db.get(ScanJob, job_id)
            log.exception("scan_failed", job=job_id)
            job.status, job.finished_at, job.error = "failed", utcnow(), str(e)[:2000]
            _log(job, f"Failed: {e}")
        db.commit()
        return job.status


# ------------------------------------------------------------------ findings workflow
TRANSITIONS = {
    "open": {"in_remediation", "fixed_pending_verification", "false_positive", "risk_accepted"},
    "in_remediation": {"open", "fixed_pending_verification", "false_positive", "risk_accepted"},
    "fixed_pending_verification": {"open", "in_remediation"},
    "resolved": {"open"},
    "false_positive": {"open"},
    "risk_accepted": {"open"},
}


def change_status(db: Session, p, f: ScanFinding, status: str, reason: str, until=None) -> None:
    if status not in TRANSITIONS.get(f.status, set()):
        raise Conflict(f"Cannot move a finding from {f.status} to {status}", code="invalid_transition")
    if status in ("false_positive", "risk_accepted") and len(reason.strip()) < 10:
        raise AppError("A justification of at least 10 characters is required", code="validation_error", status_code=422)
    if status == "risk_accepted":
        if not until or until <= utcnow().date() or until > utcnow().date() + timedelta(days=365):
            raise AppError("Risk acceptance needs an expiry date within the next 365 days", code="validation_error", status_code=422)
        f.risk_accepted_until = until
    elif f.status == "risk_accepted":
        f.risk_accepted_until = None
    if status == "fixed_pending_verification" and f.source == "manual":
        status = "resolved"  # nothing can re-scan a manual finding; the analyst's statement is recorded as the resolution
    prev = f.status
    f.status, f.status_reason = status, reason.strip()[:2000]
    f.resolved_at = utcnow() if status == "resolved" else None
    _finding_event(db, f, "status", f"{prev} → {status} by {p.username}" + (f": {reason.strip()}" if reason.strip() else ""), actor=p)
    record(db, "vuln.finding.status", actor=p, resource_type="scan_finding", resource_id=f.id, details={"from": prev, "to": status})


def expire_risk_acceptance(db: Session) -> int:
    n = 0
    for f in db.execute(select(ScanFinding).where(ScanFinding.status == "risk_accepted", ScanFinding.risk_accepted_until < utcnow().date())).scalars():
        f.status, f.risk_accepted_until = "open", None
        _finding_event(db, f, "risk_expired", "Risk acceptance expired; finding reopened")
        n += 1
    return n


def counts(db: Session) -> dict:
    by = dict(db.execute(select(ScanFinding.severity, func.count()).where(ScanFinding.status.in_(OPEN_STATES)).group_by(ScanFinding.severity)).all())
    overdue = db.execute(select(func.count()).select_from(RemediationTask).where(RemediationTask.status.in_(("open", "in_progress")),
                                                                                  RemediationTask.due_date < utcnow().date())).scalar_one()
    return {"vuln_open": sum(by.values()), "vuln_open_critical": by.get(4, 0), "vuln_open_high": by.get(3, 0), "remediation_overdue": overdue}

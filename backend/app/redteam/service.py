"""Authorised assessment lifecycle: request -> independent approval -> execution in the lab -> findings and report."""
import ipaddress
import os
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.blueteam import service as soc
from app.blueteam.models import Alert, AlertEvent, SecurityEvent
from app.core.database import SessionLocal, utcnow
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.logging import log
from app.cyber_range.engine.driver import DriverError, get_driver
from app.cyber_range.engine.safety import kill_switch_engaged
from app.cyber_range.models import Lab, LabInstance
from app.governance.service import get_value
from app.redteam.actions import ACTIONS, SENSITIVE_DEFAULT, build_command, parse_output, validate_steps
from app.redteam.models import Assessment, AssessmentEvent, Finding, Scenario

ACTIVITY_SOURCE = "Red team activity (lab)"
SENSITIVE_PATHS = ("/admin", "/.git/HEAD", "/server-status", "/phpmyadmin", "/.env", "/backup")

BUILTIN_SCENARIOS = [
    {"code": "RT-RECON-01", "name": "Internal reconnaissance", "difficulty": "basic",
     "description": "Inventory live hosts and common services from a foothold inside the lab.",
     "objective": "Produce an asset and service inventory of the in-scope segment and check whether the SOC notices the sweep.",
     "steps": [{"action": "host_discovery", "title": "Sweep in-scope subnets", "params": {}},
               {"action": "port_scan", "title": "Scan common service ports", "params": {"ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]}}]},
    {"code": "RT-WEB-01", "name": "Web exposure inventory", "difficulty": "basic",
     "description": "Find web services on the targets and list which administrative or sensitive paths answer.",
     "objective": "Identify exposed web management surfaces that should not be reachable.",
     "steps": [{"action": "port_scan", "title": "Find web ports", "params": {"ports": [80, 443, 8000, 8080, 8443]}},
               {"action": "http_inventory", "title": "Inventory HTTP paths", "params": {"ports": [80], "paths": ["/", "/admin", "/login", "/robots.txt", "/.git/HEAD", "/server-status"]}}]},
    {"code": "RT-SEG-01", "name": "Segmentation validation", "difficulty": "intermediate",
     "description": "Verify that database, remote-access and admin ports are not reachable from the attacker's segment.",
     "objective": "Prove (or disprove) the network segmentation policy between zones.",
     "steps": [{"action": "exposure_check", "title": "Check sensitive ports", "params": {"ports": SENSITIVE_DEFAULT}}]},
    {"code": "RT-PURPLE-02", "name": "Detection validation: web attack patterns", "difficulty": "basic",
     "description": "Find web ports, then send inert requests carrying SQL injection / traversal signatures so CR-WEB-001 (and any web IDS) can be verified.",
     "objective": "Purple-team check: every attack-pattern request should raise a web-attack alert; answered requests show where no blocking control exists.",
     "steps": [{"action": "port_scan", "title": "Find web ports", "params": {"ports": [80, 8080]}},
               {"action": "web_attack_probe", "title": "Send attack-pattern test requests", "params": {"ports": [80]}}]},
    {"code": "RT-PURPLE-03", "name": "Detection validation: suspicious DNS", "difficulty": "basic",
     "description": "Resolve test domains under abused TLDs from the attacker node to verify DNS-based C2 detection (CR-DNS-001, Zeek dns.log).",
     "objective": "Purple-team check that suspicious-TLD lookups are logged and alerted.",
     "steps": [{"action": "dns_probe", "title": "Resolve suspicious test domains", "params": {}}]},
    {"code": "RT-PURPLE-04", "name": "Detection drill: reconnaissance to initial access", "difficulty": "intermediate",
     "description": "A short kill-chain drill: host sweep, service scan, web inventory, attack-pattern requests, suspicious DNS and a segmentation check.",
     "objective": "Measure per ATT&CK technique which stages the SOC detects (attacked vs detected report).",
     "steps": [{"action": "host_discovery", "title": "Sweep in-scope subnets", "params": {}},
               {"action": "port_scan", "title": "Scan common service ports", "params": {"ports": [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080]}},
               {"action": "http_inventory", "title": "Inventory HTTP paths", "params": {"ports": [80], "paths": ["/", "/admin", "/login", "/.git/HEAD", "/server-status"]}},
               {"action": "web_attack_probe", "title": "Send attack-pattern test requests", "params": {"ports": [80]}},
               {"action": "dns_probe", "title": "Resolve suspicious test domains", "params": {}},
               {"action": "exposure_check", "title": "Check sensitive ports", "params": {"ports": SENSITIVE_DEFAULT}}]},
    {"code": "RT-PURPLE-05", "name": "Lateral movement surface check", "difficulty": "intermediate",
     "description": "Check whether remote-service ports used for lateral movement (SSH, SMB, RDP, WinRM, VNC) are reachable across zones.",
     "objective": "Prove that remote services are only reachable from management segments, and that the SOC sees the attempts.",
     "steps": [{"action": "exposure_check", "title": "Check remote-service ports", "params": {"ports": [22, 135, 139, 445, 3389, 5900, 5985, 5986]}}]},
    {"code": "RT-PURPLE-01", "name": "Detection validation: port scan", "difficulty": "basic",
     "description": "Run a 100-port scan so the blue team can confirm the port-scan detection fires on lab activity.",
     "objective": "Purple-team check that CR-NET-001 raises an alert for a real scan in the lab.",
     "steps": [{"action": "port_scan", "title": "Scan ports 1-100", "params": {"ports": ["1-100"]}}]},
]


def seed(db: Session) -> dict:
    have = {c for (c,) in db.execute(select(Scenario.code))}
    n = 0
    for s in BUILTIN_SCENARIOS:
        if s["code"] not in have:
            db.add(Scenario(**s, is_builtin=True))
            n += 1
    db.flush()
    return {"scenarios_created": n}


def event(db, a: Assessment, kind: str, message: str, step: int | None = None, actor=None, data: dict | None = None):
    db.add(AssessmentEvent(assessment_id=a.id, kind=kind, message=message[:1024], step_index=step, actor_id=getattr(actor, "id", None), data=data))


def refresh_expiry(db: Session, a: Assessment) -> None:
    if a.status in ("pending_approval", "approved") and utcnow() > a.window_end:
        a.status = "expired"
        event(db, a, "expired", "Authorisation window ended before execution")
        db.commit()


# ------------------------------------------------------------------ request
def _running_instance(db: Session, lab_id: int) -> tuple[Lab, LabInstance]:
    lab = db.execute(select(Lab).where(Lab.id == lab_id, Lab.deleted_at.is_(None))).scalar_one_or_none()
    if not lab:
        raise NotFound("Lab not found")
    inst = db.execute(select(LabInstance).where(LabInstance.lab_id == lab.id, LabInstance.status == "running").order_by(LabInstance.id.desc()).limit(1)).scalar_one_or_none()
    if not inst:
        raise Conflict("Assessments can only target a running lab", code="lab_not_running")
    return lab, inst


def request(db: Session, p, *, title, justification, scenario_id, lab_id, attacker_node, target_nodes, window_start, window_end) -> Assessment:
    sc = db.get(Scenario, scenario_id)
    if not sc or sc.is_archived:
        raise NotFound("Scenario not found")
    lab, inst = _running_instance(db, lab_id)
    if not (lab.owner_id == p.id or p.has("lab.manage")):
        raise Forbidden("You may only assess labs you own (or hold lab.manage)", details={"missing": ["lab.manage"]})
    now = utcnow()
    ws, we = window_start.replace(tzinfo=None), window_end.replace(tzinfo=None)
    if we <= ws or we <= now or we - ws > timedelta(hours=72):
        raise AppError("The authorisation window must end in the future and last at most 72 hours", code="invalid_window", status_code=422)
    containers = {c.node_key: c for c in inst.containers}
    plan = {c["node_key"]: c for c in lab.plan["containers"]}
    if attacker_node not in containers:
        raise AppError("The attacker node must be a deployed node of this lab", code="invalid_scope", status_code=422)
    if not target_nodes or len(target_nodes) > 50 or attacker_node in target_nodes:
        raise AppError("Choose 1-50 target nodes other than the attacker", code="invalid_scope", status_code=422)
    lab_cidrs = [ipaddress.ip_network(n["cidr"]) for n in lab.plan["networks"]]
    targets = []
    for key in target_nodes:
        c = containers.get(key)
        if not c:
            raise AppError(f"Target {key} is not a deployed node of this lab", code="invalid_scope", status_code=422)
        ips = [ip for ip in (c.addresses or {}).values() if any(ipaddress.ip_address(ip) in n for n in lab_cidrs)]
        if not ips:
            raise AppError(f"Target {key} has no address inside the lab networks", code="invalid_scope", status_code=422)
        targets.append({"node_key": key, "label": plan.get(key, {}).get("label", key), "ips": sorted(ips)})
    att = containers[attacker_node]
    att_ips = sorted((att.addresses or {}).values())
    reach = sorted({str(n) for n in lab_cidrs if any(ipaddress.ip_address(ip) in n for ip in att_ips)})
    target_cidrs = sorted({str(n) for n in lab_cidrs for t in targets for ip in t["ips"] if ipaddress.ip_address(ip) in n})
    errs = validate_steps(sc.steps)
    if errs:
        raise AppError("Scenario is invalid", code="invalid_scenario", status_code=422, details=errs)
    a = Assessment(title=title, justification=justification, scenario_id=sc.id,
                   scenario={"code": sc.code, "name": sc.name, "steps": sc.steps, "objective": sc.objective},
                   lab_id=lab.id, instance_id=inst.id, runtime_id=inst.runtime_id, attacker_node=attacker_node, attacker_ip=att_ips[0] if att_ips else "",
                   scope={"targets": targets, "cidrs": target_cidrs, "attacker_cidrs": reach, "lab_name": lab.name},
                   window_start=ws, window_end=we, status="pending_approval", requested_by=p.id)
    db.add(a)
    db.flush()
    event(db, a, "requested", f"{p.username} requested '{sc.name}' against {len(targets)} target(s) in lab {lab.name}", actor=p)
    record(db, "redteam.assessment.request", actor=p, resource_type="assessment", resource_id=a.id,
           details={"lab": lab.id, "runtime_id": inst.runtime_id, "scenario": sc.code, "targets": [t["node_key"] for t in targets]})
    return a


def decide(db: Session, p, a: Assessment, approve: bool, comment: str) -> None:
    refresh_expiry(db, a)
    if a.status != "pending_approval":
        raise Conflict(f"Assessment is {a.status}", code="invalid_state")
    # Local edition: the single operator approves their own scope. The scope itself is still enforced on execution
    # (only nodes of the operator's own running, isolated lab; inside the approved time window; kill switch honoured).
    if approve and len(comment.strip()) < 10:
        raise Conflict("Write a short authorisation note (at least 10 characters) confirming the targets are your own isolated lab",
                       code="note_required")
    a.status = "approved" if approve else "rejected"
    a.decided_by, a.decision_comment, a.decided_at = p.id, comment, utcnow()
    event(db, a, a.status, f"{'Approved' if approve else 'Rejected'} by {p.username}: {comment}", actor=p)
    record(db, f"redteam.assessment.{'approve' if approve else 'reject'}", actor=p, resource_type="assessment", resource_id=a.id,
           details={"comment": comment[:500], "self_approved": a.requested_by == p.id})


def start(db: Session, p, a: Assessment) -> None:
    refresh_expiry(db, a)
    if a.requested_by != p.id:
        raise Forbidden("Only the requester can execute an approved assessment")
    if get_value(db, "redteam.require_approval") and a.status != "approved":
        raise Conflict(f"Assessment is {a.status}; it must be approved first", code="not_approved")
    now = utcnow()
    if not a.window_start <= now <= a.window_end:
        raise Conflict("Outside the approved authorisation window", code="outside_window")
    if kill_switch_engaged(db):
        raise Conflict("The lab kill switch is engaged", code="kill_switch")
    inst = db.get(LabInstance, a.instance_id)
    if not inst or inst.status != "running" or inst.runtime_id != a.runtime_id:
        raise Conflict("The approved lab deployment is no longer running; request a new assessment", code="scope_changed")
    a.status = "queued"
    event(db, a, "queued", f"Execution started by {p.username}", actor=p)
    record(db, "redteam.assessment.execute", actor=p, resource_type="assessment", resource_id=a.id)
    db.commit()
    if os.environ.get("CR_LAB_EXECUTION", "celery") == "inline":
        run(a.id)
    else:
        from app.core.celery_app import celery_app
        celery_app.send_task("app.redteam.tasks.run_assessment", args=[a.id], queue="lab")


def abort(db: Session, p, a: Assessment) -> None:
    if a.status in ("pending_approval", "approved"):
        a.status = "cancelled"
        event(db, a, "cancelled", f"Cancelled by {p.username}", actor=p)
    elif a.status in ("queued", "running"):
        a.abort_requested = True
        event(db, a, "abort_requested", f"Abort requested by {p.username}", actor=p)
    else:
        raise Conflict(f"Assessment is {a.status}", code="invalid_state")
    record(db, "redteam.assessment.abort", actor=p, resource_type="assessment", resource_id=a.id)


# ------------------------------------------------------------------ execution (lab worker)
def _activity(db, a: Assessment, step: int, action: str, res: dict) -> int:
    """Record what the assessment actually did as SIEM telemetry, so the blue team can validate detections."""
    src = soc.builtin_source(db, ACTIVITY_SOURCE, "json")
    if not src.description:
        src.description = "Actions executed by authorised red team assessments inside labs (one record per probe)."
    ts = utcnow().isoformat() + "Z"
    recs = []
    base = {"timestamp": ts, "dataset": "redteam.activity", "src_ip": a.attacker_ip, "host": a.attacker_node, "user": f"assessment-{a.id}"}
    if action == "host_discovery":
        for ip in res["up"]:
            recs.append({**base, "event_uid": f"rt{a.id}-{step}-icmp-{ip}", "category": "network", "action": "icmp_echo", "outcome": "success",
                         "dst_ip": ip, "protocol": "icmp", "message": f"assessment #{a.id} host discovery: {ip} answered ICMP echo"})
    for ip, port in res["open"] + res["closed"]:
        ok = (ip, port) in res["open"]
        recs.append({**base, "event_uid": f"rt{a.id}-{step}-tcp-{ip}-{port}", "category": "network", "action": "tcp_connect", "outcome": "success" if ok else "failure",
                     "dst_ip": ip, "dst_port": port, "protocol": "tcp", "message": f"assessment #{a.id} {action}: {ip}:{port} {'open' if ok else 'closed'}"})
    for d in res.get("dns", []):
        recs.append({**base, "event_uid": f"rt{a.id}-{step}-dns-{d['domain']}", "category": "dns", "action": "query", "outcome": "success" if d["resolved"] else "failure",
                     "host": d["domain"], "protocol": "dns", "message": f"assessment #{a.id} dns_probe: {d['domain']} {'resolved' if d['resolved'] else 'NXDOMAIN/no answer'}"})
    for h in res["http"]:
        recs.append({**base, "event_uid": f"rt{a.id}-{step}-http-{h['ip']}-{h['port']}-{h['path']}", "category": "http", "action": "GET", "outcome": str(h["status"] or ""),
                     "dst_ip": h["ip"], "dst_port": h["port"], "protocol": "http", "message": f"GET http://{h['ip']}:{h['port']}{h['path']} {h['status'] or 'no response'} ua=cyber-range-assessment"})
    if not recs:
        return 0
    return soc.ingest(db, src, recs[:5000], kind="json")["accepted"]


def _findings(db, a: Assessment, step: int, action: str, res: dict) -> int:
    n = 0
    label = {ip: t["label"] for t in a.scope["targets"] for ip in t["ips"]}
    if action == "host_discovery":
        for ip in res["up"]:
            db.add(Finding(assessment_id=a.id, step_index=step, kind="host_up", severity=0, title=f"Live host {ip}", target_ip=ip, detail={"label": label.get(ip)}))
            n += 1
    for ip, port in res["open"]:
        sensitive = action == "exposure_check"
        db.add(Finding(assessment_id=a.id, step_index=step, kind="exposure" if sensitive else "open_port", severity=3 if sensitive else 1,
                       title=(f"Sensitive port {port} reachable on {label.get(ip, ip)}" if sensitive else f"Open TCP {port} on {label.get(ip, ip)}"),
                       target_ip=ip, port=port, detail={"label": label.get(ip), "from": a.attacker_node}))
        n += 1
    if action == "web_attack_probe":
        answered = [h for h in res["http"] if h["status"] is not None and h["status"] < 400]
        for h in answered:
            db.add(Finding(assessment_id=a.id, step_index=step, kind="web_probe", severity=1,
                           title=f"Attack-pattern request answered {h['status']} on {label.get(h['ip'], h['ip'])}:{h['port']} (no blocking control in path)",
                           target_ip=h["ip"], port=h["port"], detail=h))
            n += 1
        return n
    for h in res["http"]:
        if h["status"] is None:
            continue
        risky = h["path"] in SENSITIVE_PATHS and h["status"] < 400
        db.add(Finding(assessment_id=a.id, step_index=step, kind="http_service", severity=2 if risky else 0,
                       title=f"{'Sensitive path exposed' if risky else 'HTTP'} {h['path']} → {h['status']} on {label.get(h['ip'], h['ip'])}:{h['port']}",
                       target_ip=h["ip"], port=h["port"], detail=h))
        n += 1
    return n


def run(assessment_id: int) -> str:
    d = get_driver()
    with SessionLocal() as db:
        a = db.execute(select(Assessment).where(Assessment.id == assessment_id).with_for_update()).scalar_one_or_none()
        if not a or a.status != "queued":
            return "skipped"
        a.status, a.started_at = "running", utcnow()
        event(db, a, "started", f"Running {len(a.scenario['steps'])} step(s) from {a.attacker_node} ({a.attacker_ip})")
        db.commit()
        try:
            for i, step in enumerate(a.scenario["steps"]):
                db.refresh(a)
                inst = db.get(LabInstance, a.instance_id)
                reason = ("aborted by user" if a.abort_requested else "kill switch engaged" if kill_switch_engaged(db) else
                          "authorisation window ended" if utcnow() > a.window_end else
                          "lab deployment changed" if not inst or inst.status != "running" or inst.runtime_id != a.runtime_id else None)
                if reason:
                    a.status, a.finished_at = "aborted", utcnow()
                    event(db, a, "aborted", f"Stopped before step {i + 1}: {reason}", step=i)
                    db.commit()
                    return a.status
                att = next((c for c in inst.containers if c.node_key == a.attacker_node), None)
                if not att or not att.docker_id:
                    raise DriverError("attacker container is gone")
                a.current_step = i
                meta = ACTIONS[step["action"]]
                event(db, a, "step_started", f"Step {i + 1}: {step.get('title') or meta['title']}", step=i, data={"action": step["action"], "mitre": meta["mitre"]})
                db.commit()
                targets = [ip for t in a.scope["targets"] for ip in t["ips"]]
                argv, timeout = build_command(step["action"], step.get("params") or {}, targets, a.scope["cidrs"])
                code, out = d.exec(att.docker_id, argv, timeout)
                res = parse_output(step["action"], out)
                nf = _findings(db, a, i, step["action"], res)
                db.commit()
                nt = _activity(db, a, i, step["action"], res)
                db.refresh(a)
                summary = {"up": len(res["up"]), "open": len(res["open"]), "closed": len(res["closed"]), "http": len(res["http"]), "exit_code": code}
                event(db, a, "step_finished", f"Step {i + 1} done: {summary['up']} hosts up, {summary['open']} open ports, {summary['http']} HTTP responses, {nf} findings, {nt} telemetry records",
                      step=i, data={**summary, "open": res["open"][:200], "up": res["up"][:256], "http": res["http"][:200]})
                db.commit()
            a.status, a.finished_at, a.current_step = "completed", utcnow(), None
            event(db, a, "completed", "Assessment completed")
        except Exception as e:  # noqa: BLE001 - failures must be recorded on the assessment
            db.rollback()
            a = db.get(Assessment, assessment_id)
            log.exception("assessment_failed", assessment=assessment_id)
            a.status, a.finished_at, a.error = "failed", utcnow(), str(e)[:2000]
            event(db, a, "failed", f"Execution failed: {e}"[:1024])
        db.commit()
        return a.status


# ------------------------------------------------------------------ detection correlation + report
def detections(db: Session, a: Assessment) -> list[dict]:
    if not a.started_at:
        return []
    end = (a.finished_at or utcnow()) + timedelta(minutes=5)
    rows = db.execute(select(Alert).join(AlertEvent, AlertEvent.alert_id == Alert.id).join(SecurityEvent, SecurityEvent.id == AlertEvent.event_id)
                      .where(SecurityEvent.src_ip == a.attacker_ip, SecurityEvent.occurred_at.between(a.started_at - timedelta(seconds=5), end))
                      .distinct()).scalars().all()
    return [{"id": x.id, "title": x.title, "rule": x.rule.code, "severity": x.severity, "status": x.status, "first_seen": x.first_seen} for x in rows]


def report_markdown(db: Session, a: Assessment, users: dict) -> str:
    sev = ["info", "low", "medium", "high", "critical"]
    f = db.execute(select(Finding).where(Finding.assessment_id == a.id).order_by(Finding.severity.desc(), Finding.id)).scalars().all()
    ev = db.execute(select(AssessmentEvent).where(AssessmentEvent.assessment_id == a.id).order_by(AssessmentEvent.id)).scalars().all()
    det = detections(db, a)
    out = [f"# Assessment report: {a.title}", "",
           f"- Assessment: #{a.id} · status **{a.status}**", f"- Scenario: {a.scenario['code']} {a.scenario['name']}",
           f"- Lab: {a.scope.get('lab_name')} (deployment {a.runtime_id}) · attacker node {a.attacker_node} ({a.attacker_ip})",
           f"- Requested by {users.get(a.requested_by)} · decided by {users.get(a.decided_by)} at {a.decided_at} UTC: {a.decision_comment or ''}",
           f"- Authorisation window: {a.window_start} → {a.window_end} UTC", f"- Executed: {a.started_at} → {a.finished_at} UTC", "",
           "## Objective", "", a.scenario.get("objective") or "—", "", "## Justification", "", a.justification, "",
           "## Scope", "", "| Target | Addresses |", "|---|---|"]
    out += [f"| {t['label']} ({t['node_key']}) | {', '.join(t['ips'])} |" for t in a.scope["targets"]]
    out += ["", f"In-scope subnets: {', '.join(a.scope['cidrs'])}", "", "## Findings", ""]
    if f:
        out += ["| Severity | Finding | Target | Port |", "|---|---|---|---|"]
        out += [f"| {sev[x.severity]} | {x.title} | {x.target_ip or ''} | {x.port or ''} |" for x in f]
    else:
        out.append("No findings were produced.")
    out += ["", "## Detection coverage", ""]
    out += [f"- Alert #{d['id']} {d['rule']} ({sev[d['severity']]}): {d['title']} · {d['status']}" for d in det] or \
           ["- No SOC alert was raised for the attacker address during the run. Review detection rules and sensor coverage."]
    out += ["", "## Timeline (UTC)", ""] + [f"- {e.at} · {e.kind} · {e.message}" for e in ev]
    out += ["", "_All actions were non-destructive inventory and validation steps executed inside the isolated lab, within the approved scope and window._", ""]
    return "\n".join(out)

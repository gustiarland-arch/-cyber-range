"""Live state of one deployed lab for the 3D view: node status and addresses, real traffic, alerts and red team steps.

Everything here is read from data the platform already stores; nothing is invented or animated server-side:

* node status and IPs come from the lab's container/VM rows (kept in sync with Docker by the lab worker's
  reconcile task) and the Redis stats cache;
* traffic is aggregated from SIEM events whose source is a network sensor (Zeek or Suricata datasets), grouped by
  (source IP, destination IP) and by time bucket so the browser can replay it;
* alerts are matched to nodes through the events that raised them;
* red team steps come from the assessment's own event log and the telemetry it wrote for each probe.

The response only covers IP addresses that belong to the lab, so events of other labs never leak into the view.
"""
import ipaddress
import re
from datetime import timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.blueteam.models import Alert, AlertEvent, SecurityEvent
from app.core.database import utcnow
from app.cyber_range import service
from app.cyber_range.models import Lab, LabEvent
from app.iam.deps import Principal
from app.redteam.actions import ACTIONS
from app.redteam.models import Assessment, AssessmentEvent

SENSOR_DATASET_PREFIXES = ("zeek.", "suricata.")
REDTEAM_DATASET = "redteam.activity"
BUCKETS = 60
MAX_PAIRS = 400
MAX_EXTERNAL = 12
MAX_ALERTS = 200
MAX_ASSESSMENTS = 10
UID_STEP = re.compile(r"^rt(\d+)-(\d+)-")

# Docker / VM states -> the four states the view draws
_STATE = {"running": "running", "restarting": "pending", "created": "pending", "pending": "pending", "starting": "pending",
          "exited": "stopped", "paused": "stopped", "stopped": "stopped",
          "dead": "error", "missing": "error", "failed": "error", "removing": "error", "error": "error"}


def node_state(raw: str | None) -> str:
    return _STATE.get((raw or "").lower(), "absent" if raw is None else "pending")


def _iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _valid_ip(v) -> str | None:
    try:
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        return None


def _nodes(lab: Lab, inst, stats: dict | None) -> tuple[list[dict], dict[str, str]]:
    """Return per-node live state and the IP -> node key map for this deployment."""
    containers = {c.node_key: c for c in (inst.containers if inst else [])}
    vms = {v.node_key: v for v in (inst.vms if inst else [])}
    skipped = {s.get("node_key") or s.get("key") for s in (lab.plan.get("skipped") or []) if isinstance(s, dict)}
    samples = (stats or {}).get("containers") or {}
    ip_map: dict[str, str] = {}
    out = []
    for n in lab.topology.get("nodes", []):
        key = n["key"]
        c, vm = containers.get(key), vms.get(key)
        ips: dict[str, str] = {}
        if c is not None:
            ips = {k: v for k, v in (c.addresses or {}).items() if _valid_ip(v)}
            raw, backing, name = c.status, "container", c.name
        elif vm is not None:
            ips = {nic.get("subnet_key", ""): nic["ip"] for nic in (vm.nics or []) if _valid_ip(nic.get("ip"))}
            raw, backing, name = vm.status, "vm", vm.name
        else:
            raw, backing, name = None, "none", None
        if not ips:  # planned addresses from the topology (shown, but marked as planned)
            planned = {i.get("subnet") or i.get("name", ""): i["ip"] for i in n.get("interfaces", []) if _valid_ip(i.get("ip"))}
        else:
            planned = {}
        for ip in (ips or planned).values():
            ip_map.setdefault(_valid_ip(ip), key)
        state = node_state(raw) if inst is not None else "absent"
        if inst is not None and inst.status != "running" and state == "running":
            state = "pending"  # the instance is transitioning; containers are not trusted to be serving yet
        out.append({"key": key, "label": n.get("label") or key, "type": n.get("type"), "zone": n.get("zone"),
                    "backing": backing, "name": name, "raw_status": raw, "state": state,
                    "ips": ips or planned, "ips_planned": not ips and bool(planned), "skipped": key in skipped,
                    "stats": samples.get(key)})
    return out, ip_map


def _in_lab(ips):
    return or_(SecurityEvent.src_ip.in_(ips), SecurityEvent.dst_ip.in_(ips))


def _traffic(db: Session, ip_map: dict, start, end, bucket_s: int) -> dict:
    ips = list(ip_map)
    if not ips:
        return {"flows": [], "external": [], "total_events": 0}
    sensor = or_(*[SecurityEvent.dataset.like(p + "%") for p in SENSOR_DATASET_PREFIXES])
    bucket = func.floor((func.unix_timestamp(SecurityEvent.occurred_at) - func.unix_timestamp(start)) / bucket_s)
    rows = db.execute(
        select(SecurityEvent.src_ip, SecurityEvent.dst_ip, bucket.label("b"), func.count(), func.max(SecurityEvent.severity),
               func.max(SecurityEvent.occurred_at), func.group_concat(func.distinct(SecurityEvent.protocol)),
               func.group_concat(func.distinct(SecurityEvent.dataset)))
        .where(SecurityEvent.occurred_at >= start, SecurityEvent.occurred_at <= end, sensor, _in_lab(ips))
        .group_by(SecurityEvent.src_ip, SecurityEvent.dst_ip, "b")
    ).all()
    pairs: dict[tuple, dict] = {}
    external: dict[str, int] = {}
    total = 0
    for src, dst, b, n, sev, last, protos, datasets in rows:
        src, dst = _valid_ip(src), _valid_ip(dst)
        a, z = ip_map.get(src), ip_map.get(dst)
        if not a and not z:
            continue
        for ip, k in ((src, a), (dst, z)):
            if ip and not k:
                external[ip] = external.get(ip, 0) + n
        p = pairs.setdefault((src, dst), {"src": a, "dst": z, "src_ip": src, "dst_ip": dst, "count": 0, "max_severity": 0,
                                          "last_at": None, "protocols": set(), "datasets": set(), "buckets": {}})
        p["count"] += n
        total += n
        p["max_severity"] = max(p["max_severity"], int(sev or 0))
        p["last_at"] = max(p["last_at"], last) if p["last_at"] else last
        p["protocols"].update(x for x in (protos or "").split(",") if x)
        p["datasets"].update(x for x in (datasets or "").split(",") if x)
        bi = max(0, min(BUCKETS - 1, int(b or 0)))
        p["buckets"][bi] = p["buckets"].get(bi, 0) + n
    ext = sorted(external.items(), key=lambda kv: -kv[1])[:MAX_EXTERNAL]
    keep = {ip for ip, _ in ext}
    flows = []
    for p in sorted(pairs.values(), key=lambda x: -x["count"])[:MAX_PAIRS]:
        if (not p["src"] and p["src_ip"] not in keep) or (not p["dst"] and p["dst_ip"] not in keep):
            continue
        p.update(last_at=_iso(p["last_at"]), protocols=sorted(p["protocols"]), datasets=sorted(p["datasets"]),
                 buckets=[p["buckets"].get(i, 0) for i in range(BUCKETS)])
        flows.append(p)
    return {"flows": flows, "external": [{"ip": ip, "events": n} for ip, n in ext], "total_events": total}


def _alerts(db: Session, ip_map: dict, start, end) -> list[dict]:
    ips = list(ip_map)
    if not ips:
        return []
    rows = db.execute(
        select(Alert.id, Alert.title, Alert.severity, Alert.status, Alert.first_seen, Alert.last_seen, Alert.event_count,
               SecurityEvent.src_ip, SecurityEvent.dst_ip, func.min(SecurityEvent.occurred_at), func.max(SecurityEvent.occurred_at))
        .join(AlertEvent, AlertEvent.alert_id == Alert.id).join(SecurityEvent, SecurityEvent.id == AlertEvent.event_id)
        .where(Alert.last_seen >= start, Alert.first_seen <= end, _in_lab(ips))
        .group_by(Alert.id, Alert.title, Alert.severity, Alert.status, Alert.first_seen, Alert.last_seen, Alert.event_count,
                  SecurityEvent.src_ip, SecurityEvent.dst_ip)
        .order_by(Alert.last_seen.desc()).limit(MAX_ALERTS * 4)
    ).all()
    alerts: dict[int, dict] = {}
    for aid, title, sev, status, first, last, cnt, src, dst, ev_first, ev_last in rows:
        a = alerts.setdefault(aid, {"id": aid, "title": title, "severity": sev, "status": status, "first_seen": first, "last_seen": last,
                                    "event_count": cnt, "nodes": {}})
        for ip, role in ((src, "source"), (dst, "target")):
            k = ip_map.get(_valid_ip(ip)) if ip else None
            if k:
                a["nodes"].setdefault(k, set()).add(role)
    out = []
    for a in list(alerts.values())[:MAX_ALERTS]:
        a["nodes"] = [{"key": k, "roles": sorted(r)} for k, r in a["nodes"].items()]
        a["first_seen"], a["last_seen"] = _iso(a["first_seen"]), _iso(a["last_seen"])
        out.append(a)
    return out


def _subnets(node: dict | None) -> set[str]:
    return set((node or {}).get("ips", {}).keys()) if node and not node.get("ips_planned") else set()


def _assessments(db: Session, lab: Lab, inst, ip_map: dict, start, nodes: list[dict] | None = None) -> list[dict]:
    from app.redteam.purple import assessment_steps
    by_key = {n["key"]: n for n in (nodes or [])}
    if inst is None:
        return []
    rows = db.execute(select(Assessment).where(Assessment.lab_id == lab.id, Assessment.instance_id == inst.id)
                      .order_by(Assessment.id.desc()).limit(MAX_ASSESSMENTS)).scalars().all()
    out = []
    for a in rows:
        evs = db.execute(select(AssessmentEvent).where(AssessmentEvent.assessment_id == a.id).order_by(AssessmentEvent.id)).scalars().all()
        if a.finished_at and a.finished_at < start and not evs:
            continue
        # which lab nodes each step actually touched, from the telemetry the assessment wrote per probe
        touched: dict[int, set] = {}
        for uid, dst in db.execute(select(SecurityEvent.event_uid, SecurityEvent.dst_ip)
                                   .where(SecurityEvent.dataset == REDTEAM_DATASET, SecurityEvent.user == f"assessment-{a.id}")).all():
            m = UID_STEP.match(uid or "")
            k = ip_map.get(_valid_ip(dst)) if dst else None
            if m and int(m.group(1)) == a.id and k:
                touched.setdefault(int(m.group(2)), set()).add(k)
        scope_nodes = [t["node_key"] for t in a.scope.get("targets", []) if t.get("node_key")]
        # Docker lab subnets are isolated from each other on the host (internal bridge networks), so a target that shares no
        # subnet with the attacker cannot be reached in this lab even through a router/firewall node. Say so instead of
        # letting such probes look like "closed" or "not vulnerable".
        att_nets = _subnets(by_key.get(a.attacker_node))
        isolated = sorted(k for k in scope_nodes if att_nets and not (att_nets & _subnets(by_key.get(k))))
        detection = {d["step"]: d for d in assessment_steps(db, a)}
        steps = []
        for i, s in enumerate(a.scenario.get("steps", [])):
            meta = ACTIONS.get(s.get("action"), {})
            started = next((e.at for e in evs if e.kind == "step_started" and e.step_index == i), None)
            finished = next((e.at for e in evs if e.kind == "step_finished" and e.step_index == i), None)
            fin_msg = next((e.message for e in evs if e.kind == "step_finished" and e.step_index == i), "")
            targets = sorted(touched.get(i, set()))
            if not targets and s.get("action") == "dns_probe" and scope_nodes:
                targets = scope_nodes[:1]  # DNS probes query the first target directly
            if not targets and started:
                targets = scope_nodes  # running or no reachable host: draw the authorised scope
            state = "done" if finished else ("running" if started and a.status == "running" else ("skipped" if started else "pending"))
            steps.append({"index": i, "action": s.get("action"), "title": s.get("title") or meta.get("title", s.get("action")),
                          "mitre": meta.get("mitre"), "tactic": meta.get("tactic"), "state": state, "started_at": _iso(started),
                          "finished_at": _iso(finished), "summary": fin_msg, "targets": targets,
                          "isolated_targets": [k for k in targets if k in isolated],
                          "detection": _detection(detection.get(i))})
        out.append({"id": a.id, "title": a.title, "status": a.status, "attacker_node": a.attacker_node, "attacker_ip": a.attacker_ip,
                    "isolated_targets": isolated, "attacker_subnets": sorted(att_nets),
                    "current_step": a.current_step, "started_at": _iso(a.started_at), "finished_at": _iso(a.finished_at),
                    "steps": steps, "events": [{"at": _iso(e.at), "kind": e.kind, "step": e.step_index, "message": e.message} for e in evs]})
    return out


def _detection(d: dict | None) -> dict | None:
    """Blue team verdict for one red team step (see app/redteam/purple.py)."""
    if not d or not d["attacked"]:
        return None
    verdict = "detected" if d["detected_same_technique"] else "other_rule" if d["detected"] else "missed"
    return {"verdict": verdict, "evidence": d["evidence"], "detected_after_seconds": d["detected_after_seconds"],
            "alerts": [{k: x[k] for k in ("id", "title", "severity", "status", "rule", "technique", "same_technique", "sources",
                                          "first_at", "detected_after_seconds")} for x in d["alerts"]]}


def _lab_events(db: Session, lab: Lab, start) -> list[dict]:
    rows = db.execute(select(LabEvent).where(LabEvent.lab_id == lab.id, LabEvent.occurred_at >= start)
                      .order_by(LabEvent.id.desc()).limit(100)).scalars().all()
    return [{"at": _iso(e.occurred_at), "level": e.level, "kind": e.kind, "message": e.message,
             "node": (e.data or {}).get("node") if isinstance(e.data, dict) else None} for e in rows]


# lab lifecycle event kind -> state of every node afterwards
_LIFECYCLE = {"lab.provision": "running", "lab.start": "running", "lab.reset": "running", "lab.restore": "running",
              "lab.stop": "stopped", "lab.destroy": "absent"}
_NODE_EVENTS = ("container.exited", "container.state", "vm.exited", "vm.state")


def _status_history(db: Session, lab: Lab, inst, start) -> dict:
    """State changes of this deployment, oldest first, for replaying node status.

    `initial` is the state of every node at the window start, reconstructed from the latest lifecycle/node events before it.
    Entries come from lab lifecycle operations (all nodes) and from the lab worker's reconcile (one node)."""
    if inst is None:
        return {"initial": {}, "changes": []}
    kinds = (*_LIFECYCLE, *_NODE_EVENTS)
    rows = db.execute(select(LabEvent).where(LabEvent.instance_id == inst.id, LabEvent.kind.in_(kinds))
                      .order_by(LabEvent.id).limit(5000)).scalars().all()
    initial: dict[str, str] = {}
    changes = []
    for e in rows:
        if e.kind in _LIFECYCLE:
            ch = {"at": _iso(e.occurred_at), "node": None, "state": _LIFECYCLE[e.kind], "reason": e.message}
        else:
            d = e.data if isinstance(e.data, dict) else {}
            if not d.get("node"):
                continue
            ch = {"at": _iso(e.occurred_at), "node": d["node"], "state": node_state(d.get("state")), "reason": e.message}
        if e.occurred_at < start:
            if ch["node"] is None:
                initial = {"*": ch["state"]}
            else:
                initial[ch["node"]] = ch["state"]
        else:
            changes.append(ch)
    return {"initial": initial, "changes": changes}


def live_view(db: Session, p: Principal, lab_id: int, minutes: int) -> dict:
    lab = service.get_lab(db, p, lab_id)
    inst = service.current_instance(db, lab)
    end = utcnow()
    start = end - timedelta(minutes=minutes)
    bucket_s = max(1, (minutes * 60) // BUCKETS)
    nodes, ip_map = _nodes(lab, inst, service.live_stats(inst))
    see_soc = p.has("blueteam.alerts.view")
    see_red = p.has("redteam.assessment.view")
    traffic = _traffic(db, ip_map, start, end, bucket_s) if see_soc else {"flows": [], "external": [], "total_events": 0}
    return {
        "lab": {"id": lab.id, "name": lab.name, "network_id": lab.network_id, "network_version": lab.network_version},
        "instance": ({"id": inst.id, "runtime_id": inst.runtime_id, "status": inst.status, "started_at": _iso(inst.started_at)}
                     if inst else None),
        "topology": lab.topology,
        "window": {"start": _iso(start), "end": _iso(end), "minutes": minutes, "bucket_seconds": bucket_s, "buckets": BUCKETS},
        "nodes": nodes,
        "traffic": traffic,
        "alerts": _alerts(db, ip_map, start, end) if see_soc else [],
        "assessments": _assessments(db, lab, inst, ip_map, start, nodes) if see_red else [],
        "lab_events": _lab_events(db, lab, start),
        "status_history": _status_history(db, lab, inst, start),
        "access": {"soc": see_soc, "redteam": see_red, "terminal": p.has("lab.terminal"), "operate": p.has("lab.operate")},
        "generated_at": _iso(end),
    }


# ------------------------------------------------------------------ change stream (server-sent events)
STREAM_CHECK_SECONDS = 2.0
STREAM_HEARTBEAT_SECONDS = 15.0
STREAM_MAX_SECONDS = 600  # the browser reconnects; keeps long-lived connections bounded


def fingerprint(db: Session, lab_id: int) -> str:
    """Cheap summary of everything the live view shows; it changes whenever a refetch would show something new."""
    from app.cyber_range.models import LabContainer, LabInstance
    inst_rows = db.execute(select(LabInstance.id, LabInstance.status).where(LabInstance.lab_id == lab_id)
                           .order_by(LabInstance.id.desc()).limit(1)).first()
    containers = db.execute(select(func.group_concat(LabContainer.status)).where(LabContainer.instance_id == (inst_rows[0] if inst_rows else 0))).scalar()
    parts = [
        inst_rows and f"{inst_rows[0]}:{inst_rows[1]}",
        containers,
        db.execute(select(func.max(SecurityEvent.id))).scalar(),
        db.execute(select(func.max(Alert.last_seen))).scalar(),
        db.execute(select(func.max(LabEvent.id)).where(LabEvent.lab_id == lab_id)).scalar(),
        db.execute(select(func.max(AssessmentEvent.id)).join(Assessment, Assessment.id == AssessmentEvent.assessment_id)
                   .where(Assessment.lab_id == lab_id)).scalar(),
    ]
    return "|".join(str(x) for x in parts)


async def change_stream(lab_id: int, is_disconnected):
    """Yield SSE messages: `changed` when the fingerprint moves, a comment heartbeat otherwise. No data payload is sent:
    the browser refetches GET /labs/{id}/live, which applies the caller's permissions and IP scoping again."""
    import asyncio
    import time

    from app.core.database import SessionLocal

    def check():
        with SessionLocal() as db:
            return fingerprint(db, lab_id)

    last = await asyncio.to_thread(check)
    yield "retry: 3000\nevent: ready\ndata: {}\n\n"
    started = beat = time.monotonic()
    while time.monotonic() - started < STREAM_MAX_SECONDS:
        await asyncio.sleep(STREAM_CHECK_SECONDS)
        if await is_disconnected():
            return
        fp = await asyncio.to_thread(check)
        if fp != last:
            last = fp
            beat = time.monotonic()
            yield "event: changed\ndata: {}\n\n"
        elif time.monotonic() - beat > STREAM_HEARTBEAT_SECONDS:
            beat = time.monotonic()
            yield ": keep-alive\n\n"

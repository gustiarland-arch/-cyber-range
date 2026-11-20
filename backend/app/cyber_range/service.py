"""API-side lab management: validation, authorization, state transitions, dispatch to the lab worker."""
import json
import uuid

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.redis_client import get_redis
from app.cyber_range import runtime
from app.cyber_range.engine import safety
from app.cyber_range.engine.planner import PlanError, build_plan
from app.cyber_range.models import INSTANCE_ACTIVE, Lab, LabEvent, LabImage, LabInstance, Snapshot
from app.governance.service import update_setting
from app.iam.deps import Principal
from app.network import service as network_service
from app.network.validation import validate

DEFAULT_IMAGES = [
    {"reference": "alpine:3.20", "title": "Alpine Linux 3.20", "description": "Minimal Linux host (busybox tools, ping, nc).",
     "node_types": ["server", "workstation", "router", "firewall", "vm", "container", "sensor", "database"],
     "command": ["sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"], "tmpfs": ["/tmp"],
     "cap_add": [], "default_cpus": 0.25, "default_memory_mb": 64},
    {"reference": "nginx:1.27-alpine", "title": "NGINX web server", "description": "HTTP service on port 80 for web-tier nodes.",
     "node_types": ["server", "container"], "command": None,
     "tmpfs": ["/var/cache/nginx", "/var/run", "/tmp"], "cap_add": ["CHOWN", "SETUID", "SETGID", "NET_BIND_SERVICE"],
     "default_cpus": 0.25, "default_memory_mb": 64},
    {"reference": "busybox:1.36", "title": "BusyBox", "description": "Tiny utility image for workstations and sensors.",
     "node_types": ["workstation", "sensor", "container"],
     "command": ["sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"], "tmpfs": ["/tmp"],
     "cap_add": [], "default_cpus": 0.1, "default_memory_mb": 32},
    {"reference": "redis:7-alpine", "title": "Redis (unauthenticated, lab only)",
     "description": "Redis 7 started without a password: a deliberately weak data-tier service for vulnerability-management exercises. "
                    "Never expose outside a lab.",
     "node_types": ["database", "server", "container"],
     "command": ["redis-server", "--protected-mode", "no", "--save", "", "--appendonly", "no"], "tmpfs": ["/data", "/tmp"],
     "cap_add": ["SETUID", "SETGID", "CHOWN"], "default_cpus": 0.25, "default_memory_mb": 64},
    # Office lab (lab-images/office, built locally by start.bat/start.sh): one image, three tags, role = command.
    {"reference": "cyber-range/lab-dc:1.0", "title": "Domain controller Active Directory (Samba AD DC)",
     "description": "Domain lab.local dengan karyawan DEMO, grup departemen, file share Umum/Keuangan, DNS dan Kerberos. "
                    "Log autentikasi bergaya Windows (4624/4625/4720/4728) masuk SIEM lewat host agent.",
     "node_types": ["server"], "command": ["/opt/cr/start", "dc"], "tmpfs": ["/tmp"],
     "cap_add": ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID", "NET_BIND_SERVICE", "KILL"], "default_cpus": 0.5, "default_memory_mb": 512},
    {"reference": "cyber-range/lab-portal:1.0", "title": "Portal intranet (login domain)",
     "description": "Portal karyawan di port 80: login Kerberos ke domain controller, pengumuman, direktori, pengajuan cuti. "
                    "Setiap request tercatat sebagai web.access.",
     "node_types": ["server"], "command": ["/opt/cr/start", "portal"], "tmpfs": ["/tmp"],
     "cap_add": ["NET_BIND_SERVICE"], "default_cpus": 0.25, "default_memory_mb": 128},
    {"reference": "cyber-range/lab-ws:1.0", "title": "Workstation karyawan (dengan karyawan simulasi)",
     "description": "PC karyawan: karyawan simulasi login ke domain, membuka file share, memakai portal dan DNS sebagai lalu lintas "
                    "normal. Telemetri proses, login dan file masuk SIEM. Bisa juga dipakai sebagai node attacker assessment.",
     "node_types": ["workstation"], "command": ["/opt/cr/start", "ws"], "tmpfs": ["/tmp"],
     "cap_add": ["SETUID", "SETGID"], "default_cpus": 0.25, "default_memory_mb": 192},
]


def seed_images(db: Session) -> int:
    have = {r for (r,) in db.execute(select(LabImage.reference))}
    n = 0
    for img in DEFAULT_IMAGES:
        if img["reference"] not in have:
            db.add(LabImage(**img))
            n += 1
    db.flush()
    return n


def image_dicts(db: Session) -> list[dict]:
    rows = db.execute(select(LabImage).order_by(LabImage.id)).scalars()
    return [{"reference": i.reference, "node_types": i.node_types, "command": i.command, "tmpfs": i.tmpfs, "cap_add": i.cap_add,
             "default_cpus": i.default_cpus, "default_memory_mb": i.default_memory_mb, "is_enabled": i.is_enabled} for i in rows]


# ------------------------------------------------------------------ access
def visible_query(p: Principal):
    q = select(Lab).where(Lab.deleted_at.is_(None))
    return q if p.has("lab.manage") else q.where(Lab.owner_id == p.id)


def get_lab(db: Session, p: Principal, lab_id: int, *, operate: bool = False, lock: bool = False) -> Lab:
    q = select(Lab).where(Lab.id == lab_id, Lab.deleted_at.is_(None))
    if lock:
        q = q.with_for_update()
    lab = db.execute(q).scalar_one_or_none()
    if lab is None or not (lab.owner_id == p.id or p.has("lab.manage")):
        raise NotFound("Lab not found")
    if operate and not ((lab.owner_id == p.id and p.has("lab.operate")) or p.has("lab.manage")):
        record(db, "authz.denied", outcome="denied", actor=p, resource_type="lab", resource_id=lab.id, details={"reason": "not_operator"})
        db.commit()
        raise Forbidden("You cannot operate this lab", details={"missing": ["lab.operate"]})
    return lab


def current_instance(db: Session, lab: Lab, *, lock: bool = False) -> LabInstance | None:
    q = select(LabInstance).where(LabInstance.lab_id == lab.id, LabInstance.status.in_(INSTANCE_ACTIVE + ("failed",)))
    if lock:
        q = q.with_for_update()
    return db.execute(q.order_by(LabInstance.id.desc()).limit(1)).scalar_one_or_none()


def _event(db, lab, inst, kind, msg, level="info"):
    runtime.event(db, lab.id, inst.id if inst else None, kind, msg, level)


# ------------------------------------------------------------------ labs
def create_lab(db: Session, p: Principal, *, network_id: int, name: str, description: str) -> Lab:
    net = network_service.get_for(db, p, network_id)
    doc = network_service.to_doc(net)
    issues = validate(doc)
    errors = [i for i in issues if i.severity == "error"]
    if errors:
        raise AppError("The topology has validation errors; fix them in the editor before deploying", code="invalid_topology",
                       status_code=422, details=[e.model_dump() for e in errors])
    from app.cyber_range.engine.vm import vm_capability
    cap = vm_capability()
    try:
        plan = build_plan(doc.model_dump(mode="json"), image_dicts(db), vm_supported=cap["supported"], vm_templates=cap["templates"])
    except PlanError as e:
        raise AppError("The topology cannot be deployed", code="plan_error", status_code=422, details=e.problems) from None
    safety.check_plan(db, plan)
    lab = Lab(name=name, description=description, owner_id=p.id, network_id=net.id, network_version=net.version,
              topology=doc.model_dump(mode="json"), plan=plan)
    db.add(lab)
    db.flush()
    _event(db, lab, None, "lab.created", f"Lab created from '{net.name}' v{net.version}: {plan['totals']['containers']} containers, {plan['totals']['networks']} networks")
    record(db, "lab.create", actor=p, resource_type="lab", resource_id=lab.id,
           details={"network_id": net.id, "network_version": net.version, "totals": plan["totals"]})
    return lab


def _transition(db: Session, p: Principal, lab: Lab, inst: LabInstance, allowed: tuple, to: str, action: str, **kw) -> LabInstance:
    if inst is None or inst.status not in allowed:
        raise Conflict(f"Cannot {action} a lab that is {inst.status if inst else 'not deployed'}", code="invalid_state")
    inst.status = to
    _event(db, lab, inst, f"lab.{action}.requested", f"{action.capitalize()} requested by {p.username}")
    record(db, f"lab.{action}", actor=p, resource_type="lab", resource_id=lab.id, details={"instance": inst.id, **{k: v for k, v in kw.items() if k != "return_to"}})
    db.commit()
    runtime.dispatch(inst.id, runtime.OPS[to], **kw)
    db.refresh(inst)
    return inst


def deploy(db: Session, p: Principal, lab_id: int) -> LabInstance:
    lab = get_lab(db, p, lab_id, operate=True, lock=True)
    if current_instance(db, lab):
        raise Conflict("This lab is already deployed", code="invalid_state")
    safety.check_can_start(db, lab, lab.owner_id)
    inst = LabInstance(lab_id=lab.id, runtime_id=uuid.uuid4().hex[:10], status="provisioning", requested_by=p.id)
    db.add(inst)
    db.flush()
    _event(db, lab, inst, "lab.deploy.requested", f"Deploy requested by {p.username}")
    record(db, "lab.deploy", actor=p, resource_type="lab", resource_id=lab.id, details={"instance": inst.id, "runtime_id": inst.runtime_id})
    db.commit()
    runtime.dispatch(inst.id, "provision")
    db.refresh(inst)
    return inst


def act(db: Session, p: Principal, lab_id: int, action: str) -> LabInstance:
    lab = get_lab(db, p, lab_id, operate=True, lock=True)
    inst = current_instance(db, lab, lock=True)
    if action == "stop":
        return _transition(db, p, lab, inst, ("running",), "stopping", "stop")
    if action == "start":
        if inst and inst.status == "stopped":
            safety.check_can_start(db, lab, lab.owner_id, exclude_instance=inst.id)
        return _transition(db, p, lab, inst, ("stopped",), "starting", "start")
    if action == "reset":
        if safety.kill_switch_engaged(db):
            raise safety.SafetyViolation("The lab kill switch is engaged", code="kill_switch")
        return _transition(db, p, lab, inst, ("running", "stopped"), "resetting", "reset")
    if action == "destroy":
        return _transition(db, p, lab, inst, ("running", "stopped", "failed"), "destroying", "destroy")
    raise NotFound("Unknown action")


def take_snapshot(db: Session, p: Principal, lab_id: int, name: str) -> Snapshot:
    lab = get_lab(db, p, lab_id, operate=True, lock=True)
    inst = current_instance(db, lab, lock=True)
    if inst is None or inst.status not in ("running", "stopped"):
        raise Conflict("Snapshots need a running or stopped lab", code="invalid_state")
    snap = Snapshot(lab_id=lab.id, instance_id=inst.id, name=name, status="creating", created_by=p.id)
    db.add(snap)
    db.flush()
    _transition(db, p, lab, inst, ("running", "stopped"), "snapshotting", "snapshot", snapshot_id=snap.id, return_to=inst.status)
    db.refresh(snap)
    return snap


def restore_snapshot(db: Session, p: Principal, lab_id: int, snapshot_id: int) -> LabInstance:
    lab = get_lab(db, p, lab_id, operate=True, lock=True)
    snap = db.get(Snapshot, snapshot_id)
    if not snap or snap.lab_id != lab.id or snap.status == "deleted":
        raise NotFound("Snapshot not found")
    if snap.status != "ready":
        raise Conflict("Snapshot is not ready", code="invalid_state")
    if safety.kill_switch_engaged(db):
        raise safety.SafetyViolation("The lab kill switch is engaged", code="kill_switch")
    inst = current_instance(db, lab, lock=True)
    return _transition(db, p, lab, inst, ("running", "stopped"), "restoring", "restore", snapshot_id=snap.id)


def delete_snapshot(db: Session, p: Principal, lab_id: int, snapshot_id: int) -> None:
    lab = get_lab(db, p, lab_id, operate=True)
    snap = db.get(Snapshot, snapshot_id)
    if not snap or snap.lab_id != lab.id or snap.status == "deleted":
        raise NotFound("Snapshot not found")
    if snap.status == "creating":
        raise Conflict("Snapshot is still being created", code="invalid_state")
    snap.status = "deleted"
    record(db, "lab.snapshot.delete", actor=p, resource_type="lab", resource_id=lab.id, details={"snapshot": snap.id})
    db.commit()
    if runtime.os.environ.get("CR_LAB_EXECUTION", "celery") == "inline":
        runtime.delete_snapshot_images(snap.id)
    else:
        from app.core.celery_app import celery_app
        celery_app.send_task("app.cyber_range.tasks.delete_snapshot", args=[snap.id], queue="lab")


def delete_lab(db: Session, p: Principal, lab_id: int) -> None:
    lab = get_lab(db, p, lab_id, operate=True, lock=True)
    if current_instance(db, lab):
        raise Conflict("Destroy the running lab before deleting it", code="invalid_state")
    from app.core.database import utcnow
    lab.deleted_at = utcnow()
    record(db, "lab.delete", actor=p, resource_type="lab", resource_id=lab.id, details={"name": lab.name})


def set_kill_switch(db: Session, p: Principal, engaged: bool, reason: str) -> dict:
    update_setting(db, p, "lab.kill_switch", engaged)
    record(db, "lab.killswitch", actor=p, resource_type="setting", resource_id="lab.kill_switch", details={"engaged": engaged, "reason": reason})
    db.commit()
    stopped = 0
    if engaged:
        if runtime.os.environ.get("CR_LAB_EXECUTION", "celery") == "inline":
            stopped = runtime.enforce_kill_switch()
        else:
            from app.core.celery_app import celery_app
            celery_app.send_task("app.cyber_range.tasks.enforce_kill_switch", queue="lab")
    return {"engaged": engaged, "stopped_inline": stopped}


def live_stats(inst: LabInstance | None) -> dict | None:
    if inst is None or inst.status != "running":
        return None
    try:
        raw = get_redis().get(f"labstats:{inst.id}")
    except Exception:  # noqa: BLE001
        return None
    return json.loads(raw) if raw else None


def events(db: Session, lab: Lab, limit: int = 100) -> list[LabEvent]:
    return db.execute(select(LabEvent).where(LabEvent.lab_id == lab.id).order_by(LabEvent.id.desc()).limit(limit)).scalars().all()


def labs_using_network(db: Session, network_id: int) -> list[Lab]:
    return db.execute(select(Lab).where(Lab.network_id == network_id, Lab.deleted_at.is_(None))).scalars().all()


__all__ = ["or_"]


def counts_for_dashboard(db: Session) -> dict:
    from sqlalchemy import func

    from app.cyber_range.models import LabContainer
    running = select(LabInstance.id).where(LabInstance.status == "running")
    return {
        "labs": db.execute(select(func.count()).select_from(Lab).where(Lab.deleted_at.is_(None))).scalar_one(),
        "labs_running": db.execute(select(func.count()).select_from(running.subquery())).scalar_one(),
        "lab_containers": db.execute(select(func.count()).select_from(LabContainer).where(LabContainer.instance_id.in_(running), LabContainer.status == "running")).scalar_one(),
    }

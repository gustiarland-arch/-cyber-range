"""Lab lifecycle executed by the lab worker (Celery queue `lab`). Only this module touches the runtime driver."""
import json
import os
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, utcnow
from app.core.logging import log
from app.cyber_range.engine.driver import ContainerSpec, DriverError, LabDriver, get_driver
from app.cyber_range.engine.planner import _slug
from app.cyber_range import office
from app.cyber_range.engine.vm import VmError, VmSpec, get_vm_provider, mac_for
from app.cyber_range.models import Lab, LabContainer, LabEvent, LabInstance, LabRuntimeNetwork, Snapshot, VirtualMachine

# transitional status -> operation
OPS = {"provisioning": "provision", "stopping": "stop", "starting": "start", "resetting": "reset",
       "destroying": "destroy", "snapshotting": "snapshot", "restoring": "restore"}


def event(db: Session, lab_id: int, instance_id: int | None, kind: str, message: str, level: str = "info", data: dict | None = None) -> None:
    db.add(LabEvent(lab_id=lab_id, instance_id=instance_id, kind=kind, message=message[:512], level=level, data=data))


def labels(inst: LabInstance, lab: Lab, extra: dict | None = None) -> dict:
    return {"cyber-range.managed": "true", "cyber-range.instance": inst.runtime_id, "cyber-range.lab": str(lab.id), **(extra or {})}


def net_name(inst: LabInstance, subnet_key: str) -> str:
    return f"cr-{inst.runtime_id}-{_slug(subnet_key, 24)}"


def _create_containers(db: Session, d: LabDriver, inst: LabInstance, lab: Lab, overrides: dict | None = None) -> None:
    by_net = {n.subnet_key: n.name for n in inst.networks}
    subnet_of = {v: k for k, v in by_net.items()}
    for c in lab.plan["containers"]:
        image = (overrides or {}).get(c["node_key"]) or c["image"]
        spec = ContainerSpec(
            name=f"cr-{inst.runtime_id}-{c['slug']}", image=image, hostname=c["hostname"],
            labels=labels(inst, lab, {"cyber-range.node": c["node_key"]}), cpus=c["cpus"], memory_mb=c["memory_mb"],
            command=c["command"], tmpfs=c["tmpfs"], cap_add=c["cap_add"], ip_forward=c["ip_forward"],
            attachments=[{"network": by_net[a["subnet_key"]], "ip": a["ip"]} for a in c["attachments"] if a["subnet_key"] in by_net],
            env=office.env_for(inst, lab, c, c["image"]),   # snapshots keep the plan's role and environment
        )
        row = LabContainer(instance_id=inst.id, node_key=c["node_key"], name=spec.name, image_ref=image, status="created",
                           cpus=c["cpus"], memory_mb=c["memory_mb"])
        inst.containers.append(row)
        row.docker_id = d.create_container(spec)
        db.flush()
        d.start(row.docker_id)
        row.status = d.state(row.docker_id)
        row.addresses = {subnet_of.get(k, k): v for k, v in d.addresses(row.docker_id).items()}
        if c.get("fallback") == "vm-as-container":
            event(db, lab.id, inst.id, "vm.fallback", f"{c['label']}: no VM provider on the lab host, running as a container (compatible mode)", "warn")


def _after_containers(db: Session, inst: LabInstance, lab: Lab, d: LabDriver | None = None) -> None:
    office.ensure_agents(db, inst, lab)


def _vm_provider():
    vp = get_vm_provider()
    if vp is None:
        raise DriverError("this lab has VM nodes but no VM provider is configured on the lab worker (CR_VM_PROVIDER)")
    return vp


def _create_vms(db: Session, d: LabDriver, inst: LabInstance, lab: Lab, revert_to: dict | None = None) -> None:
    plan_vms = lab.plan.get("vms") or []
    if not plan_vms:
        return
    vp = _vm_provider()
    nets = {n.subnet_key: n for n in inst.networks}
    for v in plan_vms:
        name = f"cr-{inst.runtime_id}-{v['slug']}"
        nics = []
        for i, n in enumerate(v["nics"]):
            if n["subnet_key"] in nets:
                nics.append({"subnet_key": n["subnet_key"], "ip": n["ip"], "mac": mac_for(name, i),
                             "bridge": d.bridge_interface(nets[n["subnet_key"]].docker_id)})
        row = VirtualMachine(instance_id=inst.id, node_key=v["node_key"], provider=vp.name, status="pending", name=name, template=v["template"],
                             vcpus=v["vcpus"], memory_mb=v["memory_mb"], nics=[{k: x[k] for k in ("subnet_key", "ip", "mac")} for x in nics])
        inst.vms.append(row)
        db.flush()
        try:
            vp.create(VmSpec(name=name, template=v["template"], vcpus=v["vcpus"], memory_mb=v["memory_mb"], instance=inst.runtime_id, nics=nics))
            vp.start(name)
            row.status, row.detail = vp.state(name), None
        except VmError as e:
            raise DriverError(f"VM {v['label']}: {e}") from None
        event(db, lab.id, inst.id, "vm.created", f"{v['label']}: VM {name} ({vp.name}, template {v['template']}) {row.status}")


def _remove_vms(db: Session, inst: LabInstance, sweep: bool = False) -> None:
    vp = get_vm_provider()
    if vp is None:
        for row in list(inst.vms):
            inst.vms.remove(row)
        db.flush()
        return
    names = {row.name for row in inst.vms if row.name}
    if sweep:
        try:
            names |= set(vp.list_managed(inst.runtime_id))
        except (VmError, NotImplementedError):
            log.exception("vm_sweep_failed", instance=inst.id)
    for n in sorted(names):
        try:
            vp.destroy(n)
        except VmError as e:
            raise DriverError(f"VM {n}: {e}") from None
    for row in list(inst.vms):
        inst.vms.remove(row)
    db.flush()


def _vm_each(inst: LabInstance, fn) -> None:
    if not inst.vms:
        return
    vp = _vm_provider()
    for row in inst.vms:
        try:
            fn(vp, row)
            row.status = vp.state(row.name)
        except VmError as e:
            raise DriverError(f"VM {row.node_key}: {e}") from None


def _remove_containers(db: Session, d: LabDriver, inst: LabInstance) -> None:
    for row in list(inst.containers):
        if row.docker_id:
            d.remove_container(row.docker_id)
        inst.containers.remove(row)
    db.flush()


def _teardown(db: Session, d: LabDriver, inst: LabInstance) -> None:
    _remove_vms(db, inst, sweep=True)
    _remove_containers(db, d, inst)
    # Also sweep anything labelled for this instance (crash leftovers).
    left = d.list_managed(inst.runtime_id)
    for cid in left["containers"]:
        d.remove_container(cid)
    for row in list(inst.networks):
        if row.docker_id:
            d.remove_network(row.docker_id)
        inst.networks.remove(row)
    for nid in left["networks"]:
        d.remove_network(nid)
    db.flush()


def provision(db: Session, d: LabDriver, inst: LabInstance, lab: Lab, **_):
    for img in sorted({c["image"] for c in lab.plan["containers"]}):
        d.ensure_image(img)
    for n in lab.plan["networks"]:
        name = net_name(inst, n["subnet_key"])
        row = LabRuntimeNetwork(subnet_key=n["subnet_key"], name=name, cidr=n["cidr"], internal=True)
        inst.networks.append(row)
        row.docker_id = d.create_network(name, n["cidr"], n["bridge_ip"], labels(inst, lab, {"cyber-range.subnet": n["subnet_key"]}))
        db.flush()
    _create_containers(db, d, inst, lab)
    _after_containers(db, inst, lab, d)
    _create_vms(db, d, inst, lab)
    for s in lab.plan["skipped"]:
        event(db, lab.id, inst.id, "node.skipped", f"{s['label']}: {s['reason']}")
    inst.started_at = utcnow()
    vms = f", {len(inst.vms)} VMs" if inst.vms else ""
    return "running", f"Lab deployed: {len(inst.containers)} containers{vms} on {len(inst.networks)} isolated networks"


def _stop_sensors(db, d, inst, reason):
    from app.cyber_range.sensors import stop_for_instance
    stop_for_instance(db, d, inst, reason)


def stop(db, d, inst, lab, **_):
    _stop_sensors(db, d, inst, "lab stopped")
    for row in inst.containers:
        d.stop(row.docker_id)
        row.status = d.state(row.docker_id)
    _vm_each(inst, lambda vp, row: vp.stop(row.name))
    inst.stopped_at = utcnow()
    return "stopped", "Lab stopped"


def start(db, d, inst, lab, **_):
    for row in inst.containers:
        if d.state(row.docker_id) == "missing":
            raise DriverError(f"container for {row.node_key} no longer exists; reset the lab")
        d.start(row.docker_id)
        row.status = d.state(row.docker_id)
    _vm_each(inst, lambda vp, row: vp.start(row.name))
    _after_containers(db, inst, lab, d)
    inst.started_at = utcnow()
    return "running", "Lab started"


def reset(db, d, inst, lab, **_):
    _remove_vms(db, inst)
    _remove_containers(db, d, inst)
    _create_containers(db, d, inst, lab)
    _after_containers(db, inst, lab, d)
    _create_vms(db, d, inst, lab)
    inst.started_at = utcnow()
    return "running", "Lab reset to its clean baseline"


def snapshot(db, d, inst, lab, snapshot_id: int, return_to: str = "running", **_):
    snap = db.get(Snapshot, snapshot_id)
    images = {}
    try:
        for row in inst.containers:
            images[row.node_key] = d.commit(row.docker_id, f"cyber-range/snap-{snap.id}", _slug(row.node_key, 60))
        if inst.vms:
            vp = _vm_provider()
            for row in inst.vms:
                try:
                    vp.snapshot(row.name, f"cr-snap-{snap.id}")
                except VmError as e:
                    raise DriverError(f"VM {row.node_key}: {e}") from None
                images[f"vm:{row.node_key}"] = f"cr-snap-{snap.id}"
    except DriverError as e:
        _drop_snapshot_artifacts(d, inst, images)
        snap.status, snap.error = "failed", str(e)
        raise
    snap.images, snap.status = images, "ready"
    return return_to, f"Snapshot '{snap.name}' created ({len(images)} images)"


def restore(db, d, inst, lab, snapshot_id: int, **_):
    snap = db.get(Snapshot, snapshot_id)
    if snap.status != "ready":
        raise DriverError("snapshot is not ready")
    _remove_containers(db, d, inst)
    _create_containers(db, d, inst, lab, overrides={k: v for k, v in snap.images.items() if not k.startswith("vm:")})
    _after_containers(db, inst, lab, d)
    vm_snaps = {k[3:]: v for k, v in snap.images.items() if k.startswith("vm:")}
    if inst.vms:
        def _rev(vp, row):
            if row.node_key not in vm_snaps:
                raise VmError("this snapshot has no state for this VM")
            vp.revert(row.name, vm_snaps[row.node_key])
            vp.start(row.name)
        _vm_each(inst, _rev)
    inst.started_at = utcnow()
    return "running", f"Restored snapshot '{snap.name}'"


def destroy(db, d, inst, lab, **_):
    _stop_sensors(db, d, inst, "lab destroyed")
    _teardown(db, d, inst)
    inst.destroyed_at = utcnow()
    return "destroyed", "Lab destroyed; containers and networks removed"


HANDLERS = {"provision": provision, "stop": stop, "start": start, "reset": reset, "destroy": destroy, "snapshot": snapshot, "restore": restore}


def run_operation(instance_id: int, op: str, **kw) -> str:
    """Execute one lifecycle operation. Idempotent: does nothing unless the instance is in the matching transitional state."""
    d = get_driver()
    with SessionLocal() as db:
        inst = db.execute(select(LabInstance).where(LabInstance.id == instance_id).with_for_update()).scalar_one_or_none()
        if inst is None or OPS.get(inst.status) != op:
            log.info("lab_op_skipped", instance=instance_id, op=op, status=getattr(inst, "status", None))
            return "skipped"
        lab = db.get(Lab, inst.lab_id)
        try:
            final, msg = HANDLERS[op](db, d, inst, lab, **kw)
            inst.status, inst.error = final, None
            event(db, lab.id, inst.id, f"lab.{op}", msg)
        except Exception as e:  # noqa: BLE001 - every failure must land in the DB, not just the log
            db.rollback()
            inst = db.execute(select(LabInstance).where(LabInstance.id == instance_id).with_for_update()).scalar_one()
            lab = db.get(Lab, inst.lab_id)
            msg = str(e) if isinstance(e, DriverError) else f"{type(e).__name__}: {e}"
            log.exception("lab_op_failed", instance=instance_id, op=op)
            if op == "provision":
                try:
                    _teardown(db, d, inst)  # never leave half-built labs behind
                except Exception:  # noqa: BLE001
                    log.exception("lab_cleanup_failed", instance=instance_id)
            if op == "snapshot":
                snap = db.get(Snapshot, kw.get("snapshot_id"))
                if snap and snap.status == "creating":
                    snap.status, snap.error = "failed", msg
                inst.status, inst.error = kw.get("return_to", "running"), None
                event(db, lab.id, inst.id, "lab.snapshot.failed", f"Snapshot failed: {msg}", "error")
            else:
                inst.status, inst.error = "failed", msg[:4000]
                event(db, lab.id, inst.id, f"lab.{op}.failed", f"{op} failed: {msg}", "error")
        db.commit()
        return inst.status


def _drop_snapshot_artifacts(d: LabDriver, inst: LabInstance | None, images: dict) -> None:
    vms = {row.node_key: row.name for row in (inst.vms if inst else [])}
    for k, v in images.items():
        if k.startswith("vm:"):
            vp = get_vm_provider()
            if vp and k[3:] in vms:
                try:
                    vp.delete_snapshot(vms[k[3:]], v)
                except VmError:
                    log.exception("vm_snapshot_delete_failed", vm=vms[k[3:]])
        else:
            d.remove_image(v)


def delete_snapshot_images(snapshot_id: int) -> None:
    d = get_driver()
    with SessionLocal() as db:
        snap = db.get(Snapshot, snapshot_id)
        inst = db.get(LabInstance, snap.instance_id) if snap.instance_id else None
        _drop_snapshot_artifacts(d, inst, snap.images or {})
        snap.images = {}
        db.commit()


def collect_stats() -> int:
    """Sample container resource usage for running labs into Redis (cache only, 60 s TTL)."""
    from app.core.redis_client import get_redis
    d = get_driver()
    n = 0
    with SessionLocal() as db:
        for inst in db.execute(select(LabInstance).where(LabInstance.status == "running")).scalars():
            def sample(row):
                try:
                    return row.node_key, d.stats(row.docker_id)
                except Exception:  # noqa: BLE001
                    return row.node_key, None
            # Docker's one-shot stats call blocks ~1 s per container; sample a lab's containers in parallel.
            with ThreadPoolExecutor(max_workers=8) as pool:
                out = dict(pool.map(sample, list(inst.containers)))
            get_redis().set(f"labstats:{inst.id}", json.dumps({"at": utcnow().isoformat(), "containers": out}), ex=60)
            n += 1
    return n


def reconcile() -> int:
    """Detect containers that died outside the platform and record it."""
    d = get_driver()
    changed = 0
    with SessionLocal() as db:
        for inst in db.execute(select(LabInstance).where(LabInstance.status == "running").with_for_update(skip_locked=True)).scalars():
            for row in inst.containers:
                st = d.state(row.docker_id)
                if st != row.status:
                    # every observed change is recorded with the node and new state, so the 3D replay can show status history
                    data = {"node": row.node_key, "state": st, "previous": row.status}
                    if row.status == "running" and st != "running":
                        event(db, inst.lab_id, inst.id, "container.exited", f"{row.node_key} is {st} (outside platform control)", "warn", data)
                    else:
                        event(db, inst.lab_id, inst.id, "container.state", f"{row.node_key} is {st}", "info", data)
                    row.status = st
                    changed += 1
            vp = get_vm_provider() if inst.vms else None
            for row in (inst.vms if vp else []):
                try:
                    st = vp.state(row.name)
                except VmError:
                    continue
                if st != row.status:
                    data = {"node": row.node_key, "state": st, "previous": row.status}
                    if row.status == "running" and st != "running":
                        event(db, inst.lab_id, inst.id, "vm.exited", f"VM {row.node_key} is {st} (outside platform control)", "warn", data)
                    else:
                        event(db, inst.lab_id, inst.id, "vm.state", f"VM {row.node_key} is {st}", "info", data)
                    row.status = st
                    changed += 1
        db.commit()
    return changed


def enforce_kill_switch() -> int:
    from app.cyber_range.engine.safety import kill_switch_engaged
    with SessionLocal() as db:
        if not kill_switch_engaged(db):
            return 0
        ids = []
        for inst in db.execute(select(LabInstance).where(LabInstance.status.in_(("running", "starting", "provisioning", "resetting", "restoring"))).with_for_update(skip_locked=True)).scalars():
            if inst.status == "running":
                inst.status = "stopping"
                event(db, inst.lab_id, inst.id, "killswitch", "Kill switch engaged: stopping lab", "warn")
                ids.append(inst.id)
        db.commit()
    for i in ids:
        run_operation(i, "stop")
    return len(ids)


def dispatch(instance_id: int, op: str, **kw) -> None:
    """Hand an operation to the lab worker, or run it inline (tests / single-process dev)."""
    if os.environ.get("CR_LAB_EXECUTION", "celery") == "inline":
        run_operation(instance_id, op, **kw)
        return
    from app.core.celery_app import celery_app
    celery_app.send_task("app.cyber_range.tasks.lab_operation", args=[instance_id, op], kwargs=kw, queue="lab")

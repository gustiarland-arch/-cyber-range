from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import get_db
from app.core.errors import NotFound
from app.cyber_range import sensors, service
from app.cyber_range.engine.safety import kill_switch_engaged
from app.cyber_range.engine.vm import vm_capability
from app.cyber_range.models import Lab, LabImage, Snapshot, VirtualMachine
from app.iam.deps import Principal, require
from app.iam.models import User

router = APIRouter(prefix="/labs", tags=["labs"])
VIEW = Depends(require("lab.view"))
OPERATE = Depends(require("lab.operate"))


class LabCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    network_id: int
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=4000)


class SnapshotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[\w .:-]+$")


class KillSwitch(BaseModel):
    engaged: bool
    reason: str = Field(min_length=3, max_length=500)


class ImageIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reference: str = Field(pattern=r"^[a-z0-9]+([._/-][a-z0-9]+)*(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$", max_length=255)
    title: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=2000)
    node_types: list[str] = Field(min_length=1)
    keepalive: bool = True
    default_cpus: float = Field(default=0.25, ge=0.05, le=4)
    default_memory_mb: int = Field(default=64, ge=16, le=8192)


def _inst_out(inst, with_stats=False):
    if inst is None:
        return None
    out = {"id": inst.id, "runtime_id": inst.runtime_id, "status": inst.status, "error": inst.error, "created_at": inst.created_at,
           "started_at": inst.started_at, "stopped_at": inst.stopped_at,
           "networks": [{"subnet_key": n.subnet_key, "name": n.name, "cidr": n.cidr, "internal": n.internal} for n in inst.networks],
           "containers": [{"node_key": c.node_key, "name": c.name, "image": c.image_ref, "status": c.status, "addresses": c.addresses or {},
                           "cpus": c.cpus, "memory_mb": c.memory_mb, "docker_id": (c.docker_id or "")[:12]} for c in inst.containers]}
    if with_stats:
        out["stats"] = service.live_stats(inst)
    return out


def _lab_out(db, lab: Lab, owners=None, detail=False):
    inst = service.current_instance(db, lab)
    out = {"id": lab.id, "name": lab.name, "description": lab.description, "owner_id": lab.owner_id,
           "owner": (owners or {}).get(lab.owner_id) or db.get(User, lab.owner_id).username,
           "network_id": lab.network_id, "network_version": lab.network_version, "totals": lab.plan["totals"],
           "status": inst.status if inst else "not_deployed", "created_at": lab.created_at, "updated_at": lab.updated_at,
           "instance": _inst_out(inst, with_stats=detail)}
    if detail:
        out["plan"] = lab.plan
        out["topology"] = lab.topology
        snaps = db.execute(select(Snapshot).where(Snapshot.lab_id == lab.id, Snapshot.status != "deleted").order_by(Snapshot.id.desc())).scalars()
        out["snapshots"] = [{"id": s.id, "name": s.name, "status": s.status, "error": s.error, "created_at": s.created_at,
                             "nodes": len(s.images or {})} for s in snaps]
        out["events"] = [{"id": e.id, "at": e.occurred_at, "level": e.level, "kind": e.kind, "message": e.message} for e in service.events(db, lab)]
    return out


@router.get("/capabilities")
def capabilities(db: Session = Depends(get_db), _p: Principal = VIEW):
    from app.api.health import host_capabilities
    return {"vm": vm_capability(), "host": host_capabilities(), "kill_switch": kill_switch_engaged(db),
            "runtime": "docker", "note": "Capabilities are detected by the API process; the lab worker re-checks on its own host."}


@router.get("")
def list_labs(db: Session = Depends(get_db), p: Principal = VIEW):
    labs = db.execute(service.visible_query(p).order_by(Lab.updated_at.desc()).limit(500)).scalars().all()
    owners = dict(db.execute(select(User.id, User.username).where(User.id.in_({lab.owner_id for lab in labs} or {0}))).all())
    return {"kill_switch": kill_switch_engaged(db), "labs": [_lab_out(db, lab, owners) for lab in labs]}


@router.post("", status_code=201)
def create_lab(body: LabCreate, db: Session = Depends(get_db), p: Principal = OPERATE):
    lab = service.create_lab(db, p, network_id=body.network_id, name=body.name, description=body.description)
    db.commit()
    return _lab_out(db, lab, detail=True)


@router.get("/vms")
def list_vms(db: Session = Depends(get_db), p: Principal = VIEW, probe: bool = False):
    """VM-type nodes across visible labs and how they are realised: real VMs (libvirt/Proxmox) or compatible-mode containers."""
    out = []
    for lab in db.execute(service.visible_query(p)).scalars():
        inst = service.current_instance(db, lab)
        vm_rows = {v.node_key: v for v in (inst.vms if inst else [])}
        for v in lab.plan.get("vms") or []:
            row = vm_rows.get(v["node_key"])
            out.append({"lab_id": lab.id, "lab": lab.name, "node_key": v["node_key"], "label": v["label"], "mode": "vm",
                        "provider": row.provider if row else None, "name": row.name if row else None, "image": v["template"],
                        "cpus": v["vcpus"], "memory_mb": v["memory_mb"], "status": row.status if row else "not deployed",
                        "nics": row.nics if row else v["nics"]})
        for c in lab.plan["containers"]:
            if c["type"] == "vm":
                cont = next((x for x in (inst.containers if inst else []) if x.node_key == c["node_key"]), None)
                out.append({"lab_id": lab.id, "lab": lab.name, "node_key": c["node_key"], "label": c["label"],
                            "mode": "container (compatible mode)" if c.get("fallback") else "container", "image": c["image"],
                            "cpus": c["cpus"], "memory_mb": c["memory_mb"], "status": cont.status if cont else "not deployed"})
    return {"capability": vm_capability(probe=probe and p.has("lab.manage")), "vms": out}


@router.get("/images")
def list_images(db: Session = Depends(get_db), _p: Principal = VIEW):
    return [{"id": i.id, "reference": i.reference, "title": i.title, "description": i.description, "node_types": i.node_types,
             "default_cpus": i.default_cpus, "default_memory_mb": i.default_memory_mb, "is_enabled": i.is_enabled, "cap_add": i.cap_add or []}
            for i in db.execute(select(LabImage).order_by(LabImage.id)).scalars()]


@router.post("/images", status_code=201)
def add_image(body: ImageIn, db: Session = Depends(get_db), p: Principal = Depends(require("lab.manage"))):
    from app.core.errors import Conflict
    from app.network.models import NODE_TYPES
    bad = set(body.node_types) - set(NODE_TYPES) - set()
    if bad or {"internet", "switch"} & set(body.node_types):
        from app.core.errors import AppError
        raise AppError(f"Invalid node types: {sorted(bad | ({'internet', 'switch'} & set(body.node_types)))}", code="validation_error", status_code=422)
    if db.execute(select(LabImage.id).where(LabImage.reference == body.reference)).first():
        raise Conflict("Image already on the allowlist")
    img = LabImage(reference=body.reference, title=body.title, description=body.description, node_types=body.node_types,
                   command=service.DEFAULT_IMAGES[0]["command"] if body.keepalive else None, tmpfs=["/tmp"], cap_add=[],
                   default_cpus=body.default_cpus, default_memory_mb=body.default_memory_mb, is_enabled=True)
    db.add(img)
    db.flush()
    record(db, "lab.image.add", actor=p, resource_type="image", resource_id=img.id, details={"reference": body.reference})
    db.commit()
    return {"id": img.id}


@router.patch("/images/{image_id}")
def toggle_image(image_id: int, body: dict, db: Session = Depends(get_db), p: Principal = Depends(require("lab.manage"))):
    img = db.get(LabImage, image_id)
    if not img:
        raise NotFound("Image not found")
    enabled = body.get("is_enabled")
    if not isinstance(enabled, bool):
        from app.core.errors import AppError
        raise AppError("is_enabled must be a boolean", code="validation_error", status_code=422)
    img.is_enabled = enabled
    record(db, "lab.image.update", actor=p, resource_type="image", resource_id=img.id, details={"reference": img.reference, "is_enabled": enabled})
    db.commit()
    return {"id": img.id, "is_enabled": img.is_enabled}


@router.post("/kill-switch")
def kill_switch(body: KillSwitch, db: Session = Depends(get_db), p: Principal = Depends(require("lab.killswitch"))):
    return service.set_kill_switch(db, p, body.engaged, body.reason)


@router.get("/{lab_id}")
def get_lab(lab_id: int, db: Session = Depends(get_db), p: Principal = VIEW):
    return _lab_out(db, service.get_lab(db, p, lab_id), detail=True)


@router.get("/{lab_id}/live")
def live(lab_id: int, minutes: int = Query(60, ge=5, le=1440), db: Session = Depends(get_db), p: Principal = VIEW):
    """Live state for the 3D view: node status/IPs, sensor traffic, alerts and red team steps (see app/cyber_range/live.py)."""
    from app.cyber_range.live import live_view
    return live_view(db, p, lab_id, minutes)


@router.get("/{lab_id}/live/stream")
async def live_stream(lab_id: int, request: Request, db: Session = Depends(get_db), p: Principal = VIEW):
    """Server-sent events telling the 3D view when to refetch /live (no data in the stream itself)."""
    from fastapi.responses import StreamingResponse

    from app.cyber_range.live import change_stream
    service.get_lab(db, p, lab_id)  # same visibility check as /live
    db.close()
    return StreamingResponse(change_stream(lab_id, request.is_disconnected), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/{lab_id}/deploy")
def deploy(lab_id: int, db: Session = Depends(get_db), p: Principal = OPERATE):
    service.deploy(db, p, lab_id)
    return _lab_out(db, service.get_lab(db, p, lab_id), detail=True)


@router.post("/{lab_id}/snapshots", status_code=201)
def snapshot(lab_id: int, body: SnapshotCreate, db: Session = Depends(get_db), p: Principal = OPERATE):
    s = service.take_snapshot(db, p, lab_id, body.name)
    return {"id": s.id, "status": s.status}


@router.post("/{lab_id}/snapshots/{snapshot_id}/restore")
def restore(lab_id: int, snapshot_id: int, db: Session = Depends(get_db), p: Principal = OPERATE):
    service.restore_snapshot(db, p, lab_id, snapshot_id)
    return _lab_out(db, service.get_lab(db, p, lab_id), detail=True)


@router.delete("/{lab_id}/snapshots/{snapshot_id}", status_code=204)
def delete_snapshot(lab_id: int, snapshot_id: int, db: Session = Depends(get_db), p: Principal = OPERATE):
    service.delete_snapshot(db, p, lab_id, snapshot_id)


class SensorAttach(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kinds: list[str] = Field(min_length=1, max_length=2)
    subnets: list[str] | None = Field(default=None, max_length=32)


@router.get("/{lab_id}/sensors")
def list_sensors(lab_id: int, db: Session = Depends(get_db), p: Principal = VIEW):
    lab = service.get_lab(db, p, lab_id)
    return {"sensors": sensors.list_for_lab(db, lab), "images": sensors.images()}


@router.post("/{lab_id}/sensors", status_code=202)
def attach_sensors(lab_id: int, body: SensorAttach, db: Session = Depends(get_db), p: Principal = OPERATE):
    """Start passive Zeek/Suricata capture on the lab's isolated networks; their logs feed the SOC automatically."""
    lab = service.get_lab(db, p, lab_id, operate=True)
    rows = sensors.attach(db, p, lab, body.kinds, body.subnets)
    db.commit()
    sensors.dispatch("start", [s.id for s in rows])
    db.expire_all()
    return {"sensors": sensors.list_for_lab(db, lab)}


@router.delete("/{lab_id}/sensors")
def detach_sensors(lab_id: int, sensor_id: int | None = None, db: Session = Depends(get_db), p: Principal = OPERATE):
    lab = service.get_lab(db, p, lab_id, operate=True)
    ids = sensors.detach(db, p, lab, sensor_id)
    db.commit()
    sensors.dispatch("stop", ids)
    db.expire_all()
    return {"sensors": sensors.list_for_lab(db, lab)}


@router.delete("/{lab_id}", status_code=204)
def delete_lab(lab_id: int, db: Session = Depends(get_db), p: Principal = OPERATE):
    service.delete_lab(db, p, lab_id)
    db.commit()


@router.post("/{lab_id}/{action}")
def act(lab_id: int, action: str, db: Session = Depends(get_db), p: Principal = OPERATE):
    if action not in ("start", "stop", "reset", "destroy"):
        raise NotFound("Unknown action")
    service.act(db, p, lab_id, action)
    return _lab_out(db, service.get_lab(db, p, lab_id), detail=True)


__all__ = ["datetime", "VirtualMachine"]

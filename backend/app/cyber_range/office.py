"""Office lab images: a realistic Active Directory office inside a lab.

One locally built image (lab-images/office, tagged three times) runs as a domain controller, an intranet portal, or an
employee workstation, chosen by the command in its allowlist entry (`/opt/cr/start <role>`). The platform gives those
containers, and only those, a few environment values:
  CR_LAB_SEED  per-instance secret derived from the platform secret; the DEMO employee passwords are derived from it
               inside the lab, so they are never stored in MySQL, never shown, and differ in every lab instance
  CR_DOMAIN    lab DNS domain (lab.local)
  CR_PEERS     role=ip of the lab's domain controller and portal, so workstations know where to work
  CR_NODE      the node's hostname
Each office container also runs a host agent; the lab worker collects its JSON events into a per-node log source
(LabSensor kind "agent", no extra container) so the SIEM sees process, login, file, web and domain authentication events.
"""
import hashlib
import hmac

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.blueteam.models import LogSource
from app.core.config import get_settings
from app.cyber_range.models import Lab, LabEvent, LabInstance, LabSensor

PREFIX = "cyber-range/lab-"
AGENT = "agent"
AGENT_LOG = "/var/log/cr/events.jsonl"
DOMAIN = "lab.local"
ROLES = ("dc", "portal", "ws")


def is_office(image: str | None) -> bool:
    return bool(image) and image.startswith(PREFIX)


def role_of(command) -> str | None:
    if isinstance(command, list) and len(command) == 2 and command[0] == "/opt/cr/start" and command[1] in ROLES:
        return command[1]
    return None


def lab_seed(runtime_id: str) -> str:
    key = get_settings().jwt_secret.get_secret_value().encode()
    return hmac.new(key, f"cyber-range-lab-seed:{runtime_id}".encode(), hashlib.sha256).hexdigest()


def peers(plan_containers: list[dict]) -> str:
    out = []
    for c in plan_containers:
        role = role_of(c.get("command")) if is_office(c.get("image")) else None
        ip = next((a["ip"] for a in c.get("attachments", []) if a.get("ip")), None)
        if role in ("dc", "portal") and ip:
            out.append(f"{role}={ip}")
    return ",".join(out)


def env_for(inst: LabInstance, lab: Lab, c: dict, image: str) -> dict:
    if not is_office(image):
        return {}
    return {"CR_LAB_SEED": lab_seed(inst.runtime_id), "CR_DOMAIN": DOMAIN, "CR_PEERS": peers(lab.plan["containers"]),
            "CR_NODE": c["hostname"]}


def ensure_agents(db: Session, inst: LabInstance, lab: Lab) -> int:
    """(Re)attach the host-agent log collection to every office container of a running instance."""
    n = 0
    labels = {c["node_key"]: c["label"] for c in lab.plan["containers"]}
    planned = {c["node_key"]: c["image"] for c in lab.plan["containers"]}
    for row in inst.containers:
        if not is_office(planned.get(row.node_key)) or not row.docker_id:
            continue
        name = f"Lab #{lab.id} {lab.name[:60]} · host · {row.node_key}"[:128]
        src = db.execute(select(LogSource).where(LogSource.name == name)).scalar_one_or_none()
        if not src:
            src = LogSource(name=name, kind="json", lab_id=lab.id, is_demo=False,
                            description=f"Host agent of lab node '{labels.get(row.node_key, row.node_key)}': processes, logins, file changes, "
                                        "web access and domain authentication. Collected by the lab worker; no ingest key.")
            db.add(src)
            db.flush()
        s = db.execute(select(LabSensor).where(LabSensor.instance_id == inst.id, LabSensor.kind == AGENT,
                                               LabSensor.subnet_key == row.node_key)).scalar_one_or_none()
        if s is None:
            s = LabSensor(lab_id=lab.id, instance_id=inst.id, kind=AGENT, subnet_key=row.node_key, interface=AGENT,
                          image_ref=row.image_ref, log_source_id=src.id, offsets={}, created_by=lab.owner_id)
            db.add(s)
        if s.docker_id != row.docker_id:
            s.offsets = {}          # a new container starts a new log file
        s.docker_id, s.status, s.error, s.stopped_at = row.docker_id, "running", None, None
        n += 1
    if n:
        db.add(LabEvent(lab_id=lab.id, instance_id=inst.id, kind="sensor.started", message=f"Host agents collecting from {n} office node(s)"))
    db.flush()
    return n

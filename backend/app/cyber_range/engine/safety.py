"""Safety controller: every lab operation passes these checks server-side before anything runs."""
import ipaddress

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.cyber_range.models import INSTANCE_ACTIVE, Lab, LabImage, LabInstance, LabRuntimeNetwork
from app.governance.service import get_value


class SafetyViolation(AppError):
    status_code, code = 409, "safety_violation"


def kill_switch_engaged(db: Session) -> bool:
    return bool(get_value(db, "lab.kill_switch"))


def check_can_start(db: Session, lab: Lab, owner_id: int, *, exclude_instance: int | None = None) -> None:
    if kill_switch_engaged(db):
        raise SafetyViolation("The lab kill switch is engaged; no lab may start", code="kill_switch")
    active = LabInstance.status.in_(INSTANCE_ACTIVE)
    q_user = select(func.count()).select_from(LabInstance).join(Lab).where(active, Lab.owner_id == owner_id)
    q_all = select(func.count()).select_from(LabInstance).where(active)
    if exclude_instance:
        q_user = q_user.where(LabInstance.id != exclude_instance)
        q_all = q_all.where(LabInstance.id != exclude_instance)
    if db.execute(q_user).scalar_one() >= get_value(db, "lab.max_active_per_user"):
        raise SafetyViolation("Active lab quota per user reached; stop or destroy another lab first", code="quota_exceeded")
    if db.execute(q_all).scalar_one() >= get_value(db, "lab.max_active_total"):
        raise SafetyViolation("Host lab capacity reached", code="quota_exceeded")
    check_plan(db, lab.plan)
    check_cidr_conflicts(db, lab.plan, exclude_instance=exclude_instance)


def check_plan(db: Session, plan: dict) -> None:
    t = plan["totals"]
    limits = {"containers": get_value(db, "lab.max_containers"), "memory_mb": get_value(db, "lab.max_memory_mb"), "cpus": get_value(db, "lab.max_cpus")}
    over = {k: (t[k], v) for k, v in limits.items() if t[k] > v}
    if over:
        raise SafetyViolation("Lab exceeds resource quota: " + ", ".join(f"{k} {a} > {b}" for k, (a, b) in over.items()), code="quota_exceeded")
    allowed = {r for (r,) in db.execute(select(LabImage.reference).where(LabImage.is_enabled.is_(True)))}
    bad = sorted({c["image"] for c in plan["containers"]} - allowed)
    if bad:
        raise SafetyViolation(f"Images not on the allowlist: {', '.join(bad)}", code="image_not_allowed")


def check_cidr_conflicts(db: Session, plan: dict, *, exclude_instance: int | None = None) -> None:
    q = select(LabRuntimeNetwork.cidr, LabInstance.lab_id).join(LabInstance).where(LabInstance.status.in_(INSTANCE_ACTIVE))
    if exclude_instance:
        q = q.where(LabInstance.id != exclude_instance)
    running = [(ipaddress.ip_network(c), lab_id) for c, lab_id in db.execute(q)]
    for n in plan["networks"]:
        mine = ipaddress.ip_network(n["cidr"])
        for other, lab_id in running:
            if mine.overlaps(other):
                raise SafetyViolation(f"Subnet {mine} overlaps {other} used by running lab #{lab_id}. Stop that lab or change the CIDR.",
                                      code="cidr_conflict")

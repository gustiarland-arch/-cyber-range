"""Topology persistence: ORM <-> canonical document, key-based upsert saves, access control, import/export."""
import json

import yaml
from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import utcnow
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.iam.deps import Principal
from app.network.models import LabNetwork, NetworkLink, NetworkNode, NetworkZone, NodeInterface, NodePosition, Subnet
from app.network.schemas import Issue, NetworkSummary, TopologyDoc
from app.network.templates import TEMPLATES
from app.network.validation import status_of, structural_errors, validate

ADMIN = "network.topology.admin"
EDIT = "network.topology.edit"


# ------------------------------------------------------------------ access
def can_view(p: Principal, n: LabNetwork) -> bool:
    return n.owner_id == p.id or p.has(ADMIN) or (n.visibility == "shared" and (p.has("lab.view") or p.has(EDIT)))


def can_edit(p: Principal, n: LabNetwork) -> bool:
    return (n.owner_id == p.id and p.has(EDIT)) or p.has(ADMIN)


def get_for(db: Session, p: Principal, network_id: int, *, edit: bool = False, lock: bool = False) -> LabNetwork:
    q = select(LabNetwork).where(LabNetwork.id == network_id, LabNetwork.deleted_at.is_(None))
    if lock:
        q = q.with_for_update()
    n = db.execute(q).scalar_one_or_none()
    if n is None or not can_view(p, n):
        raise NotFound("Network not found")  # do not reveal existence of others' private networks
    if edit and not can_edit(p, n):
        record(db, "authz.denied", outcome="denied", actor=p, resource_type="network", resource_id=n.id, details={"reason": "not_editor"})
        db.commit()
        raise Forbidden("You can view this network but not edit it", details={"missing": [EDIT if n.owner_id == p.id else ADMIN]})
    return n


def visible_query(p: Principal):
    q = select(LabNetwork).where(LabNetwork.deleted_at.is_(None))
    if not p.has(ADMIN):
        conds = [LabNetwork.owner_id == p.id]
        if p.has("lab.view") or p.has(EDIT):
            conds.append(LabNetwork.visibility == "shared")
        q = q.where(or_(*conds))
    return q


def _name_free(db: Session, owner_id: int, name: str, exclude_id: int | None = None) -> None:
    q = select(LabNetwork.id).where(LabNetwork.owner_id == owner_id, LabNetwork.name == name, LabNetwork.deleted_at.is_(None))
    if exclude_id:
        q = q.where(LabNetwork.id != exclude_id)
    if db.execute(q).first():
        raise Conflict(f"You already have a network named '{name}'")


# ------------------------------------------------------------------ ORM -> doc
def to_doc(n: LabNetwork) -> TopologyDoc:
    zkey = {z.id: z.key for z in n.zones}
    skey = {s.id: s.key for s in n.subnets}
    nkey = {x.id: x.key for x in n.nodes}
    return TopologyDoc(
        name=n.name, description=n.description,
        zones=[{"key": z.key, "name": z.name, "kind": z.kind, "color": z.color, "position": {"x": z.x, "y": z.y},
                "size": {"w": z.width, "h": z.height}} for z in n.zones],
        subnets=[{"key": s.key, "name": s.name, "cidr": s.cidr, "gateway": s.gateway, "vlan": s.vlan_id,
                  "zone": zkey.get(s.zone_id)} for s in n.subnets],
        nodes=[{"key": x.key, "type": x.type, "label": x.label, "hostname": x.hostname, "os": x.os, "zone": zkey.get(x.zone_id),
                "group": x.group_name, "properties": x.properties or {},
                "position": {"x": x.position.x if x.position else 0, "y": x.position.y if x.position else 0},
                "elevation": x.position.z if x.position else None,
                "interfaces": [{"name": i.name, "subnet": skey.get(i.subnet_id), "ip": i.ip_address} for i in x.interfaces]}
               for x in n.nodes],
        links=[{"key": link.key, "source": nkey[link.source_node_id], "target": nkey[link.target_node_id], "label": link.label,
                "kind": link.kind, "bandwidth_mbps": link.bandwidth_mbps} for link in n.links],
    )


# ------------------------------------------------------------------ doc -> ORM (key-based upsert)
def _apply(db: Session, n: LabNetwork, doc: TopologyDoc) -> dict:
    stats = {"added": 0, "updated": 0, "removed": 0}

    def sync(existing: list, items: list, make, update, *, remove: bool = True) -> dict:
        by_key = {e.key: e for e in existing}
        keep = set()
        for it in items:
            obj = by_key.get(it.key)
            if obj is None:
                obj = make(it)
                existing.append(obj)
                stats["added"] += 1
            else:
                stats["updated"] += 1
            update(obj, it)
            keep.add(it.key)
        if remove:
            prune(existing, keep)
        return {e.key: e for e in existing}

    def prune(existing: list, keep: set) -> None:
        for e in [e for e in existing if e.key not in keep]:
            existing.remove(e)
            stats["removed"] += 1

    def upd_zone(z, d):
        z.name, z.kind, z.color, z.x, z.y, z.width, z.height = d.name, d.kind, d.color, d.position.x, d.position.y, d.size.w, d.size.h

    zones = sync(n.zones, doc.zones, lambda d: NetworkZone(key=d.key), upd_zone)
    db.flush()

    def upd_subnet(s, d):
        s.name, s.cidr, s.gateway, s.vlan_id = d.name, d.cidr, d.gateway, d.vlan
        s.zone_id = zones[d.zone].id if d.zone else None

    subnets = sync(n.subnets, doc.subnets, lambda d: Subnet(key=d.key), upd_subnet)
    db.flush()

    def upd_node(x, d):
        x.type, x.label, x.hostname, x.os, x.group_name, x.properties = d.type, d.label, d.hostname, d.os, d.group, d.properties
        x.zone_id = zones[d.zone].id if d.zone else None
        if x.position is None:
            x.position = NodePosition()
        x.position.x, x.position.y, x.position.z = d.position.x, d.position.y, d.elevation
        have = {i.name: i for i in x.interfaces}
        want = {i.name for i in d.interfaces}
        for i in [i for i in x.interfaces if i.name not in want]:
            x.interfaces.remove(i)
        for di in d.interfaces:
            itf = have.get(di.name) or NodeInterface(name=di.name)
            if di.name not in have:
                x.interfaces.append(itf)
            itf.subnet_id = subnets[di.subnet].id if di.subnet else None
            itf.ip_address = di.ip

    # Order matters: drop obsolete links first, upsert nodes, re-point links, then drop obsolete nodes
    # (avoids DB-level cascades deleting rows the session still tracks).
    prune(n.links, {d.key for d in doc.links})
    db.flush()
    nodes = sync(n.nodes, doc.nodes, lambda d: NetworkNode(key=d.key), upd_node, remove=False)
    db.flush()

    def upd_link(link, d):
        link.source_node_id, link.target_node_id = nodes[d.source].id, nodes[d.target].id
        link.label, link.kind, link.bandwidth_mbps = d.label, d.kind, d.bandwidth_mbps

    sync(n.links, doc.links, lambda d: NetworkLink(key=d.key), upd_link)
    db.flush()
    prune(n.nodes, {d.key for d in doc.nodes})
    db.flush()
    return stats


def _store_validation(n: LabNetwork, issues: list[Issue]) -> None:
    n.validation_status, n.error_count, n.warning_count = status_of(issues)


def _check_structure(doc: TopologyDoc) -> None:
    errs = structural_errors(doc)
    if errs:
        raise AppError("Topology has structural errors and cannot be saved", code="invalid_topology", status_code=422,
                       details=[e.model_dump() for e in errs])


# ------------------------------------------------------------------ operations
def create(db: Session, p: Principal, *, name: str, description: str, visibility: str, doc: TopologyDoc | None = None,
           action: str = "network.create", extra: dict | None = None) -> LabNetwork:
    _name_free(db, p.id, name)
    n = LabNetwork(name=name, description=description, owner_id=p.id, visibility=visibility, updated_by=p.id)
    db.add(n)
    db.flush()
    doc = doc or TopologyDoc(name=name, description=description)
    doc = doc.model_copy(update={"name": name, "description": description})
    _check_structure(doc)
    stats = _apply(db, n, doc)
    _store_validation(n, validate(doc))
    record(db, action, actor=p, resource_type="network", resource_id=n.id,
           details={"name": name, "visibility": visibility, **stats, **(extra or {})})
    return n


def create_from_template(db: Session, p: Principal, *, name: str, description: str, visibility: str, template: str,
                         avoid_running: bool = False) -> LabNetwork:
    """avoid_running: move subnets that collide with running labs to free ranges (practice labs, class labs)."""
    t = TEMPLATES.get(template)
    if not t:
        raise NotFound("Unknown template")
    body = t["doc"]
    if avoid_running:
        from app.cyber_range.models import INSTANCE_ACTIVE, Lab, LabInstance, LabRuntimeNetwork
        from app.network.templates import readdress
        # planned networks of every active instance (a just-dispatched deploy has no runtime networks yet) plus realised ones
        taken = [c for (c,) in db.execute(select(LabRuntimeNetwork.cidr).join(LabInstance).where(LabInstance.status.in_(INSTANCE_ACTIVE)))]
        for (plan,) in db.execute(select(Lab.plan).join(LabInstance, LabInstance.lab_id == Lab.id).where(LabInstance.status.in_(INSTANCE_ACTIVE))):
            taken += [n["cidr"] for n in (plan or {}).get("networks", [])]
        body, _ = readdress(body, taken)
    doc = TopologyDoc.model_validate({"name": name, "description": description or t["description"], **body})
    return create(db, p, name=name, description=description or t["description"], visibility=visibility, doc=doc,
                  extra={"template": template})


def save_topology(db: Session, p: Principal, network_id: int, expected_version: int, doc: TopologyDoc) -> tuple[LabNetwork, list[Issue]]:
    n = get_for(db, p, network_id, edit=True, lock=True)
    if n.version != expected_version:
        raise Conflict("This topology was changed by someone else. Reload to get the latest version.",
                       code="version_conflict", details={"current_version": n.version})
    _check_structure(doc)
    if doc.name != n.name:
        _name_free(db, n.owner_id, doc.name, exclude_id=n.id)
    n.name, n.description = doc.name, doc.description
    stats = _apply(db, n, doc)
    issues = validate(doc)
    _store_validation(n, issues)
    n.version += 1
    n.updated_by, n.updated_at = p.id, utcnow()
    record(db, "network.topology.save", actor=p, resource_type="network", resource_id=n.id,
           details={"version": n.version, **stats, "status": n.validation_status})
    return n, issues


def update_meta(db: Session, p: Principal, network_id: int, **fields) -> LabNetwork:
    n = get_for(db, p, network_id, edit=True, lock=True)
    changes = {}
    if fields.get("name") and fields["name"] != n.name:
        _name_free(db, n.owner_id, fields["name"], exclude_id=n.id)
        changes["name"] = [n.name, fields["name"]]
        n.name = fields["name"]
    if fields.get("description") is not None and fields["description"] != n.description:
        changes["description"] = True
        n.description = fields["description"]
    if fields.get("visibility") and fields["visibility"] != n.visibility:
        changes["visibility"] = [n.visibility, fields["visibility"]]
        n.visibility = fields["visibility"]
    if changes:
        n.version += 1
        n.updated_by = p.id
        record(db, "network.update", actor=p, resource_type="network", resource_id=n.id, details=changes)
    return n


def delete(db: Session, p: Principal, network_id: int) -> None:
    n = get_for(db, p, network_id, edit=True, lock=True)
    n.deleted_at = utcnow()
    record(db, "network.delete", actor=p, resource_type="network", resource_id=n.id, details={"name": n.name})


def duplicate(db: Session, p: Principal, network_id: int, name: str) -> LabNetwork:
    src = get_for(db, p, network_id)
    doc = to_doc(src)
    return create(db, p, name=name, description=src.description, visibility="private", doc=doc,
                  action="network.duplicate", extra={"source_id": src.id})


def parse_import(fmt: str, content: str) -> TopologyDoc:
    try:
        data = json.loads(content) if fmt == "json" else yaml.safe_load(content)
    except (json.JSONDecodeError, yaml.YAMLError) as e:
        raise AppError(f"Could not parse {fmt.upper()}: {str(e).splitlines()[0][:200]}", code="parse_error", status_code=422) from None
    if not isinstance(data, dict):
        raise AppError("Top level must be an object", code="parse_error", status_code=422)
    try:
        return TopologyDoc.model_validate(data)
    except ValidationError as e:
        raise AppError("Imported document does not match the topology schema", code="validation_error", status_code=422,
                       details=[{"loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()[:50]]) from None


def export(n: LabNetwork, fmt: str) -> str:
    data = to_doc(n).model_dump(mode="json")
    if fmt == "yaml":
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    return json.dumps(data, indent=2, ensure_ascii=False)


def summary(db: Session, p: Principal, n: LabNetwork, owner_names: dict | None = None) -> NetworkSummary:
    s = NetworkSummary.model_validate(n)
    s.node_count, s.link_count = len(n.nodes), len(n.links)
    s.can_edit = can_edit(p, n)
    if owner_names is not None:
        s.owner = owner_names.get(n.owner_id)
    return s


def counts_for_dashboard(db: Session) -> dict:
    live = LabNetwork.deleted_at.is_(None)
    return {
        "networks": db.execute(select(func.count()).select_from(LabNetwork).where(live)).scalar_one(),
        "nodes": db.execute(select(func.count()).select_from(NetworkNode).join(LabNetwork).where(live)).scalar_one(),
    }

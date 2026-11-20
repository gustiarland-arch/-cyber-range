from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.database import get_db
from app.iam.deps import Principal, require
from app.iam.models import User
from app.network import service
from app.network.models import LINK_KINDS, NODE_TYPES, ZONE_KINDS, LabNetwork
from app.network.schemas import (
    ImportRequest, Issue, NetworkCreate, NetworkDetail, NetworkMetaUpdate, NetworkSummary, TopologyDoc, TopologySave,
)
from app.network.templates import TEMPLATES
from app.network.validation import validate

router = APIRouter(prefix="/networks", tags=["network"])
VIEW = Depends(require("lab.view"))
EDIT = Depends(require("network.topology.edit"))


def _detail(db: Session, p: Principal, n: LabNetwork, issues: list[Issue] | None = None) -> NetworkDetail:
    doc = service.to_doc(n)
    s = service.summary(db, p, n, {n.owner_id: db.get(User, n.owner_id).username})
    return NetworkDetail(**s.model_dump(), topology=doc, issues=issues if issues is not None else validate(doc))


@router.get("/meta")
def meta(_p: Principal = VIEW):
    return {"node_types": NODE_TYPES, "zone_kinds": ZONE_KINDS, "link_kinds": LINK_KINDS,
            "templates": [{"id": k, "title": v["title"], "description": v["description"]} for k, v in TEMPLATES.items()]}


@router.get("", response_model=list[NetworkSummary])
def list_networks(db: Session = Depends(get_db), p: Principal = VIEW, q: str | None = Query(None, max_length=100),
                  mine: bool = False):
    stmt = service.visible_query(p)
    if q:
        stmt = stmt.where(LabNetwork.name.like(f"%{q}%"))
    if mine:
        stmt = stmt.where(LabNetwork.owner_id == p.id)
    rows = db.execute(stmt.order_by(LabNetwork.updated_at.desc()).limit(500)).scalars().all()
    owners = dict(db.execute(select(User.id, User.username).where(User.id.in_({r.owner_id for r in rows} or {0}))).all())
    return [service.summary(db, p, n, owners) for n in rows]


@router.post("", response_model=NetworkDetail, status_code=201)
def create(body: NetworkCreate, db: Session = Depends(get_db), p: Principal = EDIT):
    if body.template:
        n = service.create_from_template(db, p, name=body.name, description=body.description, visibility=body.visibility, template=body.template)
    else:
        n = service.create(db, p, name=body.name, description=body.description, visibility=body.visibility)
    db.commit()
    return _detail(db, p, n)


@router.post("/import", response_model=NetworkDetail, status_code=201)
def import_topology(body: ImportRequest, db: Session = Depends(get_db), p: Principal = EDIT):
    doc = service.parse_import(body.format, body.content)
    name = body.name or doc.name
    n = service.create(db, p, name=name, description=doc.description, visibility=body.visibility, doc=doc,
                       action="network.import", extra={"format": body.format, "bytes": len(body.content)})
    db.commit()
    return _detail(db, p, n)


@router.post("/validate", response_model=list[Issue])
def validate_draft(doc: TopologyDoc, _p: Principal = VIEW):
    """Validate an unsaved draft (no persistence)."""
    return validate(doc)


@router.get("/{network_id}", response_model=NetworkDetail)
def get_network(network_id: int, db: Session = Depends(get_db), p: Principal = VIEW):
    return _detail(db, p, service.get_for(db, p, network_id))


@router.put("/{network_id}/topology", response_model=NetworkDetail)
def save(network_id: int, body: TopologySave, db: Session = Depends(get_db), p: Principal = EDIT):
    n, issues = service.save_topology(db, p, network_id, body.expected_version, body.topology)
    db.commit()
    return _detail(db, p, n, issues)


@router.patch("/{network_id}", response_model=NetworkSummary)
def update_meta(network_id: int, body: NetworkMetaUpdate, db: Session = Depends(get_db), p: Principal = EDIT):
    n = service.update_meta(db, p, network_id, **body.model_dump(exclude_unset=True))
    db.commit()
    return service.summary(db, p, n)


@router.post("/{network_id}/duplicate", response_model=NetworkDetail, status_code=201)
def duplicate(network_id: int, body: NetworkMetaUpdate, db: Session = Depends(get_db), p: Principal = EDIT):
    src = service.get_for(db, p, network_id)
    n = service.duplicate(db, p, network_id, body.name or f"{src.name} (copy)")
    db.commit()
    return _detail(db, p, n)


@router.delete("/{network_id}", status_code=204)
def delete(network_id: int, db: Session = Depends(get_db), p: Principal = EDIT):
    service.delete(db, p, network_id)
    db.commit()


@router.get("/{network_id}/export")
def export(network_id: int, format: str = Query("json", pattern="^(json|yaml)$"), db: Session = Depends(get_db), p: Principal = VIEW):
    n = service.get_for(db, p, network_id)
    body = service.export(n, format)
    record(db, "network.export", actor=p, resource_type="network", resource_id=n.id, details={"format": format})
    db.commit()
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in n.name)[:60] or "topology"
    media = "application/json" if format == "json" else "application/yaml"
    return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{safe}.{format}"'})

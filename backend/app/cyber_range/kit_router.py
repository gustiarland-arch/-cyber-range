"""Lab Kit endpoints (v1.6): preview and download a lab to run on one's own computer. See app/cyber_range/kit.py."""
import re

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.config import get_settings
from app.core.database import get_db
from app.core.errors import AppError, NotFound, TooManyRequests
from app.core.redis_client import rate_limiter
from app.cyber_range import kit
from app.cyber_range.service import image_dicts
from app.iam.deps import Principal, require
from app.network import service as network_service
from app.network.models import LabNetwork
from app.network.schemas import TopologyDoc
from app.network.templates import TEMPLATES
from app.network.validation import validate

router = APIRouter(prefix="/lab-kits", tags=["lab-kits"])
KIT = Depends(require("lab.kit.download"))
SOURCE = Query(..., pattern=r"^(template:[a-z0-9-]{1,64}|network:\d{1,12})$")
FORMAT = Query("docker", pattern="^(docker|vagrant)$")
DOWNLOAD_LIMIT, DOWNLOAD_WINDOW = 30, 3600


def _boxes() -> dict[str, str]:
    return kit.parse_boxes(get_settings().kit_vagrant_boxes)


def _source(db: Session, p: Principal, source: str) -> tuple[dict, str, str]:
    kind, ref = source.split(":", 1)
    if kind == "template":
        t = TEMPLATES.get(ref)
        if t is None or ref == "blank":
            raise NotFound("Unknown lab template")
        doc = TopologyDoc.model_validate({**t["doc"], "name": t["title"][:128], "description": t.get("description", "")})
        title, label = t["title"], f"template bawaan '{ref}'"
    else:
        n = network_service.get_for(db, p, int(ref))
        doc = network_service.to_doc(n)
        title, label = n.name, f"network #{n.id} v{n.version}"
    errors = [i for i in validate(doc) if i.severity == "error"]
    if errors:
        raise AppError("The topology has validation errors; fix them in the editor first", code="invalid_topology", status_code=422,
                       details=[e.model_dump() for e in errors])
    return doc.model_dump(mode="json"), title, label


def _kit_error(e: kit.KitError):
    return AppError("This topology cannot be turned into a Lab Kit", code="kit_error", status_code=422, details=e.problems)


def _server_labs(db: Session, p: Principal) -> dict:
    return {"allowed": p.has("lab.operate"), "reason": None if p.has("lab.operate") else "no_permission"}


@router.get("/me")
def me(db: Session = Depends(get_db), p: Principal = KIT):
    """Whether the operator may also start labs on this machine (Lab Kits run the same topology elsewhere)."""
    return {"server_labs": _server_labs(db, p)}


@router.get("/options")
def options(db: Session = Depends(get_db), p: Principal = KIT):
    nets = db.execute(network_service.visible_query(p).order_by(LabNetwork.updated_at.desc()).limit(200)).scalars().all()
    return {
        "formats": [{"key": "docker", "title": "Docker Compose", "needs": "Docker Desktop / Docker Engine + Compose v2"},
                    {"key": "vagrant", "title": "Vagrant (VM)", "needs": "Vagrant 2.4+ dan VirtualBox 7, atau libvirt"}],
        "templates": [{"key": k, "title": v["title"], "description": v.get("description", ""), "nodes": sum(n["type"] not in ("internet", "switch") for n in v["doc"]["nodes"])}
                      for k, v in TEMPLATES.items() if k != "blank"],
        "networks": [{"id": n.id, "name": n.name, "version": n.version, "mine": n.owner_id == p.id} for n in nets],
        "boxes": sorted(set(_boxes().values())),
        "server_packages": [{"key": k, "title": v["title"], "apt": v["apt"], "ports": v["ports"]} for k, v in kit.SERVER_PACKAGES.items()],
        "server_labs": _server_labs(db, p),
    }


PACKAGES = Query(default=[], description="node=set1,set2 (vagrant only); sets from /lab-kits/options")
WINDOWS_DC = Query(False, description="vagrant + office lab: the domain controller becomes a Windows Server (Evaluation) VM")
WINDOWS_PCS = Query(default=[], description="employee PC VM names that run Windows 11 (Evaluation); needs windows_dc")
VM_NAME = re.compile(r"^[a-z0-9-]{1,64}$")


def _windows_box() -> str:
    return get_settings().kit_windows_dc_box


def _windows_pcs(names: list[str]) -> list[str]:
    if len(names) > 32 or not all(VM_NAME.match(n) for n in names):
        raise AppError("Invalid VM names in windows_pcs", code="kit_error", status_code=422)
    return names


@router.get("/preview")
def preview(source: str = SOURCE, format: str = FORMAT, packages: list[str] = PACKAGES, windows_dc: bool = WINDOWS_DC,
            windows_pcs: list[str] = WINDOWS_PCS, db: Session = Depends(get_db), p: Principal = KIT):
    doc, title, label = _source(db, p, source)
    try:
        out = kit.preview(doc, image_dicts(db), fmt=format, boxes=_boxes(), packages=kit.parse_packages(packages),
                          windows_dc=windows_dc, windows_box=_windows_box(),
                          windows_pcs=_windows_pcs(windows_pcs), windows_pc_box=get_settings().kit_windows_pc_box)
    except kit.KitError as e:
        raise _kit_error(e) from None
    return {**out, "title": title, "source": label}


@router.get("/download")
def download(source: str = SOURCE, format: str = FORMAT, packages: list[str] = PACKAGES, windows_dc: bool = WINDOWS_DC,
             windows_pcs: list[str] = WINDOWS_PCS, db: Session = Depends(get_db), p: Principal = KIT):
    if not rate_limiter.hit(f"kit:{p.id}", DOWNLOAD_LIMIT, DOWNLOAD_WINDOW):
        raise TooManyRequests("Too many Lab Kit downloads; try again later")
    doc, title, label = _source(db, p, source)
    try:
        pk = kit.parse_packages(packages)
        data, meta = kit.build_zip(doc, image_dicts(db), fmt=format, title=title, source=label, boxes=_boxes(), packages=pk,
                                   windows_dc=windows_dc, windows_box=_windows_box(),
                          windows_pcs=_windows_pcs(windows_pcs), windows_pc_box=get_settings().kit_windows_pc_box)
    except kit.KitError as e:
        raise _kit_error(e) from None
    record(db, "lab.kit.download", actor=p, resource_type="lab_kit", resource_id=meta["kit_id"],
           details={"source": source, "format": format, "totals": meta["totals"], "packages": pk, "windows_dc": windows_dc,
                    "windows_pcs": sorted(set(windows_pcs))})
    db.commit()
    return Response(content=data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{meta["root"]}.zip"', "X-Kit-Id": meta["kit_id"],
                             "Cache-Control": "no-store"})

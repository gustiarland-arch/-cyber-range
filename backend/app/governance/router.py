from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.governance import service
from app.iam.deps import Principal, require

router = APIRouter(prefix="/settings", tags=["settings"])


class SettingIn(BaseModel):
    value: Any


@router.get("")
def list_settings(db: Session = Depends(get_db), _p: Principal = Depends(require("system.settings.view"))):
    return service.list_settings(db)


@router.put("/{key}")
def update_setting(key: str, body: SettingIn, db: Session = Depends(get_db), p: Principal = Depends(require("system.settings.manage"))):
    service.update_setting(db, p, key, body.value)
    db.commit()
    return next(s for s in service.list_settings(db) if s["key"] == key)


@router.get("/public")
def public_settings(db: Session = Depends(get_db)):
    """Unauthenticated, non-sensitive display values (name and banner)."""
    out = {k: service.get_value(db, k) for k in ("platform.display_name", "platform.login_banner")}
    return out

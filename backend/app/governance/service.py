"""System settings with server-side schema validation."""
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import record
from app.core.errors import AppError, Forbidden, NotFound
from app.governance.models import SystemSetting

# key: (type, default, description, constraints)
SETTINGS_SCHEMA: dict[str, dict[str, Any]] = {
    "platform.display_name": {"type": str, "default": "CYBER RANGE", "max_len": 64, "description": "Name shown in the UI header"},
    "platform.login_banner": {"type": str, "default": "Authorized use only. All activity is audited.", "max_len": 500,
                              "description": "Banner displayed on the login screen"},
    "telemetry.event_retention_days": {"type": int, "default": 90, "min": 7, "max": 3650,
                                       "description": "Retention for raw/normalized events (enforced from Phase 4)"},
    "audit.retention_days": {"type": int, "default": 730, "min": 365, "max": 3650, "description": "Minimum audit log retention"},
    "lab.kill_switch": {"type": bool, "default": False, "description": "When true, all running labs are stopped and no lab may start"},
    "lab.max_active_per_user": {"type": int, "default": 2, "min": 1, "max": 50, "description": "Active lab instances per user"},
    "lab.max_active_total": {"type": int, "default": 10, "min": 1, "max": 500, "description": "Active lab instances on this host"},
    "lab.max_containers": {"type": int, "default": 25, "min": 1, "max": 200, "description": "Containers per lab"},
    "lab.max_memory_mb": {"type": int, "default": 4096, "min": 128, "max": 262144, "description": "Memory quota per lab (MB)"},
    "lab.max_cpus": {"type": int, "default": 8, "min": 1, "max": 256, "description": "CPU quota per lab (cores)"},
    "malware.max_sample_mb": {"type": int, "default": 32, "min": 1, "max": 200, "description": "Maximum size of a submitted malware sample (MB)"},
    "malware.allowed_types": {"type": str, "default": "pe,elf,macho,script,pdf,ole,ooxml,zip,jar,gzip,rar,7z,html,lnk,text,data", "max_len": 300,
                              "description": "Comma-separated content types accepted into quarantine (detected from content, not file name)"},
    "evidence.max_upload_mb": {"type": int, "default": 512, "min": 1, "max": 20480, "description": "Maximum size of one uploaded evidence file (MB)"},
    "redteam.require_approval": {"type": bool, "default": True, "readonly": True,
                                 "description": "Red-team assessments always require approval (cannot be disabled)"},
}


def _validate(key: str, value: Any) -> Any:
    spec = SETTINGS_SCHEMA.get(key)
    if spec is None:
        raise NotFound("Unknown setting")
    if spec.get("readonly"):
        raise Forbidden("This setting is enforced by policy and cannot be changed", code="policy_locked")
    t = spec["type"]
    if t is bool and not isinstance(value, bool) or t is int and (isinstance(value, bool) or not isinstance(value, int)) \
            or t is str and not isinstance(value, str):
        raise AppError(f"Setting {key} must be of type {t.__name__}", code="validation_error", status_code=422)
    if t is int and not (spec["min"] <= value <= spec["max"]):
        raise AppError(f"Setting {key} must be between {spec['min']} and {spec['max']}", code="validation_error", status_code=422)
    if t is str:
        value = value.strip()
        if len(value) > spec["max_len"]:
            raise AppError(f"Setting {key} must be at most {spec['max_len']} characters", code="validation_error", status_code=422)
        if spec.get("choices") and value not in spec["choices"]:
            raise AppError(f"Setting {key} must be one of: {', '.join(spec['choices'])}", code="validation_error", status_code=422)
    return value


def seed_defaults(db: Session) -> int:
    have = {k for (k,) in db.execute(select(SystemSetting.key))}
    n = 0
    for key, spec in SETTINGS_SCHEMA.items():
        if key not in have:
            db.add(SystemSetting(key=key, value=spec["default"], description=spec["description"]))
            n += 1
    db.flush()
    return n


def list_settings(db: Session) -> list[dict]:
    rows = {s.key: s for s in db.execute(select(SystemSetting)).scalars()}
    out = []
    for key, spec in SETTINGS_SCHEMA.items():
        row = rows.get(key)
        out.append({
            "key": key, "value": row.value if row else spec["default"], "type": spec["type"].__name__,
            "description": spec["description"], "readonly": bool(spec.get("readonly")),
            "min": spec.get("min"), "max": spec.get("max"), "max_len": spec.get("max_len"), "choices": list(spec["choices"]) if spec.get("choices") else None,
            "updated_at": row.updated_at if row else None, "updated_by": row.updated_by if row else None,
        })
    return out


def get_value(db: Session, key: str) -> Any:
    row = db.get(SystemSetting, key)
    return row.value if row else SETTINGS_SCHEMA[key]["default"]


def update_setting(db: Session, actor, key: str, value: Any) -> None:
    value = _validate(key, value)
    row = db.get(SystemSetting, key)
    if row is None:
        row = SystemSetting(key=key, value=SETTINGS_SCHEMA[key]["default"], description=SETTINGS_SCHEMA[key]["description"])
        db.add(row)
    before = row.value
    row.value, row.updated_by = value, actor.id
    record(db, "system.setting.update", actor=actor, resource_type="setting", resource_id=key, details={"before": before, "after": value})

"""Management CLI: `python -m app.cli seed`, `demo` and `record-backup`.

The local edition has one account, the local operator; `seed` creates it. There are no passwords to manage.
"""
import argparse
import sys

from sqlalchemy import select

from app import models  # noqa: F401
from app.audit.service import record
from app.core.database import SessionLocal
from app.governance.service import seed_defaults
from app.iam import service


def cmd_seed(_args) -> int:
    with SessionLocal() as db:
        res = service.sync_catalog(db)
        res["settings_created"] = seed_defaults(db)
        from app.cyber_range.service import seed_images
        res["images_created"] = seed_images(db)
        from app.blueteam.service import seed as seed_soc
        res.update(seed_soc(db))
        from app.redteam.service import seed as seed_rt
        res.update(seed_rt(db))
        from app.intel.service import seed as seed_intel
        res.update(seed_intel(db))
        from app.vuln.service import seed as seed_vuln
        res.update(seed_vuln(db))
        from app.malware.service import seed as seed_mw
        res.update(seed_mw(db))
        from app.soar.service import seed as seed_soar
        res.update(seed_soar(db))
        from app.training.service import seed as seed_training
        res.update({f"training_{k}": v for k, v in seed_training(db).items()})
        res["operator"] = service.ensure_operator(db).username
        record(db, "system.seed", actor_label="system:cli", details=res)
        db.commit()
    print(f"seed ok: {res}")
    return 0


def cmd_record_backup(_args) -> int:
    """Read a backup/restore manifest (JSON) from stdin and record it, so the UI can show backup status."""
    import json
    from datetime import datetime

    from app.reports.models import BackupRun
    m = json.load(sys.stdin)
    parse = lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None)  # noqa: E731
    comps = [{k: c.get(k) for k in ("name", "file", "size", "sha256")} for c in m.get("components", [])]
    with SessionLocal() as db:
        if db.execute(select(BackupRun.id).where(BackupRun.label == str(m["label"])[:64], BackupRun.kind == m.get("kind", "backup"))).first():
            print(f"{m.get('kind', 'backup')} {m['label']} already recorded")
            return 0
        b = BackupRun(label=str(m["label"])[:64], kind=m.get("kind", "backup"), status=m.get("status", "ok"), started_at=parse(m["started_at"]),
                      finished_at=parse(m["finished_at"]), components=comps, total_size=sum(int(c.get("size") or 0) for c in comps),
                      schema_revision=str(m.get("schema_revision", ""))[:32], host=str(m.get("host", ""))[:128], note=str(m.get("note", ""))[:2000])
        db.add(b)
        db.flush()
        record(db, f"system.{b.kind}", actor_label="system:cli", resource_type="backup", resource_id=b.id,
               outcome="success" if b.status == "ok" else "failure", details={"label": b.label, "components": [c["name"] for c in comps]})
        db.commit()
    print(f"recorded {m.get('kind', 'backup')} {m['label']}")
    return 0


class _SystemActor:
    """Audit actor for CLI-driven DEMO loading (docker compose --profile demo)."""
    id = None
    username = "system:demo"


def cmd_demo(args) -> int:
    """Load or purge the clearly labelled DEMO data sets (SOC events/alerts and threat intel). Never mixed with real telemetry."""
    from app.blueteam import service as soc
    from app.intel import service as intel
    with SessionLocal() as db:
        if args.purge:
            res = {"soc": soc.purge_demo(db, _SystemActor()), "intel": intel.purge_demo(db, _SystemActor())}
        else:
            res = {"intel": intel.load_demo(db, _SystemActor()), "soc": soc.load_demo(db, _SystemActor())}
    print(f"demo {'purged' if args.purge else 'loaded'} (all records labelled DEMO): {res}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="cyber-range")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed").set_defaults(fn=cmd_seed)
    sub.add_parser("record-backup").set_defaults(fn=cmd_record_backup)
    dm = sub.add_parser("demo", help="load (or --purge) labelled DEMO data")
    dm.add_argument("--purge", action="store_true")
    dm.set_defaults(fn=cmd_demo)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())

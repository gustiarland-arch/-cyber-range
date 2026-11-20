from app.core.celery_app import celery_app
from app.core.database import SessionLocal


@celery_app.task(name="app.blueteam.tasks.forward_platform_audit")
def forward_platform_audit() -> int:
    from app.blueteam.service import forward_platform_audit as fwd
    with SessionLocal() as db:
        return fwd(db)

from app.core.celery_app import celery_app
from app.core.database import SessionLocal


@celery_app.task(name="app.vuln.tasks.run_scan")
def run_scan(job_id: int) -> str:
    from app.vuln.service import run
    return run(job_id)


@celery_app.task(name="app.vuln.tasks.expire_risk_acceptance")
def expire_risk_acceptance() -> int:
    from app.vuln.service import expire_risk_acceptance as go
    with SessionLocal() as db:
        n = go(db)
        db.commit()
        return n

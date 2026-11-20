from datetime import timedelta

from sqlalchemy import delete, or_

from app.core.celery_app import celery_app
from app.core.database import SessionLocal, utcnow
from app.iam.models import UserSession


@celery_app.task(name="app.iam.tasks.purge_expired_sessions")
def purge_expired_sessions(grace_days: int = 30) -> int:
    """Delete sessions expired or revoked more than `grace_days` ago (idempotent)."""
    cutoff = utcnow() - timedelta(days=grace_days)
    with SessionLocal() as db:
        n = db.execute(delete(UserSession).where(or_(UserSession.expires_at < cutoff, UserSession.revoked_at < cutoff))).rowcount
        db.commit()
    return n

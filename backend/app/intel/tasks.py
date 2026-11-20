from app.core.celery_app import celery_app
from app.core.database import SessionLocal


@celery_app.task(name="app.intel.tasks.expire_indicators")
def expire_indicators() -> int:
    from app.intel.service import expire
    with SessionLocal() as db:
        return expire(db)


@celery_app.task(name="app.intel.tasks.poll_feeds")
def poll_feeds() -> int:
    from app.intel.feeds import poll_due
    return poll_due()

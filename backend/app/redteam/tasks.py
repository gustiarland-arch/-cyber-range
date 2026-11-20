from app.core.celery_app import celery_app


@celery_app.task(name="app.redteam.tasks.run_assessment")
def run_assessment(assessment_id: int) -> str:
    from app.redteam.service import run
    return run(assessment_id)

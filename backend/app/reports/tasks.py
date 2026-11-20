from app.core.celery_app import celery_app
from app.reports import service


@celery_app.task(name="app.reports.tasks.generate_report")
def generate_report(report_id: int) -> None:
    service.generate(report_id)

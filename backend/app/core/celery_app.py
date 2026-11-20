"""Celery application. Redis is the broker/result backend (queue only, never primary storage)."""
from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

_s = get_settings()
celery_app = Celery("cyber_range", broker=_s.celery_broker_url or _s.redis_url, backend=_s.celery_broker_url or _s.redis_url,
                    include=["app.iam.tasks", "app.cyber_range.tasks", "app.blueteam.tasks", "app.redteam.tasks", "app.intel.tasks", "app.vuln.tasks", "app.malware.tasks", "app.reports.tasks"])
celery_app.conf.update(
    task_serializer="json", accept_content=["json"], result_serializer="json", timezone="UTC", enable_utc=True,
    task_acks_late=True, worker_prefetch_multiplier=1, result_expires=3600,
    task_routes={"app.iam.tasks.*": {"queue": "maintenance"}, "app.cyber_range.tasks.*": {"queue": "lab"}, "app.redteam.tasks.*": {"queue": "lab"},
                 "app.vuln.tasks.run_scan": {"queue": "lab"}, "app.malware.tasks.*": {"queue": "analysis"}, "app.reports.tasks.*": {"queue": "reports"}},
    beat_schedule={
        "purge-expired-sessions": {"task": "app.iam.tasks.purge_expired_sessions", "schedule": crontab(minute=17)},
        "lab-stats": {"task": "app.cyber_range.tasks.collect_stats", "schedule": 10.0, "options": {"expires": 9}},
        "lab-reconcile": {"task": "app.cyber_range.tasks.reconcile", "schedule": 60.0, "options": {"expires": 50}},
        "soc-platform-audit": {"task": "app.blueteam.tasks.forward_platform_audit", "schedule": 10.0, "options": {"expires": 9}},
        "intel-expire": {"task": "app.intel.tasks.expire_indicators", "schedule": crontab(minute="*/15")},
        "vuln-risk-expiry": {"task": "app.vuln.tasks.expire_risk_acceptance", "schedule": crontab(minute=5, hour="*/6")},
        "sandbox-poll": {"task": "app.malware.tasks.poll_sandbox_runs", "schedule": 60.0, "options": {"expires": 55}},
        "lab-sensors": {"task": "app.cyber_range.tasks.sensors_collect", "schedule": 10.0, "options": {"expires": 9}},
        "intel-feeds": {"task": "app.intel.tasks.poll_feeds", "schedule": 300.0, "options": {"expires": 290}},
        "lab-kill-switch": {"task": "app.cyber_range.tasks.enforce_kill_switch", "schedule": 15.0, "options": {"expires": 14}},
    },
)

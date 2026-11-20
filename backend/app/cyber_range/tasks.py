from app.core.celery_app import celery_app
from app.cyber_range import runtime


@celery_app.task(name="app.cyber_range.tasks.lab_operation", acks_late=True)
def lab_operation(instance_id: int, op: str, **kw) -> str:
    return runtime.run_operation(instance_id, op, **kw)


@celery_app.task(name="app.cyber_range.tasks.delete_snapshot")
def delete_snapshot(snapshot_id: int) -> None:
    runtime.delete_snapshot_images(snapshot_id)


@celery_app.task(name="app.cyber_range.tasks.collect_stats")
def collect_stats() -> int:
    return runtime.collect_stats()


@celery_app.task(name="app.cyber_range.tasks.reconcile")
def reconcile() -> int:
    return runtime.reconcile()


@celery_app.task(name="app.cyber_range.tasks.enforce_kill_switch")
def enforce_kill_switch() -> int:
    return runtime.enforce_kill_switch()


@celery_app.task(name="app.cyber_range.tasks.sensors_start")
def sensors_start(ids: list[int]) -> int:
    from app.cyber_range import sensors
    return sensors.start_sensors(ids)


@celery_app.task(name="app.cyber_range.tasks.sensors_stop")
def sensors_stop(ids: list[int]) -> int:
    from app.cyber_range import sensors
    return sensors.stop_sensors(ids)


@celery_app.task(name="app.cyber_range.tasks.sensors_collect")
def sensors_collect() -> int:
    from app.cyber_range import sensors
    return sensors.collect()

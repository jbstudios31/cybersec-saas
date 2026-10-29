from celery import Celery
from celery.schedules import crontab

from app.core.config import REDIS_URL

celery_app = Celery("cybersec", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.task_routes = {
    "worker.tasks.run_scan": "scans",
    "worker.schedule.scan_all_targets": "scans",
}
celery_app.conf.beat_schedule = {
    "scan-all-targets-weekly": {
        "task": "worker.schedule.scan_all_targets",
        "schedule": crontab(hour=2, minute=0, day_of_week=0),  # Domingos 02:00 UTC
    },
}
celery_app.conf.timezone = "UTC"

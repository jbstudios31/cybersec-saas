from celery import shared_task

from app.core import config
from app.core.database import SessionLocal, engine
from app.core.ssrf import validate_target_url
from app.models.base import Base
from app.models.target import Target
from worker.tasks import execute_scan


@shared_task(name="worker.schedule.scan_all_targets")
def scan_all_targets() -> dict:
    """Ejecuta un escaneo sobre todos los targets activos.
    Se programa semanalmente mediante Celery Beat."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        targets = db.query(Target).filter(Target.is_active == True).all()  # noqa: E712
        results = []
        for target in targets:
            if config.REQUIRE_TARGET_VERIFICATION and target.verified_at is None:
                continue
            try:
                validate_target_url(target.url)
            except Exception:
                continue
            result = execute_scan(target.id)
            results.append({"target_id": target.id, "result": result})
        return {"scanned": len(results), "results": results}
    finally:
        db.close()

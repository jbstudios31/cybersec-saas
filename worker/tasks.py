from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core import config
from app.core.database import SessionLocal, engine
from app.core.ssrf import validate_target_url
from app.models.base import Base
from app.models.finding import Finding
from app.models.scan_run import ScanRun
from app.models.target import Target
from scanner.checks import scan_target
from worker.alerts import send_alert_if_critical
from worker.celery_app import celery_app


def init_db():
    Base.metadata.create_all(bind=engine)


def execute_scan(target_id: int) -> dict:
    """Ejecuta un escaneo sobre un target y guarda resultados en BD.
    Puede llamarse directamente (sin Celery) o desde una tarea de Celery."""
    init_db()
    db: Session = SessionLocal()
    try:
        target = db.get(Target, target_id)
        if not target:
            return {"error": "target not found"}
        try:
            validate_target_url(target.url)
        except Exception as exc:  # noqa: BLE001
            return {"error": getattr(exc, "detail", str(exc))}
        if config.REQUIRE_TARGET_VERIFICATION and target.verified_at is None:
            return {"error": "target not verified"}
        scan = ScanRun(target_id=target.id, status="running")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        try:
            findings_data = scan_target(target.url)
            scan.status = "done"
            scan.finished_at = datetime.now(UTC)
            db.add(scan)
            db.commit()

            new_critical = False
            for fd in findings_data:
                finding = Finding(
                    scan_run_id=scan.id,
                    severity=fd["severity"],
                    title=fd["title"],
                    description=fd["description"],
                    remediation=fd["remediation"],
                )
                db.add(finding)
                if fd["severity"] == "critical":
                    new_critical = True
            db.commit()

            if new_critical:
                send_alert_if_critical(target, scan.id)

            return {"scan_id": scan.id, "findings": len(findings_data)}
        except Exception:  # noqa: BLE001
            scan.status = "failed"
            scan.finished_at = datetime.now(UTC)
            db.add(scan)
            db.commit()
            return {"error": "scan failed"}
    finally:
        db.close()


@celery_app.task(name="worker.tasks.run_scan")
def run_scan(target_id: int) -> dict:
    """Tarea de Celery que ejecuta execute_scan (para producción con broker)."""
    return execute_scan(target_id)

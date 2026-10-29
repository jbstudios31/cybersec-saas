import json
from typing import Optional

from sqlalchemy.orm import Session

from app.core.logging import logger
from app.models.audit import AuditLog


def record_audit(
    db: Session,
    action: str,
    user_id: Optional[int] = None,
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    """Registra una acción sensible en la tabla de auditoría.

    Nunca lanza excepciones: un fallo de auditoría no debe tumbar la request.
    """
    try:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip=(ip or "")[:64] or None,
            user_agent=(user_agent or "")[:255] or None,
            details=json.dumps(details, ensure_ascii=False) if details else None,
        )
        db.add(entry)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.warning("audit_log_fallido", extra={"action": action, "error": str(exc)})

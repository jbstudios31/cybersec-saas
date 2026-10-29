import json
import logging
import sys
from contextvars import ContextVar

from app.core.config import IS_PRODUCTION, LOG_LEVEL

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

_RESERVED = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
    "pathname", "process", "processName", "relativeCreated", "stack_info",
    "thread", "threadName", "taskName",
}


class JsonFormatter(logging.Formatter):
    """Formatea los logs como JSON (una línea por evento) para ingestión."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = str(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = f"{self.formatTime(record, '%H:%M:%S')} {record.levelname:<7} {record.name}: {record.getMessage()}"
        rid = request_id_var.get()
        if rid and rid != "-":
            base = f"{base} [req={rid}]"
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


def configure_logging() -> None:
    """Configura el logging raíz una sola vez (JSON en producción, texto en dev)."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if IS_PRODUCTION else PlainFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # Silenciar logs ruidosos de terceros
    for noisy in ("uvicorn.access", "celery.worker.strategy", "kombu"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


configure_logging()

logger = logging.getLogger("cybersec")

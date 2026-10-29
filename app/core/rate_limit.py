import threading
import time
from collections import defaultdict

from fastapi import HTTPException, status

from app.core.config import RATE_LIMIT_MAX_ATTEMPTS, RATE_LIMIT_WINDOW_SECONDS, REDIS_URL
from app.core.logging import logger

MAX_ATTEMPTS = RATE_LIMIT_MAX_ATTEMPTS
WINDOW_SECONDS = RATE_LIMIT_WINDOW_SECONDS

# Fallback en memoria (single worker / sin Redis)
_login_attempts: dict[str, list[float]] = defaultdict(list)
_lock = threading.Lock()

_redis_client = None
_redis_checked = False


def _get_redis():
    """Devuelve el cliente Redis si está disponible; None si no (fallback en memoria)."""
    global _redis_client, _redis_checked
    if _redis_checked:
        return _redis_client
    _redis_checked = True
    try:
        import redis

        client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1, socket_timeout=1)
        client.ping()
        _redis_client = client
        logger.info("rate_limit_redis_activo")
    except Exception:  # noqa: BLE001
        _redis_client = None
        logger.warning("rate_limit_sin_redis_usando_memoria")
    return _redis_client


def _key(email: str) -> str:
    return f"ratelimit:login:{(email or '').strip().lower()}"


def _too_many() -> None:
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Demasiados intentos fallidos. Intenta de nuevo más tarde.",
    )


def check_rate_limit(email: str) -> None:
    """Lanza 429 si el email ya superó el máximo de intentos en la ventana."""
    client = _get_redis()
    if client is not None:
        try:
            count = client.get(_key(email))
            if count is not None and int(count) >= MAX_ATTEMPTS:
                _too_many()
            return
        except Exception:  # noqa: BLE001 - si Redis falla, usar memoria
            pass

    now = time.time()
    window_start = now - WINDOW_SECONDS
    with _lock:
        attempts = _login_attempts.get(email, [])
        _login_attempts[email] = [t for t in attempts if t > window_start]
        if len(_login_attempts[email]) >= MAX_ATTEMPTS:
            _too_many()


def record_failed_attempt(email: str) -> None:
    """Registra un intento fallido para el email."""
    client = _get_redis()
    if client is not None:
        try:
            key = _key(email)
            pipe = client.pipeline()
            pipe.incr(key)
            pipe.expire(key, WINDOW_SECONDS)
            pipe.execute()
            return
        except Exception:  # noqa: BLE001
            pass

    with _lock:
        _login_attempts[email].append(time.time())


def reset_attempts(email: str) -> None:
    """Limpia los intentos fallidos tras un login exitoso."""
    client = _get_redis()
    if client is not None:
        try:
            client.delete(_key(email))
            return
        except Exception:  # noqa: BLE001
            pass

    with _lock:
        _login_attempts.pop(email, None)

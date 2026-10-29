import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


ENV = os.getenv("ENV", "development")
IS_PRODUCTION = ENV == "production"
DEBUG = _bool("DEBUG", not IS_PRODUCTION)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
if IS_PRODUCTION and SECRET_KEY == "dev-secret-change-me":
    raise RuntimeError("SECRET_KEY debe configurarse en producción")

# Documentación interactiva: desactivable en producción
DOCS_ENABLED = _bool("DOCS_ENABLED", not IS_PRODUCTION)

# Hosts permitidos (anti Host header injection). Vacío = sin restricción.
TRUSTED_HOSTS = [h.strip() for h in os.getenv("TRUSTED_HOSTS", "").split(",") if h.strip()]

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cybersec.db")
DB_POOL_SIZE = _int("DB_POOL_SIZE", 5)
DB_MAX_OVERFLOW = _int("DB_MAX_OVERFLOW", 10)
DB_SSLMODE = os.getenv("DB_SSLMODE", "")
DB_ECHO = _bool("DB_ECHO", False)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

SCAN_ASYNC = _bool("SCAN_ASYNC", True)
CRON_TOKEN = os.getenv("CRON_TOKEN", "")

# JWT
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = _int("JWT_EXPIRE_MINUTES", 60 * 24)
JWT_ISSUER = os.getenv("JWT_ISSUER", "cybersec-saas")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "cybersec-saas")

# Contraseñas
PASSWORD_MIN_LENGTH = _int("PASSWORD_MIN_LENGTH", 10)

# Rate limiting
RATE_LIMIT_MAX_ATTEMPTS = _int("RATE_LIMIT_MAX_ATTEMPTS", 5)
RATE_LIMIT_WINDOW_SECONDS = _int("RATE_LIMIT_WINDOW_SECONDS", 300)

SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = _int("SMTP_PORT", 1025)
SMTP_USER = os.getenv("SMTP_USER") or None
SMTP_PASS = os.getenv("SMTP_PASS") or None
SMTP_USE_TLS = _bool("SMTP_USE_TLS", False)
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "alerts@localhost")
ALERT_FROM_EMAIL = os.getenv("ALERT_FROM_EMAIL", ALERT_EMAIL)

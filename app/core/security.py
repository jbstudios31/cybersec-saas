import hashlib
import hmac
import os
import re
from typing import Optional

from app.core.config import PASSWORD_MIN_LENGTH
from app.models.user import User

PBKDF2_ITERATIONS = 310000


class WeakPasswordError(ValueError):
    """La contraseña no cumple la política de seguridad."""


def validate_password_strength(password: str) -> None:
    """Valida la política de contraseñas. Lanza WeakPasswordError si no cumple."""
    if len(password or "") < PASSWORD_MIN_LENGTH:
        raise WeakPasswordError(f"La contraseña debe tener al menos {PASSWORD_MIN_LENGTH} caracteres")
    if not re.search(r"[a-z]", password):
        raise WeakPasswordError("La contraseña debe incluir al menos una letra minúscula")
    if not re.search(r"[A-Z]", password):
        raise WeakPasswordError("La contraseña debe incluir al menos una letra mayúscula")
    if not re.search(r"[0-9]", password):
        raise WeakPasswordError("La contraseña debe incluir al menos un número")
    if password.lower() in ("password", "12345678", "qwertyui", "admin123", "changeme"):
        raise WeakPasswordError("La contraseña es demasiado común")


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if salt is None:
        salt = os.urandom(16).hex()
    pwd_hash = _pbkdf2(password, salt, PBKDF2_ITERATIONS)
    return pwd_hash, salt


def _pbkdf2(password: str, salt: str, iterations: int) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    ).hex()
    return f"pbkdf2_sha256${iterations}${digest}"


def verify_password(password: str, pwd_hash: str, salt: str) -> bool:
    """Verifica el hash admitiendo el formato versionado y el legacy (hex plano)."""
    if not pwd_hash or not salt:
        return False
    if pwd_hash.startswith("pbkdf2_sha256$"):
        try:
            _, iterations_str, expected = pwd_hash.split("$", 2)
            iterations = int(iterations_str)
        except (ValueError, IndexError):
            return False
        computed = _pbkdf2(password, salt, iterations)
    else:
        # Legacy: hash hex plano generado con 100000 iteraciones
        computed = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
        ).hex()
    return hmac.compare_digest(computed, pwd_hash)


def get_user_by_email(db, email: str) -> Optional[User]:
    if not email:
        return None
    return db.query(User).filter(User.email == email.strip().lower()).first()

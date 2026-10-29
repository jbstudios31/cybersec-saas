import secrets

from starlette.requests import Request


def generate_csrf_token(request: Request) -> str:
    """Genera un token CSRF y lo guarda en la sesión."""
    token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = token
    return token


def get_csrf_token(request: Request) -> str | None:
    """Devuelve el token CSRF almacenado en la sesión."""
    return request.session.get("csrf_token")


def validate_csrf_token(request: Request, form_token: str | None) -> bool:
    """Valida que el token enviado coincida con el de la sesión."""
    session_token = request.session.get("csrf_token")
    if not session_token or not form_token:
        return False
    return secrets.compare_digest(session_token, form_token)

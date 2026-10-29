from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, get_db
from app.core.jwt import decode_access_token
from app.core.security import get_user_by_email
from app.models.user import User

DbSession = Annotated[Session, Depends(get_db)]
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(request: Request) -> User:
    """Devuelve el usuario autenticado desde la sesión o lanza 401 (para API)."""
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")
    db = SessionLocal()
    try:
        user = db.get(User, user_id)
    finally:
        db.close()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no válido")
    return user


def get_current_user_html(request: Request) -> User | None:
    """Devuelve el usuario autenticado o None (para rutas HTML, sin lanzar excepción)."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    db = SessionLocal()
    try:
        user = db.get(User, user_id)
    finally:
        db.close()
    return user if (user and user.is_active) else None


def require_auth_html(request: Request, user: User | None) -> RedirectResponse | None:
    """Si no hay usuario, devuelve una respuesta de redirect a /login. Si hay, devuelve None."""
    if user is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return None


def get_current_user_jwt(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: DbSession = None,
) -> User:
    """Autentica por JWT Bearer token para la API REST."""
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    user = get_user_by_email(db, email)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no válido")
    return user

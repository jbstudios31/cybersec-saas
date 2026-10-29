import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

from app.core.config import JWT_ALGORITHM, JWT_AUDIENCE, JWT_EXPIRE_MINUTES, JWT_ISSUER, SECRET_KEY


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=JWT_EXPIRE_MINUTES)
    )
    to_encode.update(
        {
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "jti": uuid.uuid4().hex,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "typ": "access",
        }
    )
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
        )
        if payload.get("typ") != "access":
            return None
        return payload
    except JWTError:
        return None

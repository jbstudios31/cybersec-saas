"""Verificación de propiedad del dominio antes de escanear.

El cliente demuestra que controla el dominio publicando un token en DNS (TXT en
``_cybersec-verify.<host>``) o en ``https://<host>/.well-known/cybersec-verify.txt``.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from urllib.parse import urlparse

import dns.resolver
import requests
from fastapi import HTTPException, status

from app.core import config
from app.core.ssrf import UnsafeTargetError, parse_target_url, safe_session, validate_target_url_or_raise

DNS_PREFIX = "_cybersec-verify"
WELL_KNOWN_PATH = "/.well-known/cybersec-verify.txt"


def new_verification_token() -> str:
    return secrets.token_urlsafe(24)


def verification_instructions(url: str, token: str) -> dict:
    _, hostname, _ = parse_target_url(url)
    return {
        "dns": {
            "type": "TXT",
            "name": f"{DNS_PREFIX}.{hostname}",
            "value": f"cybersec-verify={token}",
        },
        "http": {
            "url": f"https://{hostname}{WELL_KNOWN_PATH}",
            "content": token,
        },
    }


def _dns_txt_matches(hostname: str, token: str) -> bool:
    expected = f"cybersec-verify={token}"
    try:
        answers = dns.resolver.resolve(f"{DNS_PREFIX}.{hostname}", "TXT", lifetime=5)
    except Exception:  # noqa: BLE001 - sin registro = no verificado
        return False
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if secrets.compare_digest(txt, expected):
            return True
    return False


def _http_token_matches(url: str, token: str) -> bool:
    netloc = urlparse(url).netloc
    try:
        with safe_session() as session:
            resp = session.get(f"https://{netloc}{WELL_KNOWN_PATH}", timeout=5, allow_redirects=False)
    except requests.RequestException:
        return False
    if resp.status_code != 200:
        return False
    return secrets.compare_digest(resp.text.strip(), token)


def check_domain_ownership(url: str, token: str) -> bool:
    """Comprueba el token por DNS o HTTP. Lanza UnsafeTargetError si el destino no es seguro."""
    validate_target_url_or_raise(url)
    _, hostname, _ = parse_target_url(url)
    return _dns_txt_matches(hostname, token) or _http_token_matches(url, token)


def ensure_verified(target) -> None:
    """Bloquea escaneos de objetivos no verificados cuando la verificación está activa."""
    if config.REQUIRE_TARGET_VERIFICATION and target.verified_at is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verifica la propiedad del dominio antes de escanear",
        )


def mark_verified(target) -> None:
    target.verified_at = datetime.now(UTC)


__all__ = [
    "UnsafeTargetError",
    "check_domain_ownership",
    "ensure_verified",
    "mark_verified",
    "new_verification_token",
    "verification_instructions",
]

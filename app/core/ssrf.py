"""Protección SSRF.

- Solo http/https, sin credenciales en la URL y solo puertos permitidos.
- Toda IP resuelta debe ser pública (``ip.is_global``). Las IPv4 mapeadas en IPv6
  (``::ffff:127.0.0.1``) se evalúan como IPv4.
- La conexión real se hace SIEMPRE a la IP validada (``safe_session``): se resuelve el DNS
  una vez, se comprueba cada IP y se conecta a esa IP, con el hostname solo para SNI y
  verificación del certificado. Así se evitan DNS rebinding y redirects internos.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests
from fastapi import HTTPException, status
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError

from app.core import config

BLOCKED_HOSTNAMES = {"localhost", "local", "localdomain"}
BLOCKED_SUFFIXES = (".localhost", ".local", ".localdomain", ".internal", ".lan", ".home.arpa")


class UnsafeTargetError(ValueError):
    """El destino no es un objetivo público permitido."""


def is_private_ip(ip_str: str) -> bool:
    """True si la IP NO es un destino público seguro."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None:
            ip = ip.sixtofour
        elif ip.teredo is not None:
            return True
    return not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_reserved


def _getaddrinfo(host: str, port: int):
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def check_hostname(hostname: str) -> None:
    host = hostname.lower().rstrip(".")
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        raise UnsafeTargetError("No se permiten nombres de host locales o internos")


def check_port(port: int) -> None:
    if port not in config.ALLOWED_TARGET_PORTS:
        allowed = ", ".join(str(p) for p in sorted(config.ALLOWED_TARGET_PORTS))
        raise UnsafeTargetError(f"Puerto {port} no permitido (permitidos: {allowed})")


def resolve_public_ips(hostname: str, port: int) -> list[str]:
    """Resuelve el host y exige que TODAS las IPs sean públicas. Devuelve las IPs."""
    check_hostname(hostname)
    check_port(port)
    try:
        infos = _getaddrinfo(hostname, port)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"No se pudo resolver el host: {hostname}") from exc
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        if is_private_ip(addr):
            raise UnsafeTargetError(
                f"El host {hostname} resuelve a una dirección privada o local; "
                "no se permiten escaneos internos."
            )
        if addr not in ips:
            ips.append(addr)
    if not ips:
        raise UnsafeTargetError(f"No se pudo resolver el host: {hostname}")
    return ips


def resolve_public_ip(hostname: str, port: int) -> str:
    return resolve_public_ips(hostname, port)[0]


def parse_target_url(url: str):
    """Valida la forma de la URL. Devuelve (parsed, hostname, port)."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTargetError("URL inválida") from exc
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTargetError("Solo se permiten URLs http o https")
    if not parsed.hostname:
        raise UnsafeTargetError("La URL debe incluir un host")
    if parsed.username or parsed.password:
        raise UnsafeTargetError("La URL no puede incluir credenciales")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed, parsed.hostname, port


def validate_target_url_or_raise(url: str) -> None:
    _, hostname, port = parse_target_url(url)
    resolve_public_ips(hostname, port)


def validate_target_url(url: str) -> None:
    """Versión para endpoints FastAPI: lanza HTTPException 400."""
    try:
        validate_target_url_or_raise(url)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


# ---- Conexión fijada a la IP validada ----


def connect_pinned(host: str, port: int, timeout, source_address=None) -> socket.socket:
    """Abre el socket contra una IP pública validada en el momento de conectar."""
    last_exc: OSError | None = None
    for ip in resolve_public_ips(host, port):
        try:
            return socket.create_connection((ip, port), timeout, source_address)
        except OSError as exc:
            last_exc = exc
    raise OSError(f"No se pudo conectar a {host}:{port}") from last_exc


class _PinnedHTTPConnection(HTTPConnection):
    def _new_conn(self):
        try:
            return connect_pinned(self._dns_host, self.port, self.timeout, self.source_address)
        except (UnsafeTargetError, OSError) as exc:
            raise NewConnectionError(self, str(exc)) from exc


class _PinnedHTTPSConnection(HTTPSConnection):
    def _new_conn(self):
        try:
            return connect_pinned(self._dns_host, self.port, self.timeout, self.source_address)
        except (UnsafeTargetError, OSError) as exc:
            raise NewConnectionError(self, str(exc)) from exc


class _PinnedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _PinnedHTTPPool, "https": _PinnedHTTPSPool}


def safe_session() -> requests.Session:
    """Sesión HTTP que solo conecta a IPs públicas validadas. Usar como context manager."""
    session = requests.Session()
    session.trust_env = False  # sin proxies del entorno: la conexión debe ir directa
    adapter = _PinnedAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

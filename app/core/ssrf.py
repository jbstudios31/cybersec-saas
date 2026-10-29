import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import HTTPException, status

# Rangos de IP privada y reservada (RFC 1918, RFC 5735, RFC 4193, etc.)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),      # localhost
    ipaddress.ip_network("::1/128"),           # localhost IPv6
    ipaddress.ip_network("fc00::/7"),          # unique local IPv6
    ipaddress.ip_network("fe80::/10"),         # link-local IPv6
    ipaddress.ip_network("169.254.0.0/16"),    # link-local IPv4 (AWS metadata)
    ipaddress.ip_network("0.0.0.0/8"),         # "this network"
    ipaddress.ip_network("240.0.0.0/4"),       # reserved
]

BLOCKED_HOSTNAMES = {"localhost", "local", "localdomain"}


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # Si no se puede parsear, tratamos como inseguro
    # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1) must be checked as IPv4
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in net for net in PRIVATE_NETWORKS)


def validate_target_url(url: str) -> None:
    """Valida que la URL sea un objetivo público seguro para escanear.
    Lanza HTTPException 400 si la URL apunta a redes privadas/localhost."""
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL inválida",
        ) from exc

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Solo se permiten URLs http o https",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La URL debe incluir un host",
        )

    if hostname.lower() in BLOCKED_HOSTNAMES or hostname.lower().endswith((".localhost", ".local", ".localdomain")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se permiten nombres de host locales (localhost)",
        )

    # Resolver DNS y verificar cada IP resuelta
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No se pudo resolver el host: {hostname}",
        ) from exc

    resolved_ips = set()
    for info in infos:
        addr = info[4][0]
        resolved_ips.add(addr)

    for ip_str in resolved_ips:
        if is_private_ip(ip_str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"El host {hostname} resuelve a una IP privada o local ({ip_str}). No se permiten escaneos internos.",
            )

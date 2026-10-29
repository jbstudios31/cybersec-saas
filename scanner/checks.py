from __future__ import annotations

import datetime as _dt
import socket
import ssl
import warnings
from typing import Any

import requests

from app.core.ssrf import parse_target_url, resolve_public_ip, safe_session

# Cabecera -> (severidad si falta, por qué importa, cómo corregirlo).
# No se evalúa COEP: solo aplica a páginas con aislamiento cross-origin y exigirla
# rompería sitios que cargan recursos de terceros (fuentes, CDN).
HEADER_INFO = {
    "content-security-policy": (
        "medium",
        "Sin una política de seguridad de contenido, un script inyectado en la página puede ejecutarse sin restricciones.",
        "Define Content-Security-Policy con una lista de orígenes permitidos, por ejemplo default-src 'self'.",
    ),
    "x-frame-options": (
        "medium",
        "Otro sitio puede mostrar tu página dentro de un marco y engañar al usuario para que haga clic (clickjacking).",
        "Envía X-Frame-Options: DENY o usa frame-ancestors en la política CSP.",
    ),
    "x-content-type-options": (
        "medium",
        "El navegador puede interpretar un archivo con un tipo distinto al declarado y ejecutarlo como código.",
        "Envía X-Content-Type-Options: nosniff.",
    ),
    "strict-transport-security": (
        "medium",
        "Sin HSTS, un atacante en la red puede forzar al usuario a usar HTTP y leer o modificar el tráfico.",
        "Envía Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    ),
    "referrer-policy": (
        "low",
        "Las URL internas pueden filtrarse a otros sitios a través de la cabecera Referer.",
        "Envía Referrer-Policy: strict-origin-when-cross-origin.",
    ),
    "permissions-policy": (
        "low",
        "El sitio no limita el acceso a funciones del navegador como cámara, micrófono o geolocalización.",
        "Envía Permissions-Policy con las funciones desactivadas, por ejemplo camera=(), microphone=(), geolocation=().",
    ),
    "cross-origin-opener-policy": (
        "low",
        "Otras ventanas abiertas desde tu sitio pueden conservar una referencia a tu página.",
        "Envía Cross-Origin-Opener-Policy: same-origin.",
    ),
    "cross-origin-resource-policy": (
        "low",
        "Otros sitios pueden incrustar tus recursos sin restricción.",
        "Envía Cross-Origin-Resource-Policy: same-origin, o same-site si compartes recursos entre subdominios.",
    ),
}
SECURITY_HEADERS = {name: info[0] for name, info in HEADER_INFO.items()}

COMMON_PATHS = [
    "/.env",
    "/admin",
    "/phpinfo.php",
    "/.git/config",
    "/wp-config.php",
    "/server-status",
    "/.htaccess",
    "/config.json",
    "/.svn/entries",
]


def missing_header_findings(present: set[str]) -> list[dict[str, Any]]:
    return [
        {
            "severity": severity,
            "title": f"Falta la cabecera {header}",
            "description": why,
            "remediation": fix,
        }
        for header, (severity, why, fix) in HEADER_INFO.items()
        if header not in present
    ]


def check_headers(url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    with safe_session() as session:
        try:
            resp = session.get(url, timeout=10, allow_redirects=False)
        except requests.RequestException as exc:
            findings.append(
                {
                    "severity": "high",
                    "title": "El objetivo no responde",
                    "description": f"No se pudo conectar con {url}: {exc}",
                    "remediation": "Comprueba que la URL sea pública y que el sitio esté en línea.",
                }
            )
            return findings

        findings.extend(missing_header_findings({h.lower() for h in resp.headers.keys()}))

        set_cookie = resp.headers.get("set-cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Cookie sin la bandera HttpOnly",
                        "description": "Un script de la página puede leer esta cookie, por lo que un ataque XSS podría robar la sesión.",
                        "remediation": "Marca las cookies de sesión con HttpOnly.",
                    }
                )
            if "secure" not in set_cookie.lower() and url.startswith("https://"):
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Cookie sin la bandera Secure en un sitio HTTPS",
                        "description": "El navegador puede enviar esta cookie por una conexión sin cifrar, donde un atacante podría leerla.",
                        "remediation": "Marca las cookies con Secure cuando el sitio se sirva por HTTPS.",
                    }
                )
            if "samesite" not in set_cookie.lower():
                findings.append(
                    {
                        "severity": "low",
                        "title": "Cookie sin el atributo SameSite",
                        "description": "La cookie se envía también en peticiones iniciadas desde otros sitios, lo que facilita ataques CSRF.",
                        "remediation": "Define SameSite=Lax o SameSite=Strict en las cookies.",
                    }
                )

        try:
            opts = session.options(url, timeout=5, allow_redirects=False)
            allow = opts.headers.get("allow", "")
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow.upper()]
            if dangerous:
                findings.append(
                    {
                        "severity": "medium",
                        "title": f"Métodos HTTP peligrosos habilitados: {', '.join(dangerous)}",
                        "description": f"El servidor acepta los métodos {', '.join(dangerous)}, que permiten modificar o inspeccionar recursos.",
                        "remediation": "Deshabilita los métodos HTTP que la aplicación no necesite.",
                    }
                )
        except requests.RequestException:
            pass
    return findings


def _certificate_findings(hostname: str, ip: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ctx = ssl.create_default_context()
    with socket.create_connection((ip, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            not_after = cert.get("notAfter")
            if not_after:
                expiry = _dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (expiry - _dt.datetime.now(_dt.UTC).replace(tzinfo=None)).days
                if days < 0:
                    findings.append(
                        {
                            "severity": "critical",
                            "title": "Certificado TLS vencido",
                            "description": f"El certificado de {hostname} venció el {not_after}. Los navegadores muestran una advertencia de seguridad a tus visitantes.",
                            "remediation": "Renueva el certificado TLS y configura la renovación automática.",
                        }
                    )
                elif days < 30:
                    findings.append(
                        {
                            "severity": "high",
                            "title": "El certificado TLS vence pronto",
                            "description": f"El certificado de {hostname} vence en {days} días.",
                            "remediation": "Renueva el certificado antes de que venza o activa la renovación automática.",
                        }
                    )
    return findings


def _old_tls_version(hostname: str, ip: str) -> str | None:
    """Devuelve la primera versión TLS obsoleta aceptada por el servidor, o None."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for version in ["TLSv1", "TLSv1.1"]:
            try:
                ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_old.check_hostname = False  # solo medimos el protocolo; la validez se mide arriba
                ctx_old.verify_mode = ssl.CERT_NONE
                ctx_old.minimum_version = ssl.TLSVersion.TLSv1
                ctx_old.maximum_version = ssl.TLSVersion.TLSv1 if version == "TLSv1" else ssl.TLSVersion.TLSv1_1
                with socket.create_connection((ip, 443), timeout=5) as sock:
                    with ctx_old.wrap_socket(sock, server_hostname=hostname):
                        return version
            except (OSError, ssl.SSLError):
                continue
    return None


def check_ssl(hostname: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not hostname:
        return findings
    try:
        # Se resuelve y valida una vez; todas las conexiones TLS van a esa IP pública.
        ip = resolve_public_ip(hostname, 443)
        findings.extend(_certificate_findings(hostname, ip))
        old = _old_tls_version(hostname, ip)
        if old:
            findings.append(
                {
                    "severity": "high",
                    "title": f"El servidor acepta una versión de TLS obsoleta: {old}",
                    "description": f"{old} tiene debilidades conocidas y los navegadores modernos ya no lo usan.",
                    "remediation": f"Desactiva {old} y exige TLS 1.2 o superior.",
                }
            )
    except Exception:  # noqa: BLE001 - network errors are expected
        findings.append(
            {
                "severity": "low",
                "title": "No se pudo revisar el certificado TLS",
                "description": f"No fue posible obtener el certificado de {hostname} por el puerto 443.",
                "remediation": "Comprueba que el puerto 443 esté abierto y que haya un certificado válido instalado.",
            }
        )
    return findings


def check_common_paths(url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base = url.rstrip("/")
    with safe_session() as session:
        for path in COMMON_PATHS:
            try:
                resp = session.get(base + path, timeout=5, allow_redirects=False)
            except requests.RequestException:
                continue
            if resp.status_code in (200, 301, 302, 401, 403):
                findings.append(
                    {
                        "severity": "medium",
                        "title": f"Ruta expuesta: {path}",
                        "description": f"La ruta {path} respondió con HTTP {resp.status_code}. Puede revelar configuración, credenciales o código fuente.",
                        "remediation": f"Bloquea el acceso público a {path} o elimínala del servidor.",
                    }
                )
    return findings


def scan_target(url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    _, hostname, _ = parse_target_url(url)
    findings.extend(check_headers(url))
    findings.extend(check_ssl(hostname))
    findings.extend(check_common_paths(url))
    return findings

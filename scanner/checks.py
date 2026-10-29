from __future__ import annotations

import datetime as _dt
import socket
import ssl
import warnings
from typing import Any

import requests

from app.core.ssrf import parse_target_url, resolve_public_ip, safe_session

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]

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


def check_headers(url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    with safe_session() as session:
        try:
            resp = session.get(url, timeout=10, allow_redirects=False)
        except requests.RequestException as exc:
            findings.append(
                {
                    "severity": "high",
                    "title": "Target unreachable",
                    "description": f"Could not connect to {url}: {exc}",
                    "remediation": "Verify the target URL is public and reachable.",
                }
            )
            return findings

        present = {h.lower() for h in resp.headers.keys()}
        for header in SECURITY_HEADERS:
            if header not in present:
                findings.append(
                    {
                        "severity": "medium",
                        "title": f"Missing security header: {header}",
                        "description": f"The response does not include the {header} header.",
                        "remediation": f"Configure the server to send {header}.",
                    }
                )

        set_cookie = resp.headers.get("set-cookie", "")
        if set_cookie:
            if "httponly" not in set_cookie.lower():
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Cookie without HttpOnly flag",
                        "description": "A session cookie was set without the HttpOnly flag.",
                        "remediation": "Set HttpOnly on all session cookies.",
                    }
                )
            if "secure" not in set_cookie.lower() and url.startswith("https://"):
                findings.append(
                    {
                        "severity": "medium",
                        "title": "Cookie without Secure flag over HTTPS",
                        "description": "A session cookie was set without the Secure flag on an HTTPS site.",
                        "remediation": "Set Secure on all cookies when serving over HTTPS.",
                    }
                )
            if "samesite" not in set_cookie.lower():
                findings.append(
                    {
                        "severity": "low",
                        "title": "Cookie without SameSite attribute",
                        "description": "A cookie was set without the SameSite attribute.",
                        "remediation": "Set SameSite=Lax or Strict on cookies.",
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
                        "title": f"Dangerous HTTP methods enabled: {', '.join(dangerous)}",
                        "description": f"The server allows {', '.join(dangerous)} methods.",
                        "remediation": "Disable unnecessary HTTP methods.",
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
                            "title": "SSL certificate expired",
                            "description": f"Certificate for {hostname} expired on {not_after}.",
                            "remediation": "Renew the SSL/TLS certificate.",
                        }
                    )
                elif days < 30:
                    findings.append(
                        {
                            "severity": "high",
                            "title": "SSL certificate expires soon",
                            "description": f"Certificate for {hostname} expires in {days} days.",
                            "remediation": "Renew the SSL/TLS certificate before expiration.",
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
                    "title": f"Insecure TLS version supported: {old}",
                    "description": f"The server supports {old}, which is deprecated.",
                    "remediation": f"Disable {old} and use TLS 1.2 or higher.",
                }
            )
    except Exception:  # noqa: BLE001 - network errors are expected
        findings.append(
            {
                "severity": "low",
                "title": "SSL check unavailable",
                "description": f"Could not retrieve certificate for {hostname}",
                "remediation": "Ensure port 443 is reachable and a valid certificate is installed.",
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
                        "title": f"Exposed path: {path}",
                        "description": f"Path {path} responded with HTTP {resp.status_code}.",
                        "remediation": f"Restrict or remove {path} from public access.",
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

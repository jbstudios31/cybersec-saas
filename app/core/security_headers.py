"""Cabeceras de seguridad de las respuestas de la propia app.

La CSP es estricta (sin 'unsafe-inline' ni 'unsafe-eval'): el CSS y el JS se sirven desde
/static (ver scripts/build-css.sh). Las fuentes también se sirven desde /static: no hay recursos de terceros.
No se envía COEP: exigiría que cualquier recurso externo declare CORP/CORS.
"""

from __future__ import annotations

CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "font-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)

PERMISSIONS_POLICY = ", ".join(
    f"{feature}=()"
    for feature in (
        "accelerometer",
        "camera",
        "geolocation",
        "gyroscope",
        "magnetometer",
        "microphone",
        "payment",
        "usb",
    )
)

BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": PERMISSIONS_POLICY,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

# Swagger/ReDoc (solo con DOCS_ENABLED) cargan JS inline y de un CDN: se excluyen de la CSP.
CSP_EXEMPT_PATHS = ("/docs", "/redoc")


def apply_security_headers(response, path: str, hsts: bool) -> None:
    for name, value in BASE_HEADERS.items():
        response.headers[name] = value
    if not path.startswith(CSP_EXEMPT_PATHS):
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    if hsts:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

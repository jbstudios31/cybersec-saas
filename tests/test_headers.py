import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from scanner.checks import SECURITY_HEADERS, missing_header_findings

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "app" / "templates"
CSS = (ROOT / "app" / "static" / "app.css").read_text()


def test_responses_include_security_headers():
    client = TestClient(app)
    for path in ("/login", "/health", "/ruta-inexistente"):
        headers = client.get(path).headers
        for name in (
            "content-security-policy",
            "permissions-policy",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
        ):
            assert name in headers, f"{name} falta en {path}"


def test_csp_is_strict():
    csp = TestClient(app).get("/login").headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp
    assert "cdn.tailwindcss.com" not in csp
    assert "googleapis" not in csp and "gstatic" not in csp
    assert "style-src 'self';" in csp and "font-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_app_passes_its_own_header_scan():
    headers = {h.lower() for h in TestClient(app).get("/login").headers.keys()}
    # HSTS solo se envía en producción (ENV=production); el resto debe estar siempre.
    missing = [f["title"] for f in missing_header_findings(headers) if "strict-transport-security" not in f["title"]]
    assert missing == []


def test_coep_is_not_required_by_scanner():
    assert "cross-origin-embedder-policy" not in SECURITY_HEADERS
    assert all(f["severity"] in ("low", "medium") for f in missing_header_findings(set()))


def test_static_assets_are_served():
    client = TestClient(app)
    assert client.get("/static/app.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_templates_have_no_inline_code_or_external_scripts():
    for path in TEMPLATES.rglob("*.html"):
        html = path.read_text()
        assert not re.search(r"\son[a-z]+\s*=", html), f"handler inline en {path.name}"
        assert not re.search(r"<script(?![^>]*\ssrc=)", html), f"script inline en {path.name}"
        assert "<style" not in html, f"bloque <style> en {path.name}"
        assert ' style="' not in html, f"atributo style en {path.name}"
        for src in re.findall(r'<script[^>]*\ssrc="([^"]+)"', html):
            assert src.startswith("/static/"), f"script externo en {path.name}: {src}"


def _escape(token: str) -> str:
    return re.sub(r"([:/.\[\]%#,()!@])", r"\\\1", token)


def test_compiled_css_contains_template_classes():
    """Evita olvidar `scripts/build-css.sh` tras cambiar clases de Tailwind en las plantillas."""
    missing = set()
    for path in TEMPLATES.rglob("*.html"):
        html = re.sub(r"\{%.*?%\}|\{\{.*?\}\}", " ", path.read_text(), flags=re.S)
        for value in re.findall(r'class="([^"]*)"', html):
            for token in value.split():
                if token.endswith("-") or token in {"inline", "block"}:
                    continue
                if f".{_escape(token)}" not in CSS and f".{_escape(token)}{{" not in CSS:
                    missing.add(token)
    assert not missing, f"Clases sin compilar (ejecuta scripts/build-css.sh): {sorted(missing)}"

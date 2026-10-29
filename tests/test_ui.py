import re
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from app.core.database import SessionLocal, engine
from app.core.security import hash_password
from app.main import app, filtro_conteo_abiertos, filtro_fecha, filtro_por_severidad
from app.models.base import Base
from app.models.finding import Finding
from app.models.scan_run import ScanRun
from app.models.target import Target
from app.models.user import User
from app.reports import build_pdf_report


def setup_function(function):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    for model in (Finding, ScanRun, Target, User):
        db.query(model).delete()
    db.commit()
    for email, pwd, admin in (("admin@test.local", "admin123", True), ("cliente@test.local", "cliente123", False)):
        h, s = hash_password(pwd)
        db.add(User(email=email, password_hash=h, password_salt=s, is_admin=admin, is_active=True))
    db.commit()
    db.close()


def teardown_function(function):
    Base.metadata.drop_all(bind=engine)


def login(email, password):
    client = TestClient(app)
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    client.post("/login", data={"email": email, "password": password, "csrf_token": token}, follow_redirects=False)
    return client


def _seed():
    db = SessionLocal()
    quiet = Target(name="Sitio tranquilo", url="https://tranquilo.example.com", owner_id=2)
    risky = Target(name="Tienda en línea", url="https://tienda.example.com", owner_id=2)
    db.add_all([quiet, risky])
    db.commit()
    scan = ScanRun(target_id=risky.id, status="done", started_at=datetime(2026, 10, 29, 3, 38, tzinfo=UTC))
    db.add(scan)
    db.commit()
    db.add_all([
        Finding(scan_run_id=scan.id, severity="low", title="Aviso menor", description="d", remediation="r"),
        Finding(scan_run_id=scan.id, severity="critical", title="Certificado TLS vencido", description="d", remediation="r"),
        Finding(scan_run_id=scan.id, severity="high", title="Resuelto ya", description="d", remediation="r", status="resolved"),
    ])
    db.commit()
    ids = (quiet.id, risky.id)
    db.close()
    return ids


def test_dashboard_orders_by_risk_and_summarizes_in_spanish():
    quiet_id, risky_id = _seed()
    html = login("cliente@test.local", "cliente123").get("/").text
    assert html.index("Tienda en línea") < html.index("Sitio tranquilo")
    assert "1 hallazgo crítico abierto" in html
    assert f'href="/targets/{risky_id}/view">Tienda en línea</a>' in html  # enlace en el resumen
    assert "1 crítico" in html and "1 bajo" in html
    assert "Resuelto ya" not in html
    assert "Sin escanear" in html


def test_empty_dashboard_has_helpful_copy():
    html = login("cliente@test.local", "cliente123").get("/").text
    assert "Todavía no hay objetivos" in html
    admin_html = login("admin@test.local", "admin123").get("/").text
    assert 'href="/admin"' in admin_html and "Registra el primer sitio" in admin_html


def test_target_page_lists_findings_by_severity_with_fixes():
    _, risky_id = _seed()
    html = login("cliente@test.local", "cliente123").get(f"/targets/{risky_id}/view").text
    assert html.index("Certificado TLS vencido") < html.index("Aviso menor")
    assert "Cómo corregirlo." in html
    assert 'commandfor="dlg-scan"' in html and "<dialog" in html
    assert "Resuelto" in html  # estado del hallazgo ya resuelto
    assert 'aria-current="page"' in html


def test_admin_page_uses_labeled_fields_and_owner_select():
    _seed()
    html = login("admin@test.local", "admin123").get("/admin").text
    assert 'for="nu-email"' in html and 'for="nt-owner"' in html
    assert "cliente@test.local" in html  # el propietario se muestra como correo, no como ID
    assert "Administración" in html


def test_pages_have_basic_accessibility_structure():
    _, risky_id = _seed()
    admin = login("admin@test.local", "admin123")
    pages = {
        "/login": TestClient(app).get("/login").text,
        "/": admin.get("/").text,
        f"/targets/{risky_id}/view": admin.get(f"/targets/{risky_id}/view").text,
        "/admin": admin.get("/admin").text,
    }
    for path, html in pages.items():
        assert '<html lang="es">' in html, path
        assert len(re.findall(r"<h1[ >]", html)) == 1, f"{path}: debe haber un solo h1"
        assert len(re.findall(r"<main[ >]", html)) == 1, path
        assert 'class="skip-link"' in html, path
        for input_tag in re.findall(r"<(?:input|select)[^>]*>", html):
            if 'type="hidden"' in input_tag:
                continue
            input_id = re.search(r'id="([^"]+)"', input_tag)
            assert input_id and f'for="{input_id.group(1)}"' in html, f"{path}: campo sin label: {input_tag}"


def test_login_form_follows_autofill_guidance():
    html = TestClient(app).get("/login").text
    assert 'autocomplete="username"' in html and 'autocomplete="current-password"' in html
    assert 'data-toggle-password="password"' in html


def test_error_pages_use_the_app_layout():
    resp = login("cliente@test.local", "cliente123").get("/targets/9999/view")
    assert resp.status_code == 404
    assert "<h1>No encontrado</h1>" in resp.text and 'class="skip-link"' in resp.text


def test_filters():
    assert filtro_fecha(datetime(2026, 10, 29, 3, 38, tzinfo=UTC)) == "28 oct 2026, 23:38"  # UTC-4
    assert filtro_fecha(None) == "—"

    class F:
        def __init__(self, id, severity, status="pending"):
            self.id, self.severity, self.status = id, severity, status

    ordered = filtro_por_severidad([F(1, "low"), F(2, "critical"), F(3, "high")])
    assert [f.severity for f in ordered] == ["critical", "high", "low"]
    counts = filtro_conteo_abiertos([F(1, "high"), F(2, "high", "resolved"), F(3, "low", "false_positive")])
    assert counts == {"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1}


def test_pdf_report_escapes_markup_and_orders_findings():
    pdf = build_pdf_report(
        "<b>Mi sitio</b> & Cía",
        "https://ejemplo.com/?a=1&b=2",
        1,
        [
            {"severity": "low", "title": "Menor <i>x</i>", "description": "d", "remediation": "r"},
            {"severity": "critical", "title": "Grave", "description": "d", "remediation": "r"},
        ],
    )
    assert pdf.startswith(b"%PDF")
    assert build_pdf_report("X", "https://x.com", 1, []).startswith(b"%PDF")

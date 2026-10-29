import re
from datetime import UTC

import pytest
from fastapi.testclient import TestClient

from app.core import config
from app.core.database import SessionLocal, engine
from app.core.security import hash_password
from app.core.ssrf import UnsafeTargetError, is_private_ip, parse_target_url
from app.main import app
from app.models.base import Base
from app.models.target import Target
from app.models.user import User


def setup_function(function):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(Target).delete()
    db.query(User).delete()
    db.commit()
    h, s = hash_password("admin123")
    db.add(User(email="admin@test.local", password_hash=h, password_salt=s, is_admin=True, is_active=True))
    h2, s2 = hash_password("cliente123")
    db.add(User(email="cliente@test.local", password_hash=h2, password_salt=s2, is_admin=False, is_active=True))
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


# ---- SSRF: clasificación de IPs ----

@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
     "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "2002:7f00:0001::1"],
)
def test_private_ips_are_blocked(ip):
    assert is_private_ip(ip)


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_ips_are_allowed(ip):
    assert not is_private_ip(ip)


def test_url_with_credentials_is_rejected():
    with pytest.raises(UnsafeTargetError):
        parse_target_url("https://user:pass@example.com")


def test_port_not_allowed_is_rejected():
    client = login("admin@test.local", "admin123")
    resp = client.post("/targets", json={"name": "ssh", "url": "https://example.com:22", "owner_id": 1})
    assert resp.status_code == 400


def test_ipv4_mapped_ipv6_literal_is_rejected():
    client = login("admin@test.local", "admin123")
    resp = client.post("/targets", json={"name": "mapped", "url": "http://[::ffff:127.0.0.1]/", "owner_id": 1})
    assert resp.status_code == 400


# ---- Paginación acotada ----

def test_page_size_is_bounded():
    client = login("admin@test.local", "admin123")
    assert client.get("/targets?page_size=100000").status_code == 422
    assert client.get("/targets?page=0").status_code == 422
    assert client.get("/targets?page_size=10").status_code == 200


# ---- Verificación de propiedad del dominio ----

def _create_target(owner_id=2, url="https://example.com"):
    db = SessionLocal()
    t = Target(name="T", url=url, owner_id=owner_id)
    db.add(t)
    db.commit()
    tid = t.id
    db.close()
    return tid


def test_verification_token_flow(monkeypatch):
    tid = _create_target()
    client = login("cliente@test.local", "cliente123")

    resp = client.post(f"/targets/{tid}/verification")
    assert resp.status_code == 200
    body = resp.json()
    assert body["verified"] is False
    token = body["instructions"]["http"]["content"]
    assert len(token) >= 20
    assert body["instructions"]["dns"]["name"] == "_cybersec-verify.example.com"

    # El mismo token se reutiliza en la siguiente petición
    assert client.post(f"/targets/{tid}/verification").json()["instructions"]["http"]["content"] == token

    # Sin prueba de propiedad: rechazado
    monkeypatch.setattr("app.api.routes.check_domain_ownership", lambda url, tok: False)
    assert client.post(f"/targets/{tid}/verify").status_code == 400

    # Con prueba de propiedad: verificado
    monkeypatch.setattr("app.api.routes.check_domain_ownership", lambda url, tok: True)
    assert client.post(f"/targets/{tid}/verify").json() == {"verified": True}
    assert client.post(f"/targets/{tid}/verification").json()["verified"] is True


def test_scan_blocked_when_verification_required(monkeypatch):
    tid = _create_target()
    monkeypatch.setattr(config, "REQUIRE_TARGET_VERIFICATION", True)
    client = login("cliente@test.local", "cliente123")
    resp = client.post(f"/targets/{tid}/scan")
    assert resp.status_code == 403
    assert "Verifica la propiedad" in resp.json()["detail"]


def test_scan_allowed_after_verification(monkeypatch):
    tid = _create_target()
    monkeypatch.setattr(config, "REQUIRE_TARGET_VERIFICATION", True)
    db = SessionLocal()
    from datetime import datetime
    t = db.get(Target, tid)
    t.verified_at = datetime.now(UTC)
    db.commit()
    db.close()
    client = login("cliente@test.local", "cliente123")
    assert client.post(f"/targets/{tid}/scan").status_code == 202


# ---- PDF: nombre de archivo sin datos del usuario ----

def test_report_filename_is_safe():
    tid = _create_target(url="https://example.com")
    db = SessionLocal()
    db.get(Target, tid).name = 'Mi "obj"\r\nX-Injected: 1'
    db.commit()
    db.close()
    client = login("cliente@test.local", "cliente123")
    client.post(f"/targets/{tid}/scan")
    resp = client.get(f"/targets/{tid}/report")
    assert resp.status_code == 200
    assert resp.headers["content-disposition"] == f'attachment; filename="reporte-target-{tid}.pdf"'

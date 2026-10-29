from fastapi.testclient import TestClient

from app.core.database import SessionLocal, engine
from app.core.security import hash_password
from app.main import app
from app.models.base import Base
from app.models.scan_run import ScanRun
from app.models.target import Target
from app.models.user import User


def setup_function(function):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    db.query(Target).delete()
    db.query(User).delete()
    db.commit()
    pw_hash, pw_salt = hash_password("admin123")
    admin = User(
        email="admin@test.local",
        password_hash=pw_hash,
        password_salt=pw_salt,
        is_admin=True,
        is_active=True,
    )
    db.add(admin)
    db.commit()
    db.close()


def teardown_function(function):
    Base.metadata.drop_all(bind=engine)


def test_scan_next_requires_token(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config, "CRON_TOKEN", "secreto")
    client = TestClient(app)
    resp = client.post("/cron/scan-next", headers={"X-Cron-Token": "malo"})
    assert resp.status_code == 401


def test_scan_next_disabled_without_token(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config, "CRON_TOKEN", "")
    client = TestClient(app)
    resp = client.post("/cron/scan-next", headers={"X-Cron-Token": "secreto"})
    assert resp.status_code == 401


def test_scan_next_scans_target(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config, "CRON_TOKEN", "secreto")

    db = SessionLocal()
    t = Target(name="Cron Target", url="https://example.com", owner_id=1)
    db.add(t)
    db.commit()
    target_id = t.id
    db.close()

    client = TestClient(app)
    resp = client.post("/cron/scan-next", headers={"X-Cron-Token": "secreto"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["scanned"] is True
    assert body["target_id"] == target_id

    db = SessionLocal()
    scans = db.query(ScanRun).filter(ScanRun.target_id == target_id).all()
    assert len(scans) == 1
    assert scans[0].status == "done"
    db.close()


def test_scan_next_no_targets(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config, "CRON_TOKEN", "secreto")
    client = TestClient(app)
    resp = client.post("/cron/scan-next", headers={"X-Cron-Token": "secreto"})
    assert resp.status_code == 200
    assert resp.json()["scanned"] is False


def test_trigger_scan_sync_fallback(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config, "SCAN_ASYNC", False)

    db = SessionLocal()
    t = Target(name="Sync Fallback", url="https://example.com", owner_id=1)
    db.add(t)
    db.commit()
    target_id = t.id
    db.close()

    client = TestClient(app)
    # login para obtener sesión de admin
    import re
    resp = client.get("/login", follow_redirects=False)
    match = re.search(r'name="csrf_token" value="([^"]+)"', resp.text)
    client.post("/login", data={"email": "admin@test.local", "password": "admin123", "csrf_token": match.group(1)}, follow_redirects=False)

    resp = client.post(f"/targets/{target_id}/scan", follow_redirects=False)
    assert resp.status_code == 202
    body = resp.json()
    assert body["accepted"] is True
    assert body["target_id"] == target_id
    assert "scan" in body
    assert "scan_id" in body["scan"] or "error" in body["scan"]

    db = SessionLocal()
    scans = db.query(ScanRun).filter(ScanRun.target_id == target_id).all()
    assert len(scans) == 1
    assert scans[0].status == "done"
    db.close()

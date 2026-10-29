from fastapi.testclient import TestClient

from app.core.database import SessionLocal, engine
from app.core.security import hash_password
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


def client_logged_in(email: str, password: str) -> TestClient:
    client = TestClient(app)
    resp = client.post("/login", data={"email": email, "password": password})
    assert resp.status_code in (302, 200)
    return client


def test_health():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_scan_checks_returns_list():
    from scanner.checks import scan_target

    result = scan_target("https://example.com")
    assert isinstance(result, list)
    for f in result:
        assert f["severity"] in ("low", "medium", "high", "critical")
        assert "title" in f
        assert "description" in f
        assert "remediation" in f

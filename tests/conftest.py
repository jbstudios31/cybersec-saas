import os
import tempfile

# Base de datos aislada para los tests: nunca toca la BD de desarrollo/producción.
_TEST_DB = os.path.join(tempfile.gettempdir(), "cybersec_test.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"
os.environ.setdefault("ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("SCAN_ASYNC", "true")
os.environ.pop("ADMIN_EMAIL", None)
os.environ.pop("ADMIN_PASSWORD", None)

from worker.celery_app import celery_app

celery_app.conf.broker_url = "memory://"
celery_app.conf.result_backend = "cache+memory://"
celery_app.conf.task_always_eager = True
celery_app.conf.task_eager_propagates = True


# ---- Red simulada: los tests no dependen de DNS ni de Internet ----
import ipaddress  # noqa: E402
import socket  # noqa: E402

import app.core.ssrf as _ssrf  # noqa: E402

_FAKE_PUBLIC_IP = "93.184.216.34"
_real_create_connection = socket.create_connection


def _fake_getaddrinfo(host, port, *args, **kwargs):
    try:
        ipaddress.ip_address(host)
        ip = host  # las IP literales se devuelven tal cual (privadas se rechazan)
    except ValueError:
        ip = _FAKE_PUBLIC_IP
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


def _fake_create_connection(address, *args, **kwargs):
    if address[0] == _FAKE_PUBLIC_IP:
        raise ConnectionRefusedError("test: sin red")  # falla rápido, sin salir a Internet
    return _real_create_connection(address, *args, **kwargs)


_ssrf._getaddrinfo = _fake_getaddrinfo
socket.create_connection = _fake_create_connection

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

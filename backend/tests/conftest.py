import os
import tempfile

# ---------------------------------------------------------------------------
# Phase 1 test isolation.
#
# The application reads DATABASE_URL / SIMULATION_MODE / CORS_ORIGINS into
# module-level singletons (app.config.settings, database.connection.engine)
# at import time. So the environment MUST be prepared before any app module is
# imported, which is why the os.environ assignments below come first.
#
# Every test run uses a throwaway SQLite database created under the system
# temp directory. The development database (backend/cyberagent.db) is never
# opened by tests.
# ---------------------------------------------------------------------------
_TMP_DB_DIR = tempfile.mkdtemp(prefix="cyberagent_test_")
_TMP_DB = os.path.join(_TMP_DB_DIR, "test.db").replace(os.sep, "/")

os.environ["DATABASE_URL"] = f"sqlite:///{_TMP_DB}"
os.environ["SIMULATION_MODE"] = "true"
os.environ["CORS_ORIGINS"] = "http://localhost:5173,http://127.0.0.1:5173"
# Phase 12 continuous-assessment loop must never fire inside tests; the ticker
# remains explicitly opt-in and is exercised through deterministic unit calls.
os.environ["SCHEDULER_ENABLED"] = "false"

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from app.main import app
from database.connection import SessionLocal, engine

# backend/ is the parent of backend/tests/
BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="session", autouse=True)
def migrated_database():
    """Apply the real Alembic migration chain to the throwaway database.

    This guarantees the schema the app and the tests run against is exactly
    the one produced by 'alembic upgrade head'.
    """
    cfg = Config(os.path.join(BACKEND_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_ROOT, "alembic"))
    command.upgrade(cfg, "head")
    yield


@pytest.fixture(scope="session")
def client():
    """TestClient with lifespan startup enabled (verify_schema + seed_defaults).

    Using the context manager is required so the app's startup handlers run,
    mirroring how the real server boots.
    """
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def session():
    """Direct SQLAlchemy session bound to the throwaway test database."""
    s = SessionLocal()
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Auth helpers for Phase 2 tests.  Every resource endpoint now requires an
# authenticated session, so tests build real users through the public API to
# avoid coupling test logic to a hardcoded identity.
# ---------------------------------------------------------------------------
def register_user(client, email, password="StrongPass123!"):
    resp = client.post("/auth/register", json={"email": email, "password": password})
    assert resp.status_code == 201, resp.text
    return resp.json()


def login_user(client, email, password="StrongPass123!"):
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {"Authorization": f"Bearer {data['token']}"}


@pytest.fixture(scope="session")
def auth_headers(client):
    email = "owner@test.local"
    register_user(client, email)
    return login_user(client, email)


@pytest.fixture(scope="session")
def other_auth_headers(client):
    email = "other@test.local"
    register_user(client, email)
    return login_user(client, email)


@pytest.fixture(scope="session")
def admin_headers(client):
    """Admin created via the config-driven bootstrap path, exercised in-process."""
    from app.core.security import hash_password
    from database.connection import SessionLocal
    from database.models import User

    email = "admin@test.local"
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == email).first()
        if admin is None:
            admin = User(id="admin-admin@test.local", email=email,
                         password_hash=hash_password("AdminPass123!"), role="admin")
            db.add(admin)
            db.commit()
    finally:
        db.close()
    return login_user(client, email, "AdminPass123!")


def add_scope(client, headers, target):
    resp = client.post("/scans/scope", json={"target": target}, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()
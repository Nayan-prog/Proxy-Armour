"""Shared fixtures.

Every test starts with NO secrets configured (a developer's real .env never
leaks into tests). API tests opt in with the `api` fixture, which configures
admin credentials, the shared secret and a fresh database:

    SQLite (always)       - a new file per test
    PostgreSQL (opt-in)   - set TEST_DATABASE_URL=postgresql+psycopg://user:pw@host/dbname
                            (a throwaway database: tables are dropped and recreated)
"""
import os
from datetime import datetime, timezone

import bcrypt
import fakeredis
import pytest
from fastapi.testclient import TestClient

import armour_config
from app import db, live
from app.auth import THROTTLE
from app.main import app
from app.models import Base, Event
from app.policy_store import STORE

ADMIN_USER = "admin"
ADMIN_PASSWORD = "correct horse battery staple"
JWT_SECRET = "j" * 48
EVENTS_SECRET = "e" * 40
POSTGRES_URL = os.environ.get("TEST_DATABASE_URL")


@pytest.fixture(scope="session")
def admin_hash() -> str:
    return bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()


def make_env(**overrides) -> armour_config.EnvSettings:
    return armour_config.EnvSettings(_env_file=None, **overrides)


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    # delete first: EnvSettings also reads OS environment variables (e.g. inside
    # the scanner container, where DATABASE_URL and the secrets are set)
    for var in ("DATABASE_URL", "REDIS_URL", "ADMIN_USERNAME", "ADMIN_PASSWORD_HASH",
                "JWT_SECRET", "EVENTS_SHARED_SECRET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(armour_config, "env", make_env())
    live.LINK.reset()
    STORE.reset()
    THROTTLE._failures.clear()
    yield
    db.configure(None)
    live.LINK.reset()
    STORE.reset()


@pytest.fixture(params=["sqlite"] + (["postgresql"] if POSTGRES_URL else []))
def database_url(request, tmp_path):
    if request.param == "sqlite":
        return f"sqlite:///{tmp_path / 'armour.db'}"
    return POSTGRES_URL


@pytest.fixture
def api(monkeypatch, admin_hash, database_url):
    """Fully configured API: credentials, shared secret, empty seeded database."""
    monkeypatch.setattr(armour_config, "env", make_env(
        database_url=database_url, admin_username=ADMIN_USER, admin_password_hash=admin_hash,
        jwt_secret=JWT_SECRET, events_shared_secret=EVENTS_SECRET))
    db.configure(database_url)
    engine = db.engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with db.session_factory()() as session:
        STORE.seed(session)
        STORE.load(session)
    yield TestClient(app)
    if db.engine() is not None:             # a test may have switched the DB off
        engine = db.engine()
    Base.metadata.drop_all(engine)


@pytest.fixture
def token(api) -> str:
    r = api.post("/api/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
def auth(token) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def secret_header() -> dict:
    return {"X-Armour-Secret": EVENTS_SECRET}


@pytest.fixture
def fake_redis():
    server = fakeredis.FakeServer()
    sync = fakeredis.FakeRedis(server=server, decode_responses=True)
    live.LINK.use(sync, fakeredis.FakeAsyncRedis(server=server, decode_responses=True))
    return sync


def event_payload(**overrides) -> dict:
    payload = {"host": "api.openai.com", "provider": "openai", "endpoint": "/v1/chat/completions",
               "action": "tokenize", "risk": "low", "finding_types": ["EMAIL"], "finding_count": 1,
               "detectors_used": ["regex"], "tokens_issued": 1, "tokens_restored": 1,
               "latency_ms_scan": 3.5, "latency_ms_total": 120.0, "status_code": 200}
    payload.update(overrides)
    return payload


def add_events(*rows: dict) -> list[int]:
    """Insert events directly. Each row: event_payload() overrides, may include ts."""
    with db.session_factory()() as session:
        events = [Event(**{**event_payload(), "ts": datetime.now(timezone.utc), **row}) for row in rows]
        session.add_all(events)
        session.commit()
        return [e.id for e in events]

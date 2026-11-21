"""Engine/session management. The database is OPTIONAL for /scan: if DATABASE_URL
is unset or the DB is down, scanning keeps working and only the audit log and
admin data endpoints answer 503."""
from collections.abc import Iterator

from fastapi import HTTPException
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

import armour_config

_engine: Engine | None = None
_sessions: sessionmaker | None = None


def configure(url: str | None) -> None:
    """(Re)point the app at a database. None disables persistence."""
    global _engine, _sessions
    if _engine is not None:
        _engine.dispose()
    _engine = _sessions = None
    if not url:
        return
    kwargs: dict = {"pool_pre_ping": True}
    if url.startswith("postgresql"):
        # all timestamps and date_trunc() buckets in UTC
        kwargs["connect_args"] = {"options": "-c timezone=utc", "connect_timeout": 3}
    elif url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        event.listen(_engine, "connect", lambda conn, _: conn.execute("PRAGMA foreign_keys=ON"))
    _sessions = sessionmaker(_engine, expire_on_commit=False)


def configure_from_env() -> None:
    url = armour_config.env.database_url
    configure(url.get_secret_value() if url else None)


def engine() -> Engine | None:
    return _engine


def session_factory() -> sessionmaker | None:
    return _sessions


def get_session() -> Iterator[Session]:
    """FastAPI dependency. 503 if no database is configured or it is unreachable."""
    if _sessions is None:
        raise HTTPException(503, "database not configured (set DATABASE_URL)")
    session = _sessions()
    try:
        yield session
    except SQLAlchemyError:
        session.rollback()
        # never str(exc): SQLAlchemy errors can echo parameters
        raise HTTPException(503, "database unavailable")
    finally:
        session.close()

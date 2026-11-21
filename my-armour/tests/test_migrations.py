"""Alembic: upgrade/downgrade work, and the migrated schema matches the ORM models
(a model change without a migration fails here)."""
import os

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from app.models import Base
from armour_config import ROOT

URLS = ["sqlite"] + (["postgresql"] if os.environ.get("TEST_DATABASE_URL") else [])


@pytest.fixture(params=URLS)
def url(request, tmp_path):
    if request.param == "sqlite":
        return f"sqlite:///{tmp_path / 'migrate.db'}"
    url = os.environ["TEST_DATABASE_URL"]
    Base.metadata.drop_all(create_engine(url))
    with create_engine(url).begin() as conn:
        conn.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    return url


def alembic(url: str) -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.cmd_opts = type("Opts", (), {"x": [f"url={url}"]})()
    return cfg


def test_upgrade_creates_the_schema_and_downgrade_removes_it(url):
    command.upgrade(alembic(url), "head")
    engine = create_engine(url)
    tables = set(inspect(engine).get_table_names())
    assert {"events", "policies", "alembic_version"} <= tables
    columns = {c["name"] for c in inspect(engine).get_columns("events")}
    assert columns == {"id", "ts", "host", "provider", "endpoint", "action", "risk", "finding_types",
                       "finding_count", "detectors_used", "tokens_issued", "tokens_restored",
                       "tokens_missing", "tokens_unknown", "leak_flag", "syntax_valid",
                       "latency_ms_scan", "latency_ms_total", "status_code"}
    command.downgrade(alembic(url), "base")
    assert {"events", "policies"}.isdisjoint(inspect(create_engine(url)).get_table_names())


def test_migrations_match_the_models(url):
    command.upgrade(alembic(url), "head")
    with create_engine(url).connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    # ignore server-default/nullable nuances; any missing/extra table, column or index is a bug
    structural = [d for d in diff if d[0] in ("add_table", "remove_table", "add_column",
                                             "remove_column", "add_index", "remove_index")]
    assert structural == []
    command.downgrade(alembic(url), "base")

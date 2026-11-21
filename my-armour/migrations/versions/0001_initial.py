"""events and policies tables (metadata only)

Revision ID: 0001
Revises:
Create Date: 2026-11-19
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

StringArray = postgresql.ARRAY(sa.String(64)).with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                  primary_key=True, autoincrement=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("endpoint", sa.String(512), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("risk", sa.String(16)),
        sa.Column("finding_types", StringArray, nullable=False),
        sa.Column("finding_count", sa.Integer, nullable=False),
        sa.Column("detectors_used", StringArray, nullable=False),
        sa.Column("tokens_issued", sa.Integer, nullable=False),
        sa.Column("tokens_restored", sa.Integer, nullable=False),
        sa.Column("tokens_missing", sa.Integer, nullable=False),
        sa.Column("tokens_unknown", sa.Integer, nullable=False),
        sa.Column("leak_flag", sa.Boolean, nullable=False),
        sa.Column("syntax_valid", sa.Boolean),
        sa.Column("latency_ms_scan", sa.Float),
        sa.Column("latency_ms_total", sa.Float),
        sa.Column("status_code", sa.Integer),
    )
    op.create_index("ix_events_ts", "events", ["ts"])
    op.create_index("ix_events_action", "events", ["action"])
    op.create_index("ix_events_provider", "events", ["provider"])
    # GIN on PostgreSQL makes "events containing type X" (= ANY / unnest) fast;
    # postgresql_using is ignored by other databases (ordinary index)
    op.create_index("ix_events_finding_types", "events", ["finding_types"],
                    postgresql_using="gin")

    op.create_table(
        "policies",
        sa.Column("type", sa.String(64), primary_key=True),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(64), nullable=False),
        sa.CheckConstraint("action IN ('allow', 'tokenize', 'block')", name="ck_policies_action"),
        sa.CheckConstraint("severity IN ('low', 'medium', 'high')", name="ck_policies_severity"),
    )


def downgrade() -> None:
    op.drop_table("policies")
    op.drop_table("events")

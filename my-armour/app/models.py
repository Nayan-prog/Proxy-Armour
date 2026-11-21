"""Database tables. METADATA ONLY - no prompt text, no original values, no placeholders.

Arrays are native TEXT[] on PostgreSQL and JSON on SQLite (used by the tests).
"""
from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, Index, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

StringArray = ARRAY(String(64)).with_variant(JSON(), "sqlite")
# SQLite only auto-increments an "INTEGER PRIMARY KEY"
BigId = BigInteger().with_variant(Integer(), "sqlite")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Event(Base):
    """One proxied LLM request (a mitmproxy flow)."""
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    host: Mapped[str] = mapped_column(String(253))
    provider: Mapped[str] = mapped_column(String(32), index=True)
    endpoint: Mapped[str] = mapped_column(String(512))
    action: Mapped[str] = mapped_column(String(16), index=True)          # allow | tokenize | block
    risk: Mapped[str | None] = mapped_column(String(16))                 # none | low | medium | high
    finding_types: Mapped[list[str]] = mapped_column(StringArray, default=list)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    detectors_used: Mapped[list[str]] = mapped_column(StringArray, default=list)
    tokens_issued: Mapped[int] = mapped_column(Integer, default=0)
    tokens_restored: Mapped[int] = mapped_column(Integer, default=0)
    tokens_missing: Mapped[int] = mapped_column(Integer, default=0)
    tokens_unknown: Mapped[int] = mapped_column(Integer, default=0)
    leak_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    syntax_valid: Mapped[bool | None] = mapped_column(Boolean)
    latency_ms_scan: Mapped[float | None] = mapped_column(Float)
    latency_ms_total: Mapped[float | None] = mapped_column(Float)
    status_code: Mapped[int | None] = mapped_column(Integer)

    # GIN on PostgreSQL makes "events containing type X" (= ANY / unnest) fast;
    # an ordinary index elsewhere
    __table_args__ = (Index("ix_events_finding_types", "finding_types", postgresql_using="gin"),)


class Policy(Base):
    """What to do with one finding type. Seeded from config.yaml on first start."""
    __tablename__ = "policies"

    type: Mapped[str] = mapped_column(String(64), primary_key=True)
    action: Mapped[str] = mapped_column(String(16))                      # allow | tokenize | block
    severity: Mapped[str] = mapped_column(String(16))                    # low | medium | high
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="config.yaml")

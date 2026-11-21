"""Read queries for the admin API: event listing and dashboard statistics.

finding_types is a native array on PostgreSQL and JSON on SQLite, so the two
"look inside the array" operations have one small per-dialect branch each:
    PostgreSQL: = ANY(finding_types) / unnest(finding_types)
    SQLite:     json_each(finding_types)
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, exists, func, literal, select, true
from sqlalchemy.orm import Session

from app.models import Event

RANGES = {"24h": (timedelta(hours=24), "hour"), "7d": (timedelta(days=7), "day")}


def _dialect(session: Session) -> str:
    return session.get_bind().dialect.name


def _as_utc(ts: datetime) -> datetime:
    # SQLite hands back naive datetimes; everything is stored as UTC
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


def has_type(dialect: str, finding_type: str):
    """WHERE clause: the event's finding_types contains finding_type."""
    if dialect == "postgresql":
        return Event.finding_types.any(finding_type)
    values = func.json_each(Event.finding_types).table_valued("value")
    return exists(select(literal(1)).select_from(values).where(values.c.value == finding_type))


def filtered_events(session: Session, *, action=None, finding_type=None, provider=None,
                    since: datetime | None = None, until: datetime | None = None) -> Select:
    query = select(Event)
    if action:
        query = query.where(Event.action == action)
    if provider:
        query = query.where(Event.provider == provider)
    if finding_type:
        query = query.where(has_type(_dialect(session), finding_type))
    if since:
        query = query.where(Event.ts >= since)
    if until:
        query = query.where(Event.ts < until)
    return query


def page_of_events(session: Session, query: Select, page: int, page_size: int) -> tuple[list[Event], int]:
    total = session.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    rows = session.scalars(query.order_by(Event.ts.desc(), Event.id.desc())
                           .offset((page - 1) * page_size).limit(page_size)).all()
    return list(rows), total or 0


def _count_by_type(session: Session, since: datetime) -> dict[str, int]:
    if _dialect(session) == "postgresql":
        types = select(func.unnest(Event.finding_types).label("t")).where(Event.ts >= since).subquery()
        rows = session.execute(select(types.c.t, func.count()).group_by(types.c.t))
    else:
        values = func.json_each(Event.finding_types).table_valued("value")
        rows = session.execute(select(values.c.value, func.count()).select_from(Event)
                               .join(values, true()).where(Event.ts >= since)
                               .group_by(values.c.value))
    return dict(sorted(((t, n) for t, n in rows), key=lambda tn: (-tn[1], tn[0])))


def _bucket(dialect: str, unit: str):
    if dialect == "postgresql":
        return func.date_trunc(unit, Event.ts)
    return func.strftime("%Y-%m-%d %H:00:00" if unit == "hour" else "%Y-%m-%d 00:00:00", Event.ts)


def _parse_bucket(value) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return _as_utc(value)


def stats(session: Session, range_key: str, now: datetime | None = None) -> dict:
    span, unit = RANGES[range_key]
    now = now or datetime.now(timezone.utc)
    since = now - span
    in_range = Event.ts >= since

    by_action = dict(session.execute(select(Event.action, func.count()).where(in_range)
                                     .group_by(Event.action)).all())
    by_provider = dict(session.execute(select(Event.provider, func.count()).where(in_range)
                                       .group_by(Event.provider)).all())
    leaks, avg_total, avg_scan, issued, restored, missing = session.execute(
        select(func.count().filter(Event.leak_flag.is_(True)),
               func.avg(Event.latency_ms_total), func.avg(Event.latency_ms_scan),
               func.coalesce(func.sum(Event.tokens_issued), 0),
               func.coalesce(func.sum(Event.tokens_restored), 0),
               func.coalesce(func.sum(Event.tokens_missing), 0)).where(in_range)).one()

    # time series: one bucket per hour (24h) or day (7d), zero-filled
    bucket = _bucket(_dialect(session), unit).label("bucket")
    counts: dict[datetime, dict[str, int]] = {}
    for b, action, n in session.execute(select(bucket, Event.action, func.count()).where(in_range)
                                        .group_by(bucket, Event.action)):
        counts.setdefault(_parse_bucket(b), {})[action] = n
    step = timedelta(hours=1) if unit == "hour" else timedelta(days=1)
    start = since.replace(minute=0, second=0, microsecond=0)
    if unit == "day":
        start = start.replace(hour=0)
    timeseries, t = [], start
    while t <= now:
        c = counts.get(t, {})
        timeseries.append({"bucket": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "allow": c.get("allow", 0), "tokenize": c.get("tokenize", 0),
                           "block": c.get("block", 0), "total": sum(c.values())})
        t += step

    return {
        "range": range_key,
        "since": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "totals": {"requests": sum(by_action.values()), "blocked": by_action.get("block", 0),
                   "tokenized": by_action.get("tokenize", 0), "allowed": by_action.get("allow", 0),
                   "leaks": leaks or 0,
                   "tokens_issued": int(issued), "tokens_restored": int(restored),
                   "tokens_missing": int(missing),
                   # share of issued placeholders that came back and were restored;
                   # None when nothing was tokenized (not 0% or 100%)
                   "restoration_rate": round(restored / issued, 4) if issued else None,
                   "avg_latency_ms_total": round(avg_total, 2) if avg_total is not None else None,
                   "avg_latency_ms_scan": round(avg_scan, 2) if avg_scan is not None else None},
        "by_action": by_action,
        "by_type": _count_by_type(session, since),
        "by_provider": by_provider,
        "timeseries": timeseries,
    }

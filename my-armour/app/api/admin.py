"""Dashboard API under /api. Everything except /api/login needs a bearer JWT.

    POST /api/login                 username + password -> JWT (8 h)
    GET  /api/stats?range=24h|7d    totals, by action/type/provider, time series, live counters
    GET  /api/events                paginated, filters: action, type, provider, from, to
    GET  /api/events/{id}
    GET  /api/policies              PUT /api/policies (proxy picks changes up within poll_seconds)
    GET  /api/live                  server-sent events (Redis pub/sub, DB polling fallback)
    POST /api/playground/scan       detection + tokenized preview of pasted text - never stored

Responses contain metadata only; the playground returns offsets, not values.
"""
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from armour_config import TYPE_NAME, settings
from app import db, live, queries
from app.auth import THROTTLE, authenticate, create_token, require_admin
from app.detectors import overall_risk, scan_text
from app.detectors.engine import default_severities
from app.models import Event, Policy, utcnow
from app.policy import apply_policy, request_action
from app.policy_store import STORE
from app.schemas import (
    Action, EventOut, EventPage, LoginIn, PlaygroundIn, PlaygroundOut, PolicyOut,
    PolicyUpdateIn, Provider, TokenOut,
)
from proxy.tokenization import tokenize_slots

router = APIRouter(prefix="/api", tags=["admin"])


# ------------------------------------------------------------------ auth

@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request) -> TokenOut:
    client = request.client.host if request.client else "unknown"
    THROTTLE.check(client)
    if not authenticate(body.username, body.password):
        THROTTLE.failed(client)
        raise HTTPException(401, "invalid username or password",
                            headers={"WWW-Authenticate": "Bearer"})
    THROTTLE.succeeded(client)
    token, expires = create_token(body.username)
    return TokenOut(access_token=token, expires_at=expires)


# ------------------------------------------------------------------ stats / events

@router.get("/stats")
def get_stats(range: Literal["24h", "7d"] = "24h", admin: str = Depends(require_admin),
              session: Session = Depends(db.get_session)) -> dict:
    result = queries.stats(session, range)
    result["live_counters"] = live.recent_counters(60)     # None when Redis is off
    return result


@router.get("/events", response_model=EventPage)
def list_events(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                action: Action | None = None,
                type: str | None = Query(None, pattern=TYPE_NAME.pattern),
                provider: Provider | None = None,
                from_: datetime | None = Query(None, alias="from"),
                to: datetime | None = None,
                admin: str = Depends(require_admin),
                session: Session = Depends(db.get_session)) -> EventPage:
    if from_ and to and from_ >= to:
        raise HTTPException(422, "'from' must be before 'to'")
    query = queries.filtered_events(session, action=action, finding_type=type,
                                    provider=provider, since=from_, until=to)
    rows, total = queries.page_of_events(session, query, page, page_size)
    return EventPage(items=[EventOut.model_validate(r) for r in rows], total=total,
                     page=page, page_size=page_size)


@router.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: int, admin: str = Depends(require_admin),
              session: Session = Depends(db.get_session)) -> EventOut:
    row = session.get(Event, event_id)
    if row is None:
        raise HTTPException(404, "event not found")
    return EventOut.model_validate(row)


# ------------------------------------------------------------------ policies

def _policy_rows(session: Session | None) -> list[PolicyOut]:
    severities = default_severities()
    stored = {p.type: p for p in session.scalars(select(Policy))} if session else {}
    out = []
    for t in sorted(set(STORE.base.types) | set(stored)):
        if t in stored:
            out.append(PolicyOut.model_validate(stored[t]))
        else:
            out.append(PolicyOut(type=t, action=STORE.current.action_for(t),
                                 severity=STORE.current.severities.get(t, severities.get(t, "high")),
                                 updated_at=None, updated_by="config.yaml"))
    return out


@router.get("/policies", response_model=list[PolicyOut])
def get_policies(admin: str = Depends(require_admin)) -> list[PolicyOut]:
    factory = db.session_factory()
    if factory is None:                       # no database: show config.yaml (read-only)
        return _policy_rows(None)
    try:
        with factory() as session:
            return _policy_rows(session)
    except SQLAlchemyError:
        raise HTTPException(503, "database unavailable")


@router.put("/policies", response_model=list[PolicyOut])
def put_policies(body: PolicyUpdateIn, admin: str = Depends(require_admin),
                 session: Session = Depends(db.get_session)) -> list[PolicyOut]:
    severities = default_severities()
    known = set(severities) | set(STORE.base.types)
    unknown = sorted({p.type for p in body.policies} - known)
    if unknown:
        raise HTTPException(422, f"unknown finding type(s): {', '.join(unknown)}")
    now = utcnow()
    for update in body.policies:
        row = session.get(Policy, update.type)
        if row is None:
            row = Policy(type=update.type, severity=severities.get(update.type, "high"))
            session.add(row)
        row.action = update.action
        if update.severity is not None:
            row.severity = update.severity
        row.updated_at, row.updated_by = now, admin
    session.commit()
    STORE.load(session)                       # this process: immediately; proxy: next poll
    return _policy_rows(session)


# ------------------------------------------------------------------ live feed

async def _poll_new_events(last_id: int | None) -> tuple[int | None, list[dict]]:
    factory = db.session_factory()
    if factory is None:
        return last_id, []

    def work():
        with factory() as session:
            if last_id is None:
                return session.scalar(select(func.max(Event.id))) or 0, []
            rows = session.scalars(select(Event).where(Event.id > last_id)
                                   .order_by(Event.id).limit(100)).all()
            return (rows[-1].id if rows else last_id), [
                EventOut.model_validate(r).model_dump(mode="json") for r in rows]

    try:
        return await run_in_threadpool(work)
    except SQLAlchemyError:
        return last_id, []


@router.get("/live")
async def live_feed(request: Request, admin: str = Depends(require_admin)) -> StreamingResponse:
    # Bearer header only (use fetch() streaming in the dashboard, not EventSource):
    # a token in the URL would end up in access logs.
    stream = live.event_stream(request.is_disconnected, _poll_new_events,
                               poll_seconds=settings.live.poll_seconds,
                               heartbeat_seconds=settings.live.heartbeat_seconds)
    return StreamingResponse(stream, media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ playground

@router.post("/playground/scan", response_model=PlaygroundOut)
def playground_scan(body: PlaygroundIn, admin: str = Depends(require_admin)) -> PlaygroundOut:
    """Run detection + tokenization on pasted text. Nothing is stored or published."""
    findings = apply_policy(scan_text(body.text), STORE.current)
    holder = [body.text]
    mapping = tokenize_slots([(holder, 0)], findings)
    return PlaygroundOut(
        risk=overall_risk(findings),
        action=request_action(findings),
        findings=[{k: f[k] for k in ("type", "start", "end", "severity", "detector", "action")}
                  for f in findings],
        tokenized_preview=holder[0],
        placeholders={p: p[3:-9] for p in mapping},          # placeholder -> TYPE only
    )

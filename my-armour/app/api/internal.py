"""Proxy -> API endpoints, protected by the X-Armour-Secret shared secret.

    POST /events              one metadata-only event per proxied flow
    GET  /internal/policies   the live policy (the proxy polls this)
"""
import hmac

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

import armour_config
from app import db, live
from app.models import Event, utcnow
from app.policy_store import STORE
from app.schemas import EventIn, EventOut

SECRET_HEADER = "X-Armour-Secret"

router = APIRouter(tags=["internal"])


def require_shared_secret(x_armour_secret: str | None = Header(None)) -> None:
    expected = armour_config.env.events_shared_secret
    if expected is None:
        raise HTTPException(503, "EVENTS_SHARED_SECRET not configured")
    # constant-time: == would leak how many leading characters were right
    if x_armour_secret is None or not hmac.compare_digest(
            x_armour_secret.encode(), expected.get_secret_value().encode()):
        raise HTTPException(401, "bad or missing shared secret")


@router.post("/events", status_code=201, dependencies=[Depends(require_shared_secret)])
def create_event(event: EventIn, session: Session = Depends(db.get_session)) -> dict:
    row = Event(**event.model_dump(exclude={"ts"}), ts=event.ts or utcnow())
    session.add(row)
    session.commit()
    out = EventOut.model_validate(row)
    live.record(out.model_dump(mode="json"), out.ts)       # best effort: no Redis, no problem
    return {"id": row.id}


@router.get("/internal/policies", dependencies=[Depends(require_shared_secret)])
def internal_policies() -> dict:
    # read the table, not just this process's memory: with several API workers
    # a PUT handled by another worker must still reach the proxy
    factory = db.session_factory()
    if factory is not None:
        try:
            with factory() as session:
                STORE.load(session)
        except SQLAlchemyError:
            pass                                        # serve the last known policy
    return STORE.current.model_dump()

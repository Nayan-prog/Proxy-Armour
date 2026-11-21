import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError

from armour_config import settings
from app import db
from app.api import admin, internal
from app.detectors import scan_text, redact, overall_risk
from app.policy import apply_policy, request_action
from app.policy_store import STORE


async def _refresh_policies_forever() -> None:
    """Keep this worker's in-memory policy in step with the table (multi-worker safe)."""
    while True:
        await asyncio.sleep(settings.policy_sync.poll_seconds)
        factory = db.session_factory()
        if factory is None:
            continue
        try:
            with factory() as session:
                STORE.load(session)
        except SQLAlchemyError:
            pass                                   # keep the last known policy


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.configure_from_env()
    factory = db.session_factory()
    if factory is not None:
        try:
            with factory() as session:
                seeded = STORE.seed(session)
                STORE.load(session)
            print(f"[ARMOUR-API] database ready - policies loaded ({seeded} seeded from config.yaml)")
        except SQLAlchemyError as e:
            # e.g. schema not created yet; scanning still works on config.yaml policy
            print(f"[ARMOUR-API] database unavailable ({type(e).__name__}) - "
                  f"run `alembic upgrade head`; using config.yaml policy")
    else:
        print("[ARMOUR-API] DATABASE_URL not set - audit log and admin data disabled")
    task = asyncio.create_task(_refresh_policies_forever())
    yield
    task.cancel()


app = FastAPI(title="Proxy Armour", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.admin.cors_origins,
    allow_credentials=False,                       # bearer tokens, not cookies
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(internal.router)
app.include_router(admin.router)


@app.middleware("http")
async def no_tracebacks(request: Request, call_next):
    """Unexpected errors -> 500 with the exception TYPE logged, nothing else.

    A traceback's message could contain request data (prompt text), and Starlette's
    own error handler re-raises so the server logs the full traceback - so errors
    are caught here. The proxy turns this 500 into a fail-closed 503.
    """
    try:
        return await call_next(request)
    except Exception as e:
        print(f"[ARMOUR-API] internal error on {request.method} {request.url.path} ({type(e).__name__})")
        return JSONResponse({"detail": "internal error"}, status_code=500)


class ScanRequest(BaseModel):
    text: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan(req: ScanRequest):
    # never touches the database: the policy is in memory, so scanning keeps
    # working (and the proxy keeps forwarding) when the DB or Redis is down
    # each finding: {type, start, end, severity, detector, value, action}
    findings = apply_policy(scan_text(req.text), STORE.current)
    return {
        "risk": overall_risk(findings),          # reporting only
        "action": request_action(findings),      # allow | tokenize | block
        "findings": findings,
        "sanitized": redact(req.text, findings),  # irreversible preview, not used by the proxy
    }


if __name__ == "__main__":
    # python -m app.main  -> starts on the host/port from config.yaml
    import uvicorn
    uvicorn.run(app, host=settings.scanner.host, port=settings.scanner.port)

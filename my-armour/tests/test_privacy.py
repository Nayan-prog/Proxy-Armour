"""Privacy invariant, end to end: original values and placeholders never reach logs,
exception traces, the database, Redis, the dashboard API or the timing log.

One test drives normal traffic AND injected failures through the whole stack
in-process (proxy hooks -> real API app with SQLite + fake Redis -> mock LLMs),
capturing every sink, then searches all of them. Injected exceptions deliberately
carry a secret in their message, to prove only exception TYPES are ever logged.
"""
import asyncio
import json
import logging
import re

import httpx
import pytest
from mitmproxy import http
from mitmproxy.test import tflow

import app.main as api_main
import armour_config
from app import db, live
from app.main import app as api_app
from app.models import Event, Policy
from eval import mangling_mock
from mock_llm.app import app as mock_app
from proxy import armour_addon as addon
from proxy import tokenization
from proxy.tokenization import TokenVault
from tests.conftest import ADMIN_PASSWORD, ADMIN_USER

SECRET, EMAIL, AWS = "hunter22-prod", "rahul@acme.com", "AKIA" + "IOSFODNN7EXAMPLE"
AADHAAR = "2345 6789 0124"
ORIGINALS = (SECRET, EMAIL, AWS, AADHAAR)
PLACEHOLDER = re.compile(r"PA_[A-Z][A-Z0-9_]*_[0-9A-F]{8}")
CODE = f'Please review:\n```python\npassword = "{SECRET}"\nADMIN = "{EMAIL}"\nKEY = "{AWS}"\n```'


def chat(content, stream=False):
    return json.dumps({"model": "m", "stream": stream, "messages": [{"role": "user", "content": content}]})


async def flow_through(upstream_app, content, *, stream=False, headers=None, chunk=7):
    flow = tflow.tflow(req=http.Request.make("POST", "https://api.openai.com/v1/chat/completions",
                                             chat(content, stream), {"content-type": "application/json", **(headers or {})}))
    await addon.request(flow)
    if flow.response is None:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream_app), base_url="http://llm") as c:
            r = await c.post(flow.request.path, content=flow.request.get_content(),
                             headers={"content-type": "application/json", **(headers or {})})
        flow.response = http.Response.make(r.status_code, b"" if stream else r.content,
                                           {"content-type": r.headers["content-type"]})
        addon.responseheaders(flow)
        if stream:
            feed = flow.response.stream if callable(flow.response.stream) else (lambda d: d)
            for i in range(0, len(r.content), chunk):
                feed(r.content[i:i + chunk])
            feed(b"")
        addon.response(flow)
    else:
        addon.response(flow)
    await asyncio.gather(*addon._background)
    return flow


def boom(*_args, **_kwargs):
    # a bug whose exception message contains data: must never be logged
    raise ValueError(f"internal failure while handling {SECRET} / PA_EMAIL_0123ABCD")


@pytest.fixture
def stack(api, monkeypatch, fake_redis, tmp_path, caplog):
    monkeypatch.setattr(addon, "scanner", httpx.AsyncClient(transport=httpx.ASGITransport(app=api_app)))
    monkeypatch.setattr(addon, "VAULT", TokenVault(ttl_seconds=120))
    monkeypatch.setattr(addon, "POLICY", armour_config.settings.policy)
    monkeypatch.setattr(addon, "TIMING_LOG", str(tmp_path / "timing.jsonl"))
    caplog.set_level(logging.DEBUG)                  # every logger, every level
    pubsub = fake_redis.pubsub()
    pubsub.subscribe(live.CHANNEL)
    pubsub.get_message(timeout=1)
    return pubsub


def test_no_original_or_placeholder_reaches_any_sink(stack, api, fake_redis, monkeypatch, capsys, caplog, tmp_path):
    pubsub = stack

    async def scenarios():
        normal = await flow_through(mock_app, CODE)                                   # tokenize + restore
        assert SECRET in normal.response.get_text()                                   # (restored for the user)
        await flow_through(mock_app, CODE, stream=True)                               # SSE, 7-byte chunks
        blocked = await flow_through(mock_app, f"aadhaar {AADHAAR}")                  # block policy
        assert blocked.response.status_code == 403
        mangling_mock.LEAK_VALUES["privacy"] = EMAIL
        await flow_through(mangling_mock.app, CODE, headers={"x-mangle": "leak", "x-leak-id": "privacy"})
        await flow_through(mangling_mock.app, CODE, headers={"x-mangle": "forge"})
        await flow_through(mangling_mock.app, CODE, stream=True, headers={"x-mangle": "duplicate"})

        with monkeypatch.context() as m:                                              # JSON restore crashes
            m.setattr(addon, "restore_json", boom)
            await flow_through(mock_app, CODE)
        with monkeypatch.context() as m:                                              # stream restore crashes
            m.setattr(tokenization.StreamRestorer, "_process", boom)
            crashed = await flow_through(mock_app, CODE, stream=True)
            assert crashed.response.status_code == 200
        with monkeypatch.context() as m:                                              # API /scan crashes
            m.setattr(api_main, "scan_text", boom)
            failed = await flow_through(mock_app, CODE)
            assert failed.response.status_code == 503                                 # proxy failed closed
        with monkeypatch.context() as m:                                              # scanner returns garbage
            m.setattr(addon, "scanner", httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, text=f"<html>{SECRET}</html>"))))
            garbage = await flow_through(mock_app, CODE)
            assert garbage.response.status_code == 503

    asyncio.run(scenarios())

    # ---------------------------------------------------------------- collect every sink
    out = capsys.readouterr()
    sinks = {
        "stdout": out.out,
        "stderr": out.err,
        "logging (messages + tracebacks)": "\n".join(
            caplog.handler.format(r) for r in caplog.records),
        "timing log": (tmp_path / "timing.jsonl").read_text(encoding="utf-8"),
    }
    with db.session_factory()() as session:
        events = session.query(Event).all()
        sinks["database"] = "\n".join(repr(vars(e)) for e in events) + \
            "\n".join(repr(vars(p)) for p in session.query(Policy).all())
    # one event per flow - except the "garbage scanner" flow, whose API (incl. /events)
    # answers garbage too: the event is lost, the request is unaffected (by design)
    assert len(events) == 9
    redis_dump = []
    for key in fake_redis.keys("*"):
        redis_dump.append(key)
        if fake_redis.type(key) == "hash":
            redis_dump.append(json.dumps(fake_redis.hgetall(key)))
    while (message := pubsub.get_message(timeout=0.1)) is not None:
        redis_dump.append(str(message["data"]))
    sinks["redis (keys, hashes, pub/sub)"] = "\n".join(redis_dump)

    login = api.post("/api/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD}).json()
    auth = {"Authorization": f"Bearer {login['access_token']}"}
    dashboard = [api.get("/api/events?page_size=100", headers=auth).text,
                 api.get("/api/stats?range=24h", headers=auth).text,
                 api.get("/api/policies", headers=auth).text]
    dashboard += [api.get(f"/api/events/{e.id}", headers=auth).text for e in events]
    sinks["dashboard API responses"] = "\n".join(dashboard)

    # ---------------------------------------------------------------- the invariant
    assert "ValueError" in sinks["stdout"]                                            # failures WERE logged (by type)
    for name, content in sinks.items():
        for original in ORIGINALS:
            assert original not in content, f"original value leaked into {name}"
        assert not PLACEHOLDER.search(content), f"placeholder leaked into {name}: {PLACEHOLDER.search(content)}"
        assert "internal failure while handling" not in content, f"exception message leaked into {name}"


def test_api_internal_error_is_500_with_type_only(api, monkeypatch, capsys):
    monkeypatch.setattr(api_main, "scan_text", boom)
    r = api.post("/scan", json={"text": f"password = {SECRET}"})
    assert r.status_code == 500 and r.json() == {"detail": "internal error"}
    out = capsys.readouterr().out
    assert "ValueError" in out and SECRET not in out and "PA_" not in out


def test_responseheaders_failure_drops_the_map_and_logs_type_only(monkeypatch, capsys):
    monkeypatch.setattr(addon, "VAULT", TokenVault(ttl_seconds=120))
    flow = tflow.tflow(req=http.Request.make("POST", "https://api.openai.com/v1/chat/completions", "{}"))
    flow.metadata[addon.META] = {"host": "api.openai.com"}
    addon.VAULT.put(flow.id, {"PA_EMAIL_0123ABCD": EMAIL})
    flow.response = http.Response.make(200, b"", {"content-type": "text/event-stream"})
    monkeypatch.setattr(addon, "StreamRestorer", boom)
    addon.responseheaders(flow)                                                       # must not raise
    assert flow.id not in addon.VAULT and not callable(flow.response.stream)
    out = capsys.readouterr().out
    assert "ValueError" in out and EMAIL not in out and "PA_" not in out

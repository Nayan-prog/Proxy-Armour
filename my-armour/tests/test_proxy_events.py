"""Proxy side of persistence: one metadata-only event per flow, failure isolation,
and the polled policy."""
import asyncio
import json
import re

import httpx
import pytest
from mitmproxy import http
from mitmproxy.test import tflow

import armour_config
from app import db
from app.main import app as api_app
from app.models import Event
from app.schemas import EventIn
from mock_llm.app import app as mock_app
from proxy import armour_addon as addon
from proxy.tokenization import TokenVault
from tests.conftest import EVENTS_SECRET

EMAIL, SECRET = "rahul@acme.com", "hunter22"
# both values inside the fence: the mock LLM echoes the fenced code back
PROMPT = f'please review\n```python\nADMIN = "{EMAIL}"\npassword = "{SECRET}"\n```'


def test_missing_placeholders_are_counted_in_the_event(proxy):
    # the email is outside the fence, so the mock's reply never mentions it
    asyncio.run(run_flow(proxy, make_flow(f'mail {EMAIL}\n```python\npassword = "{SECRET}"\n```')))
    (e,) = all_events()
    assert (e.tokens_issued, e.tokens_restored, e.tokens_missing) == (2, 1, 1)


@pytest.fixture
def proxy(monkeypatch, api):
    """Proxy wired to the real API app in memory (scanner, /events, /internal/policies)."""
    monkeypatch.setattr(addon, "scanner", httpx.AsyncClient(transport=httpx.ASGITransport(app=api_app)))
    monkeypatch.setattr(addon, "VAULT", TokenVault(ttl_seconds=120))
    monkeypatch.setattr(addon, "POLICY", armour_config.settings.policy)
    return addon


def make_flow(prompt=PROMPT, url="https://api.openai.com/v1/chat/completions"):
    body = json.dumps({"model": "m", "messages": [{"role": "user", "content": prompt}]})
    return tflow.tflow(req=http.Request.make("POST", url, body, {"content-type": "application/json"}))


def mock_reply(flow):
    """The mock LLM answers whatever (tokenized) request the proxy sent upstream."""
    async def call():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=mock_app)) as c:
            return await c.post("http://mock" + flow.request.path, content=flow.request.get_content(),
                                headers={"content-type": "application/json"})
    r = asyncio.run(call())
    flow.response = http.Response.make(r.status_code, r.content, {"content-type": "application/json"})


async def run_flow(proxy, flow, reply=True):
    await proxy.request(flow)
    if flow.response is None and reply:
        await asyncio.to_thread(mock_reply, flow)
    proxy.responseheaders(flow)
    proxy.response(flow)
    await asyncio.gather(*proxy._background)         # let the background POST finish


def all_events():
    with db.session_factory()() as session:
        return session.query(Event).order_by(Event.id).all()


# ------------------------------------------------------------------ build_event

def test_build_event_is_metadata_only_and_schema_valid(proxy):
    flow = make_flow(url="https://generativelanguage.googleapis.com/v1beta/models/g:generateContent?key=AIzaSecretKey")
    asyncio.run(proxy.request(flow))
    mock_reply(flow)
    proxy.response(flow)
    event = proxy.build_event(flow)
    EventIn.model_validate(event)                     # what the API will accept
    assert event["endpoint"] == "/v1beta/models/g:generateContent"     # query (API key) dropped
    assert (event["provider"], event["action"], event["tokens_issued"]) == ("google", "tokenize", 2)
    assert event["finding_types"] == ["EMAIL", "HARDCODED_SECRET"]
    assert set(event["detectors_used"]) == {"regex", "ast"}
    dumped = json.dumps(event)
    assert EMAIL not in dumped and SECRET not in dumped and "PA_" not in dumped and "AIza" not in dumped


@pytest.mark.parametrize("host,provider", [
    ("api.openai.com", "openai"), ("contoso.openai.azure.com", "azure"),
    ("api.anthropic.com", "anthropic"), ("generativelanguage.googleapis.com", "google"),
    ("api.mistral.ai", "mistral"), ("api.groq.com", "groq"), ("example.com", "other"),
    ("evilopenai.com", "other"),
])
def test_provider_of(host, provider):
    assert addon.provider_of(host) == provider


# ------------------------------------------------------------------ one event per flow

@pytest.mark.parametrize("prompt,action,status", [
    (PROMPT, "tokenize", 200),
    ("aadhaar 2345 6789 0124", "block", 403),
    ("What is the capital of France?", "allow", 200),
])
def test_every_flow_records_one_event(proxy, monkeypatch, prompt, action, status):
    monkeypatch.setattr(armour_config, "env", armour_config.env.model_copy())
    asyncio.run(run_flow(proxy, make_flow(prompt)))
    (event,) = all_events()
    assert (event.action, event.status_code) == (action, status)
    assert event.latency_ms_scan > 0 and event.latency_ms_total >= event.latency_ms_scan


def test_tokenized_flow_event_has_restore_stats(proxy):
    asyncio.run(run_flow(proxy, make_flow()))
    (e,) = all_events()
    assert (e.tokens_issued, e.tokens_restored, e.tokens_missing, e.tokens_unknown) == (2, 2, 0, 0)
    assert e.syntax_valid is True and e.leak_flag is False and e.risk == "high"


def test_scanner_unavailable_block_is_still_recorded(proxy, monkeypatch):
    calls = {"n": 0}

    def flaky(request):                               # /scan fails, /events works
        calls["n"] += 1
        if request.url.path == "/scan":
            return httpx.Response(500)
        return asyncio.run(_forward(request))

    async def _forward(request):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api_app)) as c:
            return await c.send(request)

    monkeypatch.setattr(addon, "scanner", httpx.AsyncClient(transport=httpx.MockTransport(flaky)))
    flow = make_flow()
    asyncio.run(addon.request(flow))
    assert flow.response.status_code == 503
    payload = addon.build_event(flow)
    assert (payload["action"], payload["status_code"], payload["finding_types"]) == ("block", 503, [])


def test_upstream_error_records_an_event(proxy):
    async def scenario():
        flow = make_flow()
        await proxy.request(flow)
        proxy.error(flow)
        await asyncio.gather(*proxy._background)
    asyncio.run(scenario())
    (event,) = all_events()
    assert event.status_code is None and len(addon.VAULT) == 0


def test_the_database_never_sees_values_or_placeholders(proxy, database_url):
    if not database_url.startswith("sqlite"):
        pytest.skip("raw-file check is SQLite-specific")
    asyncio.run(run_flow(proxy, make_flow()))
    db.engine().dispose()
    raw = open(database_url.removeprefix("sqlite:///"), "rb").read()
    for needle in (EMAIL.encode(), SECRET.encode(), b"PA_EMAIL_", b"PA_HARDCODED_SECRET_", b"please review"):
        assert needle not in raw


# ------------------------------------------------------------------ failure isolation

@pytest.mark.parametrize("failure", [
    lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")),
    lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow")),
    lambda r: httpx.Response(500),
    lambda r: httpx.Response(401),
], ids=["down", "timeout", "500", "401"])
def test_logging_failures_never_break_the_request(proxy, monkeypatch, failure, capsys):
    flow = make_flow()
    asyncio.run(proxy.request(flow))
    mock_reply(flow)
    monkeypatch.setattr(addon, "scanner", httpx.AsyncClient(transport=httpx.MockTransport(failure)))

    async def finish():
        proxy.response(flow)                          # must not raise
        await asyncio.gather(*proxy._background)
    asyncio.run(finish())
    assert flow.response.status_code == 200 and EMAIL in flow.response.get_text()   # still restored
    assert "event not recorded" in capsys.readouterr().out


def test_no_secret_means_no_event_and_no_error(proxy, monkeypatch):
    monkeypatch.setattr(armour_config, "env", armour_config.env.model_copy(update={"events_shared_secret": None}))
    asyncio.run(run_flow(proxy, make_flow()))
    assert all_events() == [] and not addon._background


def test_events_are_reported_once(proxy):
    async def scenario():
        flow = make_flow()
        await proxy.request(flow)
        await asyncio.to_thread(mock_reply, flow)
        proxy.response(flow)
        proxy.error(flow)                             # a late error must not double count
        await asyncio.gather(*proxy._background)
    asyncio.run(scenario())
    assert len(all_events()) == 1


# ------------------------------------------------------------------ policy sync

def test_proxy_picks_up_policy_changes(proxy, auth, api):
    api.put("/api/policies", headers=auth, json={"policies": [{"type": "EMAIL", "action": "block"}]})
    assert asyncio.run(addon.refresh_policy()) is True
    assert addon.POLICY.action_for("EMAIL") == "block"
    flow = make_flow(f"mail {EMAIL}")
    asyncio.run(addon.request(flow))
    assert flow.response.status_code == 403


def test_proxy_policy_overrides_the_scanner_suggestion(proxy, monkeypatch):
    # the scanner (stale or other worker) says tokenize, the proxy's policy says allow
    monkeypatch.setattr(addon, "POLICY", armour_config.PolicySettings(
        default_action="block", types={**armour_config.settings.policy.types, "EMAIL": "allow"}))
    flow = make_flow(f"mail {EMAIL}")
    asyncio.run(addon.request(flow))
    assert flow.response is None and EMAIL in flow.request.get_text()


@pytest.mark.parametrize("failure", [
    lambda r: httpx.Response(500),
    lambda r: httpx.Response(200, json={"types": {"EMAIL": "maybe"}}),
    lambda r: httpx.Response(200, json={"default_action": "allow", "types": {}}),   # fail-open policy
    lambda r: (_ for _ in ()).throw(httpx.ConnectError("refused")),
], ids=["500", "invalid", "default-allow", "down"])
def test_failed_policy_poll_keeps_the_last_good_policy(proxy, monkeypatch, failure):
    before = addon.POLICY
    monkeypatch.setattr(addon, "scanner", httpx.AsyncClient(transport=httpx.MockTransport(failure)))
    assert asyncio.run(addon.refresh_policy()) is False
    assert addon.POLICY is before


def test_policy_poll_sends_the_shared_secret(proxy, monkeypatch):
    seen = {}

    def capture(request):
        seen["secret"] = request.headers.get("X-Armour-Secret")
        return httpx.Response(401)

    monkeypatch.setattr(addon, "scanner", httpx.AsyncClient(transport=httpx.MockTransport(capture)))
    asyncio.run(addon.refresh_policy())
    assert seen["secret"] == EVENTS_SECRET

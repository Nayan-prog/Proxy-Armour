"""End to end through the addon hooks: client -> request hook (real scanner) ->
mock LLM -> responseheaders/response hooks -> client. No network, no API keys."""
import asyncio
import json
import re

import httpx
import pytest
from fastapi.testclient import TestClient
from mitmproxy import http
from mitmproxy.test import tflow

from app.main import app as scanner_app
from armour_config import DemoSettings
from mock_llm.app import EDIT_LINE, app as mock_app
from proxy import armour_addon as addon
from proxy.tokenization import TokenVault

mock = TestClient(mock_app)

SECRET, EMAIL = "hunter22", "rahul@acme.com"
CODE = f'DB_PASSWORD = "{SECRET}"\nADMIN = "{EMAIL}"\nconnect(password=DB_PASSWORD)\n'
PROMPT = f"Please review:\n```python\n{CODE}```"
EXPECTED_REPLY = f"Here is your code with a small edit:\n\n```python\n{EDIT_LINE}\n{CODE}```\n"

PROVIDERS = {
    "openai": ("api.openai.com", "/v1/chat/completions",
               lambda prompt, stream: {"model": "gpt-4o-mini", "stream": stream,
                                       "messages": [{"role": "user", "content": prompt}]}),
    "anthropic": ("api.anthropic.com", "/v1/messages",
                  lambda prompt, stream: {"model": "claude-x", "max_tokens": 512, "stream": stream,
                                          "messages": [{"role": "user", "content": prompt}]}),
}


class FakeClock:
    now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture(autouse=True)
def proxy_env(monkeypatch):
    monkeypatch.setattr(addon, "scanner", httpx.AsyncClient(transport=httpx.ASGITransport(app=scanner_app)))
    monkeypatch.setattr(addon, "VAULT", TokenVault(ttl_seconds=120))


def send(provider, prompt=PROMPT, stream=False, body=None):
    host, path, make_body = PROVIDERS[provider]
    content = json.dumps(body if body is not None else make_body(prompt, stream))
    flow = tflow.tflow(req=http.Request.make("POST", f"https://{host}{path}", content,
                                             {"content-type": "application/json"}))
    asyncio.run(addon.request(flow))
    return flow


def upstream(flow):
    """What the provider does: here, the mock LLM answers the (tokenized) request."""
    return mock.post(flow.request.path, content=flow.request.get_content(),
                     headers={"content-type": "application/json"})


def deliver(flow, status, content: bytes, content_type, chunk=None, extra_headers=None):
    """Hand an upstream response to the hooks; return what the client receives."""
    headers = {"content-type": content_type, **(extra_headers or {})}
    flow.response = http.Response.make(status, b"" if chunk else content, headers)
    addon.responseheaders(flow)
    if chunk:
        stream = flow.response.stream
        assert callable(stream), "SSE response should be streamed through the restorer"
        out = b"".join(stream(content[i:i + chunk]) for i in range(0, len(content), chunk))
        out += stream(b"")
        addon.response(flow)
        return out
    addon.response(flow)
    return flow.response.content


def reply_text(provider, body: bytes, stream: bool) -> str:
    if not stream:
        data = json.loads(body)
        return data["choices"][0]["message"]["content"] if provider == "openai" else data["content"][0]["text"]
    text = ""
    for line in body.decode().split("\n"):
        if line.startswith("data: {"):
            event = json.loads(line[6:])
            if provider == "openai":
                text += "".join(c["delta"].get("content", "") for c in event["choices"])
            elif event.get("type") == "content_block_delta":
                text += event["delta"]["text"]
    return text


# ------------------------------------------------------------------ round trips

@pytest.mark.parametrize("provider", PROVIDERS)
def test_round_trip_non_streaming(provider, capsys):
    flow = send(provider)
    sent = flow.request.get_text()
    assert SECRET not in sent and EMAIL not in sent                 # placeholders went upstream
    assert re.search(r'DB_PASSWORD = \\"PA_HARDCODED_SECRET_[0-9A-F]{8}\\"', sent)

    r = upstream(flow)
    assert "PA_HARDCODED_SECRET_" in r.text                          # the LLM saw placeholders only
    body = deliver(flow, r.status_code, r.content, r.headers["content-type"])

    assert reply_text(provider, body, stream=False) == EXPECTED_REPLY   # originals back
    restore = flow.metadata["proxy_armour"]["restore"]
    assert restore == {"issued": 2, "restored": 2, "missing": 0, "unknown": 0,
                       "leaked_types": [], "syntax_valid": True}
    assert len(addon.VAULT) == 0                                     # map deleted
    logs = capsys.readouterr().out
    assert SECRET not in logs and EMAIL not in logs                  # never logged


@pytest.mark.parametrize("provider", PROVIDERS)
@pytest.mark.parametrize("chunk", [1, 7, 64, 100_000], ids=["1B", "7B", "64B", "whole"])
def test_round_trip_streaming(provider, chunk, capsys):
    flow = send(provider, stream=True)
    r = upstream(flow)
    assert r.headers["content-type"].startswith("text/event-stream")
    body = deliver(flow, r.status_code, r.content, r.headers["content-type"], chunk=chunk)

    assert reply_text(provider, body, stream=True) == EXPECTED_REPLY
    restore = flow.metadata["proxy_armour"]["restore"]
    assert (restore["restored"], restore["missing"], restore["syntax_valid"]) == (2, 0, True)
    assert len(addon.VAULT) == 0 and "proxy_armour_stream" not in flow.metadata
    logs = capsys.readouterr().out
    assert SECRET not in logs and EMAIL not in logs


def test_same_value_same_placeholder_across_messages():
    body = {"model": "m", "messages": [{"role": "user", "content": f"from {EMAIL}"},
                                       {"role": "assistant", "content": "ok"},
                                       {"role": "user", "content": f"reply to {EMAIL}"}]}
    flow = send("openai", body=body)
    sent = json.loads(flow.request.get_text())["messages"]
    first, last = sent[0]["content"].split()[-1], sent[2]["content"].split()[-1]
    assert first == last and first.startswith("PA_EMAIL_")
    r = upstream(flow)
    assert reply_text("openai", deliver(flow, 200, r.content, "application/json"), False) == f"You said: reply to {EMAIL}"


def test_unknown_placeholder_in_response_is_untouched():
    flow = send("openai", prompt=f"mail {EMAIL}")
    (issued,) = re.findall(r"PA_EMAIL_[0-9A-F]{8}", flow.request.get_text())
    reply = {"choices": [{"message": {"content": f"{issued} / PA_EMAIL_DEADBEEF"}}]}
    body = deliver(flow, 200, json.dumps(reply).encode(), "application/json")
    assert json.loads(body)["choices"][0]["message"]["content"] == f"{EMAIL} / PA_EMAIL_DEADBEEF"
    assert flow.metadata["proxy_armour"]["restore"]["unknown"] == 1


def test_leak_is_flagged_and_logged_without_the_value(capsys):
    flow = send("openai", prompt=f"mail {EMAIL}")
    reply = {"choices": [{"message": {"content": f"I already know {EMAIL}"}}]}
    deliver(flow, 200, json.dumps(reply).encode(), "application/json")
    assert flow.metadata["proxy_armour"]["restore"]["leaked_types"] == ["EMAIL"]
    logs = capsys.readouterr().out
    assert "[ARMOUR] LEAK" in logs and EMAIL not in logs


# ------------------------------------------------------------------ map lifetime

def test_map_lives_until_the_response_then_is_deleted():
    flow = send("openai", prompt=f"mail {EMAIL}")
    assert flow.id in addon.VAULT
    r = upstream(flow)
    deliver(flow, 200, r.content, "application/json")
    assert flow.id not in addon.VAULT and len(addon.VAULT) == 0


def test_upstream_error_deletes_the_map():
    flow = send("openai", prompt=f"mail {EMAIL}")
    addon.error(flow)
    assert len(addon.VAULT) == 0


def test_ttl_expiry_means_no_restoration_and_no_leak(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(addon, "VAULT", TokenVault(ttl_seconds=120, clock=clock))
    flow = send("openai", prompt=f"mail {EMAIL}")
    clock.now += 121                                     # the LLM took too long
    assert addon.VAULT.purge_expired() == 1
    r = upstream(flow)
    body = deliver(flow, 200, r.content, "application/json")
    text = reply_text("openai", body, stream=False)
    assert EMAIL not in text and "PA_EMAIL_" in text     # placeholders stay - nothing to restore
    assert flow.metadata["proxy_armour"]["restore"] == {"expired": True}


def test_compressed_stream_is_not_restored_but_never_leaks():
    flow = send("openai", stream=True)
    r = upstream(flow)
    flow.response = http.Response.make(200, b"", {"content-type": "text/event-stream",
                                                  "content-encoding": "gzip"})
    addon.responseheaders(flow)
    assert not callable(flow.response.stream)
    assert len(addon.VAULT) == 0


def test_blocked_and_allowed_requests_store_nothing():
    send("openai", prompt="aadhaar 2345 6789 0124")
    send("openai", prompt="What is the capital of France?")
    assert len(addon.VAULT) == 0


# ------------------------------------------------------------------ demo mode

def test_demo_mode_routes_to_the_mock(monkeypatch):
    monkeypatch.setattr(addon, "DEMO", DemoSettings(enabled=True, upstream_host="127.0.0.1",
                                                    upstream_port=9000))
    flow = send("openai", prompt=f"mail {EMAIL}")
    assert (flow.request.scheme, flow.request.host, flow.request.port) == ("http", "127.0.0.1", 9000)
    assert flow.metadata["proxy_armour"]["host"] == "api.openai.com"   # logs keep the real target

    blocked = send("openai", prompt="aadhaar 2345 6789 0124")
    assert blocked.request.host == "api.openai.com" and blocked.response.status_code == 403


def test_timing_log_has_durations_only(monkeypatch, tmp_path):
    log = tmp_path / "timing.jsonl"
    monkeypatch.setattr(addon, "TIMING_LOG", str(log))
    flow = send("openai")
    r = upstream(flow)
    deliver(flow, r.status_code, r.content, r.headers["content-type"])
    (line,) = log.read_text(encoding="utf-8").splitlines()
    record = json.loads(line)
    assert set(record) == {"action", "bytes", "parse_ms", "detect_ms", "tokenize_ms", "verify_ms", "restore_ms"}
    assert record["action"] == "tokenize" and all(v >= 0 for k, v in record.items() if k.endswith("_ms"))
    assert SECRET not in line and EMAIL not in line and "PA_" not in line

"""Tests for the proxy addon - pure functions plus the request hook driven with
mitmproxy's test flows (no live proxy, no network)."""
import asyncio
import json
import re

import httpx
import pytest
from mitmproxy import http
from mitmproxy.test import tflow

from app.main import app as scanner_app
from armour_config import UnsupportedBodySettings
from proxy import armour_addon as addon
from proxy.armour_addon import extract_prompt, is_llm_host, text_slots
from proxy.tokenization import PLACEHOLDER_PATTERN, TokenVault, tokenize_slots

# obviously fake test data
AWS = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "rahul@acme.com"
AADHAAR = "2345 6789 0124"     # fake, Verhoeff-valid
PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="


# ------------------------------------------------------------ provider formats

def openai_chat(text):
    return {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": text}]}


def openai_chat_parts(text):
    return {"model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}]}


def anthropic_system_str(text):
    return {"model": "claude-x", "system": text,
            "messages": [{"role": "user", "content": "hi"}]}


def anthropic_system_blocks(text):
    return {"model": "claude-x", "system": [{"type": "text", "text": text}],
            "messages": [{"role": "user", "content": "hi"}]}


def gemini(text):
    return {"contents": [{"role": "user", "parts": [{"text": text}]}]}


def responses_str(text):
    return {"model": "gpt-4o-mini", "input": text}


def responses_list(text):
    return {"model": "gpt-4o-mini",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": text}]}]}


FORMATS = [openai_chat, openai_chat_parts, anthropic_system_str, anthropic_system_blocks,
           gemini, responses_str, responses_list]
FORMAT_IDS = [f.__name__ for f in FORMATS]


# ------------------------------------------------------------ walker (bug 1)

@pytest.mark.parametrize("fmt", FORMATS, ids=FORMAT_IDS)
def test_text_is_found_in_every_provider_format(fmt):
    assert AWS in extract_prompt(fmt(f"my key {AWS}"))


def test_metadata_keys_are_skipped():
    data = {"model": "gpt-4o", "messages": [{"role": "user", "id": "msg_1", "content": "hi"}]}
    assert extract_prompt(data) == "hi"


@pytest.mark.parametrize("data", [
    # OpenAI image_url data URL
    {"messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG_B64}"}}]}]},
    # OpenAI Responses input_image
    {"input": [{"role": "user", "content": [
        {"type": "input_image", "image_url": f"data:image/png;base64,{PNG_B64}"}]}]},
    # Anthropic base64 image source
    {"messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": PNG_B64}}]}]},
    # Gemini inline_data
    {"contents": [{"parts": [{"inline_data": {"mime_type": "image/png", "data": PNG_B64}}]}]},
], ids=["openai-image-url", "responses-input-image", "anthropic-base64", "gemini-inline-data"])
def test_base64_image_data_is_skipped(data):
    # the image bytes are not scanned (labels like "image/png" may be - harmless)
    assert PNG_B64 not in extract_prompt(data)


def test_text_hidden_in_a_binary_slot_is_still_scanned():
    # structure says base64, but the content clearly isn't - scan it
    data = {"source": {"type": "base64", "media_type": "image/png", "data": f"mail {EMAIL}"}}
    assert EMAIL in extract_prompt(data)


def test_anthropic_plain_text_document_is_scanned():
    data = {"source": {"type": "text", "media_type": "text/plain", "data": f"mail {EMAIL}"}}
    assert EMAIL in extract_prompt(data)


def test_unknown_fields_are_scanned_by_default():
    # deny-list of non-text, not allow-list of text: new API fields are covered
    assert AWS in extract_prompt({"some_future_field": {"notes": [AWS]}})


def test_deeply_nested_json_does_not_crash():
    data = AWS
    for _ in range(5000):
        data = [data]
    assert extract_prompt(data) == AWS


def test_non_container_has_no_slots():
    assert text_slots("just a string") == []


# ------------------------------------------------------------ tokenize_slots

def tok(data, *findings):
    """tokenize_slots over the request's text slots; findings are (type, value)."""
    return tokenize_slots(text_slots(data), [{"type": t, "value": v, "action": "tokenize"}
                                             for t, v in findings])


@pytest.mark.parametrize("fmt", FORMATS, ids=FORMAT_IDS)
def test_tokenize_rewrites_in_place_for_every_format(fmt):
    data = fmt(f"mail {EMAIL} please")
    mapping = tok(data, ("EMAIL", EMAIL))
    (placeholder, original), = mapping.items()
    assert original == EMAIL and re.fullmatch(r"PA_EMAIL_[0-9A-F]{8}", placeholder)
    assert EMAIL not in json.dumps(data)
    assert data == fmt(f"mail {placeholder} please")      # structure untouched


def test_tokenize_replaces_longer_values_first():
    data = openai_chat("id 9876543210@gmail.com")
    mapping = tok(data, ("PHONE_IN", "9876543210"), ("EMAIL", "9876543210@gmail.com"))
    (placeholder,) = mapping                               # the phone was never on its own
    assert data["messages"][0]["content"] == f"id {placeholder}"
    assert placeholder.startswith("PA_EMAIL_")


def test_tokenize_does_not_touch_metadata():
    data = {"model": EMAIL, "messages": [{"role": "user", "content": EMAIL}]}
    (placeholder,) = tok(data, ("EMAIL", EMAIL))
    assert data["model"] == EMAIL                          # skipped key, left alone
    assert data["messages"][0]["content"] == placeholder


# ------------------------------------------------------------ host matching (bug 5)

@pytest.mark.parametrize("host", [
    "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com",
    "contoso.openai.azure.com", "a.b.openai.azure.com", "api.mistral.ai", "api.groq.com",
    "API.OpenAI.com", "api.openai.com.",
])
def test_llm_hosts_match(host):
    assert is_llm_host(host)


@pytest.mark.parametrize("host", [
    "openai.azure.com",            # wildcard needs a subdomain
    "evilopenai.azure.com",        # no dot before openai
    "openai.azure.com.evil.com",   # suffix not at the end
    "api.openai.com.evil.com",
    "example.com",
])
def test_lookalike_hosts_do_not_match(host):
    assert not is_llm_host(host)


# ------------------------------------------------------------ request hook

def make_flow(body, host="api.openai.com", content_type="application/json", method="POST"):
    content = body if isinstance(body, (bytes, str)) else json.dumps(body)
    headers = {"content-type": content_type} if content_type else {}
    return tflow.tflow(req=http.Request.make(method, f"https://{host}/v1/x", content, headers))


def run(flow):
    asyncio.run(addon.request(flow))
    return flow


def use_scanner(monkeypatch, transport):
    monkeypatch.setattr(addon, "scanner", httpx.AsyncClient(transport=transport))


@pytest.fixture(autouse=True)
def fresh_vault(monkeypatch):
    monkeypatch.setattr(addon, "VAULT", TokenVault(ttl_seconds=120))


@pytest.fixture
def real_scanner(monkeypatch):
    # the real FastAPI scanner, called in-memory (no server, no network)
    use_scanner(monkeypatch, httpx.ASGITransport(app=scanner_app))


def body_json(flow):
    return json.loads(flow.response.text)


@pytest.mark.parametrize("fmt", FORMATS, ids=FORMAT_IDS)
def test_block_policy_type_is_blocked_in_every_format(real_scanner, fmt):
    flow = run(make_flow(fmt(f"aadhaar {AADHAAR}")))
    assert flow.response.status_code == 403
    assert body_json(flow)["error"]["detected"] == ["AADHAAR"]
    assert AADHAAR not in flow.response.text       # never echo the value
    assert flow.id not in addon.VAULT


@pytest.mark.parametrize("fmt", FORMATS, ids=FORMAT_IDS)
def test_secret_is_tokenized_in_every_format(real_scanner, fmt):
    flow = run(make_flow(fmt(f"key {AWS}")))
    assert flow.response is None                   # forwarded...
    sent = flow.request.get_text()
    assert AWS not in sent                         # ...without the secret
    assert re.search(r"PA_AWS_KEY_[0-9A-F]{8}", sent)
    assert flow.id in addon.VAULT
    assert flow.request.headers["accept-encoding"] == "identity"


@pytest.mark.parametrize("host", ["contoso.openai.azure.com", "api.mistral.ai", "api.groq.com"])
def test_new_hosts_are_inspected(real_scanner, host):
    assert run(make_flow(openai_chat(f"aadhaar {AADHAAR}"), host=host)).response.status_code == 403


def test_email_is_tokenized_and_forwarded(real_scanner):
    flow = run(make_flow(gemini(f"mail {EMAIL}")))
    assert flow.response is None                   # forwarded
    sent = json.loads(flow.request.get_text())
    placeholder = sent["contents"][0]["parts"][0]["text"].removeprefix("mail ")
    assert re.fullmatch(r"PA_EMAIL_[0-9A-F]{8}", placeholder)
    record = flow.metadata["proxy_armour"]
    assert {k: record[k] for k in ("host", "action", "risk", "types", "finding_count",
                                   "detectors", "tokenized")} == {
        "host": "api.openai.com", "action": "tokenize", "risk": "low", "types": ["EMAIL"],
        "finding_count": 1, "detectors": ["regex"], "tokenized": 1}
    assert record["scan_ms"] > 0


def test_clean_request_is_forwarded_unchanged(real_scanner):
    original = json.dumps(openai_chat("What is the capital of France?"))
    flow = run(make_flow(original))
    assert flow.response is None
    assert flow.request.get_text() == original


SPLIT_PHONE = {"messages": [{"role": "user", "content": [
    {"type": "text", "text": "call +91"}, {"type": "text", "text": "9876543210"}]}]}


def test_match_spanning_two_fields_is_blocked_not_leaked(monkeypatch):
    # a detector reports ONE value spanning two JSON fields ("+91\n9876543210");
    # it exists in neither field, so replace() can't remove it - the verify
    # re-scan must catch what is left and block
    def handler(request):
        text = json.loads(request.content)["text"]
        if "9876543210" not in text:
            return httpx.Response(200, json={"risk": "none", "action": "allow", "findings": []})
        return httpx.Response(200, json={"risk": "low", "action": "tokenize", "findings": [
            {"type": "PHONE_IN", "value": "+91\n9876543210", "action": "tokenize"}]})

    use_scanner(monkeypatch, httpx.MockTransport(handler))
    flow = run(make_flow(SPLIT_PHONE))
    assert flow.response.status_code == 403
    assert "9876543210" not in flow.response.text


def test_real_detectors_do_not_join_fields(real_scanner):
    # number separators are space/dash only, never \n - so the phone is found
    # inside its own field and tokenized there
    flow = run(make_flow(SPLIT_PHONE))
    assert flow.response is None
    assert "9876543210" not in flow.request.get_text()
    assert "PA_PHONE_IN_" in flow.request.get_text()


def test_other_hosts_and_methods_are_ignored(real_scanner):
    assert run(make_flow(openai_chat(AWS), host="example.com")).response is None
    assert run(make_flow(openai_chat(AWS), method="GET")).response is None


# ------------------------------------------------------------ body types (bug 4)

def test_multipart_body_is_415(real_scanner):
    flow = run(make_flow(b"--xyz\r\nContent-Disposition: form-data; name=file\r\n\r\ndata\r\n--xyz--",
                         content_type="multipart/form-data; boundary=xyz"))
    assert flow.response.status_code == 415
    assert "multipart/form-data" in body_json(flow)["error"]["message"]
    assert "boundary" not in body_json(flow)["error"]["message"]


def test_unsupported_body_status_is_configurable(real_scanner, monkeypatch):
    monkeypatch.setattr(addon, "UNSUPPORTED_BODY",
                        UnsupportedBodySettings(status=422, message="custom"))
    flow = run(make_flow(b"a=1&b=2", content_type="application/x-www-form-urlencoded"))
    assert flow.response.status_code == 422
    assert body_json(flow)["error"]["message"].startswith("custom")


@pytest.mark.parametrize("body,content_type", [
    (b"{not json", "application/json"),
    (b"{not json", None),
    (b'"just a string"', "application/json"),
], ids=["malformed-json", "malformed-no-content-type", "json-scalar"])
def test_bad_json_is_400(real_scanner, body, content_type):
    assert run(make_flow(body, content_type=content_type)).response.status_code == 400


def test_empty_body_is_forwarded(real_scanner):
    assert run(make_flow(b"")).response is None


# ------------------------------------------------------------ fail closed (bug 2)

def _raise_connect(request):
    raise httpx.ConnectError("connection refused")


def _raise_timeout(request):
    raise httpx.ReadTimeout("timed out")


@pytest.mark.parametrize("handler", [
    lambda r: httpx.Response(200, text="<html>not json</html>"),
    lambda r: httpx.Response(200, json={"risk": "none"}),                       # missing keys
    lambda r: httpx.Response(200, json={"risk": "none", "action": "maybe", "findings": []}),
    lambda r: httpx.Response(200, json=["not", "an", "object"]),
    lambda r: httpx.Response(500, json={"risk": "none", "action": "allow", "findings": []}),
    lambda r: httpx.Response(302, headers={"location": "http://elsewhere/"}),
    _raise_connect,
    _raise_timeout,
], ids=["non-json", "missing-keys", "unknown-action", "wrong-shape",
        "http-500", "http-302", "connection-refused", "timeout"])
def test_any_scanner_failure_blocks_with_503(monkeypatch, handler):
    use_scanner(monkeypatch, httpx.MockTransport(handler))
    flow = run(make_flow(openai_chat(f"key {AWS}")))
    assert flow.response.status_code == 503
    assert AWS not in flow.response.text


def test_scanner_failure_during_tokenize_verify_blocks(monkeypatch):
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(200, json={"risk": "low", "action": "tokenize", "findings": [
                {"type": "EMAIL", "value": EMAIL, "action": "tokenize"}]})
        return httpx.Response(500)

    use_scanner(monkeypatch, httpx.MockTransport(handler))
    flow = run(make_flow(openai_chat(f"mail {EMAIL}")))
    assert flow.response.status_code == 503
    assert len(calls) == 2


def test_unexpected_internal_error_blocks_with_500(real_scanner, monkeypatch):
    def broken(_):
        raise RuntimeError("bug")

    monkeypatch.setattr(addon, "extract_prompt", broken)
    flow = run(make_flow(openai_chat("hello")))
    assert flow.response.status_code == 500

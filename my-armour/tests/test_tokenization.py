"""Pure tokenization module: placeholders, restoration, vault/TTL, SSE streaming."""
import asyncio
import json
import re

import pytest

from proxy import tokenization
from proxy.tokenization import (
    PLACEHOLDER_PATTERN, StreamRestorer, TokenVault, new_placeholder, python_syntax_valid,
    restore_json, tokenize_slots,
)

EMAIL = "rahul@acme.com"
P_EMAIL = "PA_EMAIL_7D2E91F0"
P_SECRET = "PA_HARDCODED_SECRET_00C0FFEE"
MAPPING = {P_EMAIL: EMAIL, P_SECRET: 'hun"ter\n22'}     # quote + newline: JSON escaping must survive


def slots_of(*texts):
    holder = list(texts)
    return holder, [(holder, i) for i in range(len(holder))]


def tokenize(*texts, findings):
    holder, slots = slots_of(*texts)
    mapping = tokenize_slots(slots, [{"action": "tokenize", **f} for f in findings])
    return holder, mapping


# ------------------------------------------------------------------ placeholders

def test_placeholder_format():
    assert re.fullmatch(r"PA_EMAIL_[0-9A-F]{8}", new_placeholder("EMAIL", set()))
    assert PLACEHOLDER_PATTERN.fullmatch(new_placeholder("HARDCODED_SECRET", set()))


def test_placeholder_is_random_not_derived_from_the_value():
    (a,), (b,) = (tokenize(EMAIL, findings=[{"type": "EMAIL", "value": EMAIL}])[1] for _ in range(2))
    assert a != b       # same value in two requests -> unrelated placeholders


def test_placeholder_avoids_taken_and_existing_text(monkeypatch):
    values = iter(["aaaaaaaa", "bbbbbbbb", "cccccccc"])
    monkeypatch.setattr(tokenization.secrets, "token_hex", lambda n: next(values))
    assert new_placeholder("X", {"PA_X_AAAAAAAA"}, existing_text="see PA_X_BBBBBBBB") == "PA_X_CCCCCCCC"


# ------------------------------------------------------------------ tokenize_slots

def test_same_value_gets_the_same_placeholder():
    holder, mapping = tokenize(f"to {EMAIL}", f"cc {EMAIL} and {EMAIL}",
                               findings=[{"type": "EMAIL", "value": EMAIL}] * 3)
    (placeholder,) = mapping
    assert holder == [f"to {placeholder}", f"cc {placeholder} and {placeholder}"]


def test_different_values_get_different_placeholders():
    _, mapping = tokenize("a@x.com b@x.com", findings=[{"type": "EMAIL", "value": "a@x.com"},
                                                        {"type": "EMAIL", "value": "b@x.com"}])
    assert len(mapping) == 2 and set(mapping.values()) == {"a@x.com", "b@x.com"}


def test_only_tokenize_findings_are_replaced():
    holder, slots = slots_of("mail a@x.com aadhaar 2345 6789 0124")
    mapping = tokenize_slots(slots, [
        {"type": "EMAIL", "value": "a@x.com", "action": "tokenize"},
        {"type": "AADHAAR", "value": "2345 6789 0124", "action": "block"},
        {"type": "PHONE_IN", "value": "mail", "action": "allow"},
    ])
    assert list(mapping.values()) == ["a@x.com"]
    assert holder[0].startswith("mail PA_EMAIL_")


def test_placeholder_replaces_only_the_value_so_code_stays_valid():
    code = 'db = connect(password="hunter22", user="admin")'
    holder, mapping = tokenize(code, findings=[{"type": "HARDCODED_SECRET", "value": "hunter22"}])
    (placeholder,) = mapping
    assert holder[0] == f'db = connect(password="{placeholder}", user="admin")'
    compile(holder[0], "<test>", "exec")           # still valid Python


def test_most_specific_type_labels_a_shared_value():
    token = "ghp_" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
    _, mapping = tokenize(token, findings=[
        {"type": "HIGH_ENTROPY_STRING", "value": token, "detector": "entropy"},
        {"type": "GITHUB_TOKEN", "value": token, "detector": "regex"},
    ])
    assert next(iter(mapping)).startswith("PA_GITHUB_TOKEN_")


def test_one_pass_never_corrupts_an_inserted_placeholder(monkeypatch):
    # value "ABCD" also occurs inside the first placeholder's hex - a second
    # replace() pass would corrupt it; the single regex pass cannot
    hexes = iter(["1abcd234", "99999999"])
    monkeypatch.setattr(tokenization.secrets, "token_hex", lambda n: next(hexes))
    holder, mapping = tokenize("key LONGSECRETVALUE and ABCD",
                               findings=[{"type": "X", "value": "LONGSECRETVALUE"},
                                         {"type": "Y", "value": "ABCD"}])
    assert holder == ["key PA_X_1ABCD234 and PA_Y_99999999"]


# ------------------------------------------------------------------ restore_json

def test_restore_json_round_trip_and_stats():
    data = {"choices": [{"message": {"content": f"use {P_EMAIL} and {P_EMAIL}; pw={P_SECRET}"}}]}
    stats = restore_json(data, MAPPING)
    assert data["choices"][0]["message"]["content"] == f'use {EMAIL} and {EMAIL}; pw=hun"ter\n22'
    assert (stats.restored, stats.missing, stats.unknown) == (3, 0, 0)
    assert stats.leaked_types == [] and stats.syntax_valid is None


def test_missing_placeholders_are_counted():
    stats = restore_json({"text": f"only {P_EMAIL}"}, MAPPING)
    assert (stats.restored, stats.missing) == (1, 1)


def test_unknown_placeholder_is_left_untouched_and_counted():
    data = {"text": f"{P_EMAIL} and PA_EMAIL_DEADBEEF"}
    stats = restore_json(data, MAPPING)
    assert data["text"] == f"{EMAIL} and PA_EMAIL_DEADBEEF"
    assert stats.unknown == 1


def test_restored_value_that_looks_like_a_placeholder_is_not_restored_again():
    mapping = {"PA_A_11111111": "PA_B_22222222", "PA_B_22222222": "secret"}
    data = {"text": "PA_A_11111111"}
    restore_json(data, mapping)
    assert data["text"] == "PA_B_22222222"


def test_leak_is_flagged_when_an_original_comes_back_verbatim():
    stats = restore_json({"text": f"your email is {EMAIL}"}, MAPPING)
    assert stats.leaked_types == ["EMAIL"]
    assert EMAIL not in json.dumps(stats.as_dict())      # stats never carry values


@pytest.mark.parametrize("reply,expected", [
    (f"```python\npassword = \"{P_SECRET}\"\n```", False),    # restored value has a raw newline
    (f"```python\nemail = \"{P_EMAIL}\"\n```", True),
    (f"no code, just {P_EMAIL}", None),
])
def test_syntax_valid_is_recorded_after_restoration(reply, expected):
    assert restore_json({"text": reply}, MAPPING).syntax_valid is expected


def test_python_syntax_valid():
    assert python_syntax_valid(["```python\nx = 1\n```", "```py\ny = 2\n```"]) is True
    assert python_syntax_valid(["```python\nx = (\n```"]) is False
    assert python_syntax_valid(["```js\nnot python(\n```", "prose"]) is None


# ------------------------------------------------------------------ TokenVault / TTL

class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_vault_pop_returns_once_then_deletes():
    vault = TokenVault(ttl_seconds=120)
    vault.put("flow-1", MAPPING)
    assert "flow-1" in vault
    assert vault.pop("flow-1") == MAPPING
    assert vault.pop("flow-1") is None and len(vault) == 0


def test_vault_entry_expires_after_ttl():
    clock = FakeClock()
    vault = TokenVault(ttl_seconds=120, clock=clock)
    vault.put("flow-1", MAPPING)
    clock.now += 119
    assert "flow-1" in vault
    clock.now += 2
    assert "flow-1" not in vault
    assert vault.pop("flow-1") is None


def test_purge_expired_removes_only_expired():
    clock = FakeClock()
    vault = TokenVault(ttl_seconds=120, clock=clock)
    vault.put("old", MAPPING)
    clock.now += 100
    vault.put("new", MAPPING)
    clock.now += 30
    assert vault.purge_expired() == 1
    assert "old" not in vault and "new" in vault and len(vault) == 1


def test_background_cleanup_task_purges():
    clock = FakeClock()
    vault = TokenVault(ttl_seconds=1, clock=clock)
    vault.put("flow-1", MAPPING)
    clock.now += 5

    async def scenario():
        task = asyncio.create_task(vault.run_cleanup(0.01))
        await asyncio.sleep(0.05)
        task.cancel()

    asyncio.run(scenario())
    assert len(vault) == 0


def test_vault_repr_never_shows_values():
    vault = TokenVault(ttl_seconds=120)
    vault.put("flow-1", MAPPING)
    assert EMAIL not in repr(vault) and P_EMAIL not in repr(vault)


# ------------------------------------------------------------------ SSE streaming

def openai_sse(parts):
    events = [{"choices": [{"index": 0, "delta": {"content": p}, "finish_reason": None}]} for p in parts]
    events.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
    return ("".join(f"data: {json.dumps(e)}\n\n" for e in events) + "data: [DONE]\n\n").encode()


def anthropic_sse(parts):
    out = ['event: message_start\ndata: {"type":"message_start"}\n\n',
           'event: ping\ndata: {"type": "ping"}\n\n']
    out += [f'event: content_block_delta\ndata: {json.dumps({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p}})}\n\n'
            for p in parts]
    out += ['event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n',
            'event: message_stop\ndata: {"type":"message_stop"}\n\n']
    return "".join(out).encode()


def responses_sse(parts, full):
    out = [f'event: response.output_text.delta\ndata: {json.dumps({"type": "response.output_text.delta", "delta": p})}\n\n' for p in parts]
    out.append(f'event: response.output_text.done\ndata: {json.dumps({"type": "response.output_text.done", "text": full})}\n\n')
    return "".join(out).encode()


def gemini_sse(parts):
    return "".join(f'data: {json.dumps({"candidates": [{"content": {"parts": [{"text": p}], "role": "model"}}]})}\r\n\r\n'
                   for p in parts).encode()


def deltas(out: bytes) -> str:
    text = ""
    for line in out.decode().split("\n"):
        if not line.startswith("data: {"):
            continue
        event = json.loads(line[6:])
        if "choices" in event:
            text += "".join(c["delta"].get("content", "") for c in event["choices"])
        elif event.get("type") in ("content_block_delta", "response.output_text.delta"):
            text += event["delta"]["text"] if event["type"] == "content_block_delta" else event["delta"]
        elif "candidates" in event:
            text += event["candidates"][0]["content"]["parts"][0]["text"]
    return text


def run_stream(raw: bytes, cuts=(), mapping=MAPPING):
    restorer = StreamRestorer(mapping)
    out, last = b"", 0
    for cut in list(cuts) + [len(raw)]:
        out += restorer(raw[last:cut])
        last = cut
    return out + restorer(b""), restorer


REPLY = f"Mail {P_EMAIL}, pw {P_SECRET} ✓ end P"
RESTORED = 'Mail rahul@acme.com, pw hun"ter\n22 ✓ end P'


def split(text, size):
    return [text[i:i + size] for i in range(0, len(text), size)]


@pytest.mark.parametrize("fmt", [openai_sse, anthropic_sse, gemini_sse], ids=["openai", "anthropic", "gemini"])
@pytest.mark.parametrize("token_size", [1, 3, 5, 11])
def test_placeholder_split_across_events_is_restored(fmt, token_size):
    out, restorer = run_stream(fmt(split(REPLY, token_size)))
    assert deltas(out) == RESTORED
    assert (restorer.stats.restored, restorer.stats.missing) == (2, 0)


@pytest.mark.parametrize("fmt", [openai_sse, anthropic_sse], ids=["openai", "anthropic"])
def test_every_network_chunk_boundary(fmt):
    raw = fmt(split(REPLY, 4))
    for cut in range(1, len(raw)):
        out, _ = run_stream(raw, cuts=[cut])
        assert deltas(out) == RESTORED, f"failed at byte {cut}"


def test_one_byte_chunks_with_multibyte_characters():
    raw = openai_sse(split(REPLY, 3))
    out, _ = run_stream(raw, cuts=range(1, len(raw)))
    assert deltas(out) == RESTORED


def test_held_text_is_flushed_before_the_finish_event_and_done_passes_through():
    out, _ = run_stream(openai_sse(["see P", "A_EM"]))      # stream ends mid-placeholder
    events = [e for e in out.decode().split("\n\n") if e]
    assert deltas(out) == "see PA_EM"                        # nothing lost, nothing invented
    assert events[-1] == "data: [DONE]" and events.count("data: [DONE]") == 1
    assert '"finish_reason": "stop"' in events[-2]


def test_responses_api_done_event_is_restored_but_not_duplicated():
    raw = responses_sse(split(REPLY, 4), REPLY)
    out, _ = run_stream(raw)
    assert deltas(out) == RESTORED
    done = [e for e in out.decode().split("\n\n") if "output_text.done" in e]
    assert len(done) == 1 and json.loads(done[0].split("data: ")[1])["text"] == RESTORED


def test_unknown_placeholder_in_stream_is_untouched():
    out, restorer = run_stream(openai_sse(split("x PA_EMAIL_DEADBEEF y", 3)))
    assert deltas(out) == "x PA_EMAIL_DEADBEEF y"
    assert restorer.stats.unknown == 1


def test_stream_leak_and_syntax_checks():
    reply = f"leak {EMAIL}\n```python\nemail = \"{P_EMAIL}\"\n```\n"
    _, restorer = run_stream(openai_sse(split(reply, 4)))
    assert restorer.stats.leaked_types == ["EMAIL"]
    assert restorer.stats.syntax_valid is True


def test_untouched_events_pass_through_byte_for_byte():
    raw = b'event: ping\ndata: {"type": "ping"}\n\n: keep-alive comment\n\n'
    out, _ = run_stream(raw)
    assert out == raw


def test_data_after_an_empty_chunk_is_still_restored():
    raw = openai_sse(split(REPLY, 4))
    restorer = StreamRestorer(MAPPING)
    out = restorer(raw[:50]) + restorer(b"") + restorer(raw[50:]) + restorer(b"")
    assert P_EMAIL not in deltas(out) and EMAIL in deltas(out)


def test_close_drops_every_original():
    _, restorer = run_stream(openai_sse(split(REPLY, 4)))
    stats = restorer.stats.as_dict()
    restorer.close()
    assert restorer.stats.as_dict() == stats
    assert restorer.restorer.restore(P_EMAIL) == P_EMAIL       # can't restore any more
    assert EMAIL not in repr(vars(restorer))

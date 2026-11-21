import json

from fastapi.testclient import TestClient

from mock_llm.app import CHUNK_SIZE, EDIT_LINE, app, reply_for

client = TestClient(app)
CODE_PROMPT = "fix:\n```python\nx = 1\n```"


def sse_events(text):
    events = []
    for block in text.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.split("\n"))
        events.append((lines.get("event"), lines["data"]))
    return events


def test_reply_echoes_code_with_an_edit():
    assert reply_for(CODE_PROMPT) == f"Here is your code with a small edit:\n\n```python\n{EDIT_LINE}\nx = 1\n```\n"
    assert reply_for("hello") == "You said: hello"


def test_openai_non_streaming():
    r = client.post("/v1/chat/completions", json={"model": "m", "messages": [
        {"role": "system", "content": "be nice"}, {"role": "user", "content": CODE_PROMPT}]})
    msg = r.json()["choices"][0]["message"]
    assert msg["role"] == "assistant" and EDIT_LINE in msg["content"]


def test_openai_streaming_shape():
    r = client.post("/v1/chat/completions", json={"model": "m", "stream": True,
                                                  "messages": [{"role": "user", "content": "hello there"}]})
    assert r.headers["content-type"].startswith("text/event-stream")
    events = sse_events(r.text)
    assert events[-1] == (None, "[DONE]")
    chunks = [json.loads(d) for _, d in events[:-1]]
    pieces = [c["choices"][0]["delta"].get("content", "") for c in chunks]
    assert "".join(pieces) == "You said: hello there"
    assert max(map(len, pieces)) == CHUNK_SIZE
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"


def test_anthropic_non_streaming_with_content_blocks():
    r = client.post("/v1/messages", json={"model": "m", "max_tokens": 10, "messages": [
        {"role": "user", "content": [{"type": "text", "text": "hello"}]}]})
    assert r.json()["content"] == [{"type": "text", "text": "You said: hello"}]


def test_anthropic_streaming_event_order():
    r = client.post("/v1/messages", json={"model": "m", "max_tokens": 10, "stream": True,
                                          "messages": [{"role": "user", "content": "hello"}]})
    names = [name for name, _ in sse_events(r.text)]
    assert names[:3] == ["message_start", "content_block_start", "ping"]
    assert names[-3:] == ["content_block_stop", "message_delta", "message_stop"]
    text = "".join(json.loads(d)["delta"]["text"] for n, d in sse_events(r.text) if n == "content_block_delta")
    assert text == "You said: hello"


def test_gemini_generate_content():
    r = client.post("/v1beta/models/gemini-2.0-flash:generateContent",
                    json={"contents": [{"role": "user", "parts": [{"text": "hello"}]}]})
    assert r.json()["candidates"][0]["content"]["parts"][0]["text"] == "You said: hello"
    assert client.post("/v1beta/models/x:countTokens", json={}).status_code == 404


def test_responses_api_string_and_list_input():
    r = client.post("/v1/responses", json={"model": "m", "input": "hello"})
    assert r.json()["output"][0]["content"][0]["text"] == "You said: hello"
    r = client.post("/v1/responses", json={"input": [
        {"role": "user", "content": [{"type": "input_text", "text": "hi"}]}]})
    assert r.json()["output"][0]["content"][0]["text"] == "You said: hi"


def test_azure_and_groq_paths_are_openai_compatible():
    body = {"messages": [{"role": "user", "content": "hello"}]}
    for path in ("/openai/deployments/my-gpt/chat/completions", "/openai/v1/chat/completions"):
        assert client.post(path, json=body).json()["choices"][0]["message"]["content"] == "You said: hello"

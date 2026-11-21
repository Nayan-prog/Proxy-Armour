"""A misbehaving LLM for integrity testing: answers like mock_llm (echoes the fenced
code), then damages placeholders in its reply the way a real model might.

    X-Mangle: none | drop | alter_case | truncate | split | duplicate | forge | leak
    X-Mangle-Seed: int (which placeholder occurrence is hit)
    X-Leak-Id: key into LEAK_VALUES (leak mode: the "provider" already knows a value)

OpenAI chat-completions format, JSON or SSE (stream: true).
"""
import random
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from mock_llm.app import _sse, chunks, last_user_text, reply_for

PLACEHOLDER = re.compile(r"PA_[A-Z][A-Z0-9_]*?_[0-9A-F]{8}")
FORGED = "PA_EMAIL_DEADBEEF"
LEAK_VALUES: dict[str, str] = {}          # filled by the harness (in-process only)

app = FastAPI(title="mangling mock LLM")


def mangle(reply: str, op: str, seed: int, leak_value: str | None = None) -> str:
    found = list(PLACEHOLDER.finditer(reply))
    if op in ("drop", "alter_case", "truncate", "split", "duplicate") and not found:
        return reply
    rng = random.Random(seed)
    m = found[rng.randrange(len(found))] if found else None
    if op == "drop":
        return reply[:m.start()] + reply[m.end():]
    if op == "alter_case":                 # PA_EMAIL_7D2E91F0 -> pa_email_7d2e91f0
        return reply[:m.start()] + m.group().lower() + reply[m.end():]
    if op == "truncate":                   # last hex digit lost
        return reply[:m.start()] + m.group()[:-1] + reply[m.end():]
    if op == "split":                      # tokenizer-style space inside
        cut = m.start() + len(m.group()) // 2
        return reply[:cut] + " " + reply[cut:]
    if op == "duplicate":
        return reply + f"\nAs noted above: {m.group()}\n"
    if op == "forge":                      # a placeholder that was never issued
        return reply + f"\nAlso check {FORGED}.\n"
    if op == "leak" and leak_value:        # the model "already knew" an original
        return reply + f"\nFor reference: {leak_value}\n"
    return reply


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    op = request.headers.get("x-mangle", "none")
    seed = int(request.headers.get("x-mangle-seed", "0"))
    reply = mangle(reply_for(last_user_text(body.get("messages"))), op, seed,
                   LEAK_VALUES.get(request.headers.get("x-leak-id", "")))
    base = {"id": "chatcmpl-mangle", "created": 0, "model": body.get("model", "m")}
    if not body.get("stream"):
        return JSONResponse({**base, "object": "chat.completion", "choices": [
            {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": reply}}]})

    def events():
        chunk = {**base, "object": "chat.completion.chunk"}
        for piece in chunks(reply):
            yield _sse({**chunk, "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": None}]})
        yield _sse({**chunk, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        yield "data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")

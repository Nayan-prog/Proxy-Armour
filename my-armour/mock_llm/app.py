"""A tiny stand-in for the OpenAI and Anthropic APIs, for demos and tests.

It answers like a code assistant would: if the last user message contains a
``` fenced block, it echoes that code back with one small edit (a comment line
added at the top); otherwise it echoes the text. Placeholders therefore come
back exactly as a real model would return them.

Streaming answers are sent in CHUNK_SIZE-character deltas, so every placeholder
is split across several SSE events - the hardest case for restoration.

    POST /v1/chat/completions   OpenAI   (stream: true -> SSE chunks + [DONE])
    POST /v1/messages           Anthropic (stream: true -> typed SSE events)
"""
import json
import os
import re
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

CHUNK_SIZE = 4
EDIT_LINE = "# reviewed by mock-llm"
_FENCE = re.compile(r"```([^\n]*)\n(.*?)```", re.DOTALL)

app = FastAPI(title="Proxy Armour mock LLM")


def _text_of(content) -> str:
    """Message content is a string or a list of blocks (OpenAI parts / Anthropic blocks)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(part.get("text", "") for part in content
                         if isinstance(part, dict) and isinstance(part.get("text"), str))
    return ""


def last_user_text(messages) -> str:
    for message in reversed(messages or []):
        if isinstance(message, dict) and message.get("role") == "user":
            return _text_of(message.get("content"))
    return ""


def show_received(user_text: str) -> None:
    """Demo aid (MOCK_LLM_SHOW_RECEIVED=1): print what the "provider" received - i.e.
    the tokenized prompt. This is the LLM's side of the wire, not Proxy Armour's logs."""
    if os.environ.get("MOCK_LLM_SHOW_RECEIVED") == "1":
        print(f"[MOCK-LLM provider view] received: {user_text[:400]!r}", flush=True)


def reply_for(user_text: str) -> str:
    match = _FENCE.search(user_text)
    if match:
        lang, code = match.group(1).strip() or "python", match.group(2)
        edited = f"{EDIT_LINE}\n{code}"
        if not edited.endswith("\n"):
            edited += "\n"
        return f"Here is your code with a small edit:\n\n```{lang}\n{edited}```\n"
    return f"You said: {user_text}"


def chunks(text: str):
    return [text[i:i + CHUNK_SIZE] for i in range(0, len(text), CHUNK_SIZE)]


def _sse(obj, event: str | None = None) -> str:
    prefix = f"event: {event}\n" if event else ""
    return f"{prefix}data: {json.dumps(obj)}\n\n"


# ---------------------------------------------------------------- OpenAI

@app.post("/v1/chat/completions")                               # OpenAI, Mistral
@app.post("/openai/v1/chat/completions")                        # Groq
@app.post("/openai/deployments/{deployment}/chat/completions")  # Azure OpenAI
async def chat_completions(request: Request):
    body = await request.json()
    user_text = last_user_text(body.get("messages"))

    show_received(user_text)

    reply = reply_for(user_text)
    model = body.get("model", "mock-gpt")
    created = int(time.time())
    base = {"id": "chatcmpl-mock", "created": created, "model": model}

    if not body.get("stream"):
        return JSONResponse({
            **base, "object": "chat.completion",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": reply}}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    def events():
        chunk = {**base, "object": "chat.completion.chunk"}
        yield _sse({**chunk, "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""},
                                          "finish_reason": None}]})
        for piece in chunks(reply):
            yield _sse({**chunk, "choices": [{"index": 0, "delta": {"content": piece},
                                              "finish_reason": None}]})
        yield _sse({**chunk, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
        yield "data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


# ---------------------------------------------------------------- Anthropic

@app.post("/v1/messages")
async def messages(request: Request):
    body = await request.json()
    user_text = last_user_text(body.get("messages"))

    show_received(user_text)

    reply = reply_for(user_text)
    model = body.get("model", "mock-claude")
    message = {"id": "msg_mock", "type": "message", "role": "assistant", "model": model,
               "stop_reason": "end_turn", "stop_sequence": None,
               "usage": {"input_tokens": 0, "output_tokens": 0}}

    if not body.get("stream"):
        return JSONResponse({**message, "content": [{"type": "text", "text": reply}]})

    def events():
        yield _sse({"type": "message_start",
                    "message": {**message, "content": [], "stop_reason": None}}, "message_start")
        yield _sse({"type": "content_block_start", "index": 0,
                    "content_block": {"type": "text", "text": ""}}, "content_block_start")
        yield _sse({"type": "ping"}, "ping")
        for piece in chunks(reply):
            yield _sse({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "text_delta", "text": piece}}, "content_block_delta")
        yield _sse({"type": "content_block_stop", "index": 0}, "content_block_stop")
        yield _sse({"type": "message_delta", "delta": {"stop_reason": "end_turn"},
                    "usage": {"output_tokens": 0}}, "message_delta")
        yield _sse({"type": "message_stop"}, "message_stop")

    return StreamingResponse(events(), media_type="text/event-stream")


# ---------------------------------------------------------------- Gemini

def _gemini_user_text(contents) -> str:
    for content in reversed(contents or []):
        if isinstance(content, dict) and content.get("role", "user") == "user":
            return "\n".join(p.get("text", "") for p in content.get("parts", [])
                             if isinstance(p, dict) and isinstance(p.get("text"), str))
    return ""


@app.post("/v1beta/models/{model_and_method}")
async def gemini_generate(model_and_method: str, request: Request):
    # e.g. /v1beta/models/gemini-2.0-flash:generateContent
    if not model_and_method.endswith(":generateContent"):
        return JSONResponse({"error": {"message": "mock supports :generateContent only"}}, status_code=404)
    body = await request.json()
    user_text = _gemini_user_text(body.get("contents"))

    show_received(user_text)

    reply = reply_for(user_text)
    return JSONResponse({
        "candidates": [{"content": {"role": "model", "parts": [{"text": reply}]},
                        "finishReason": "STOP", "index": 0}],
        "modelVersion": model_and_method.split(":")[0],
    })


# ---------------------------------------------------------------- OpenAI Responses API

def _responses_user_text(input_) -> str:
    if isinstance(input_, str):
        return input_
    for item in reversed(input_ or []):
        if isinstance(item, dict) and item.get("role") == "user":
            content = item.get("content")
            if isinstance(content, str):
                return content
            return "\n".join(p.get("text", "") for p in content or []
                             if isinstance(p, dict) and isinstance(p.get("text"), str))
    return ""


@app.post("/v1/responses")
async def responses(request: Request):
    body = await request.json()
    user_text = _responses_user_text(body.get("input"))

    show_received(user_text)

    reply = reply_for(user_text)
    return JSONResponse({
        "id": "resp_mock", "object": "response", "status": "completed",
        "model": body.get("model", "mock-gpt"),
        "output": [{"type": "message", "id": "msg_mock", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": reply, "annotations": []}]}],
    })

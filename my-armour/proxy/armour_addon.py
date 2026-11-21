import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import httpx
from mitmproxy import http
from pydantic import BaseModel

# mitmproxy loads this file as a script, so only proxy/ is on sys.path.
# Add the project root so the shared config module can be imported.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from armour_config import settings  # noqa: E402
from proxy.tokenization import (  # noqa: E402
    StreamRestorer, TokenVault, placeholder_spans, restore_json, tokenize_slots,
)

import armour_config  # noqa: E402
from armour_config import PolicySettings  # noqa: E402
from app.policy import request_action  # noqa: E402

LLM_HOSTS = settings.proxy.llm_hosts
SCANNER_URL = settings.scanner.url
API_BASE = f"http://{settings.scanner.host}:{settings.scanner.port}"
UNSUPPORTED_BODY = settings.proxy.unsupported_body
DEMO = settings.demo
EVENTS = settings.events
SECRET_HEADER = "X-Armour-Secret"
scanner = httpx.AsyncClient(timeout=settings.proxy.scanner_timeout)

# {flow.id: {placeholder: original}} - in memory only, never logged or persisted
VAULT = TokenVault(ttl_seconds=settings.tokenization.ttl_seconds)
META = "proxy_armour"              # flow.metadata key: metadata-only record of what we did
STREAM = "proxy_armour_stream"     # flow.metadata key: the StreamRestorer for SSE responses
# the policy the proxy enforces: config.yaml until the first successful poll of
# GET /internal/policies (the policies table), then the last policy fetched
POLICY: PolicySettings = settings.policy
_background: set[asyncio.Task] = set()     # strong refs, so tasks aren't garbage-collected
# evaluation only: append per-stage timings (milliseconds, no content) as JSON lines
TIMING_LOG = os.environ.get("ARMOUR_TIMING_LOG")


class _Stage:
    """with _Stage(record, "parse_ms"): ... - adds elapsed milliseconds to record["stages"]."""

    def __init__(self, record: dict, name: str):
        self.record, self.name = record, name

    def __enter__(self):
        self.started = time.perf_counter()

    def __exit__(self, *exc):
        stages = self.record.setdefault("stages", {})
        stages[self.name] = stages.get(self.name, 0.0) + (time.perf_counter() - self.started) * 1000


# ---------------------------------------------------------------- host matching

def is_llm_host(host: str, patterns=LLM_HOSTS) -> bool:
    """Exact hostname match, or "*.domain" matching any subdomain of domain.

    "*.openai.azure.com" matches "contoso.openai.azure.com" but NOT
    "evilopenai.azure.com" or "openai.azure.com.evil.com" (the leading dot
    in the suffix check is what makes this safe).
    """
    host = host.lower().rstrip(".")
    for pattern in patterns:
        if pattern.startswith("*."):
            if host.endswith(pattern[1:]):      # pattern[1:] == ".openai.azure.com"
                return True
        elif host == pattern:
            return True
    return False


# ------------------------------------------------------ finding text in the body

# string values under these keys are metadata, never user text
SKIP_KEYS = frozenset({"model", "role", "type", "id"})
# parents whose "data" field is base64 binary (Gemini inline_data, OpenAI audio)
BASE64_PARENTS = frozenset({"inline_data", "inlineData", "input_audio"})
BASE64_CHARS = re.compile(r"[A-Za-z0-9+/=_\-\s]*")
DATA_URL = re.compile(r"data:[\w.+-]+/[\w.+-]+(?:;[\w.+-]+=[\w.+-]+)*;base64,[A-Za-z0-9+/=_\-\s]*")


def _is_binary(container, key, value: str, parent_key) -> bool:
    """True only for base64 image/audio/file data - structure AND content must agree,
    so ordinary text placed in one of these fields is still scanned."""
    if DATA_URL.fullmatch(value):
        # OpenAI image_url / Responses input_image: "data:image/png;base64,iVBOR..."
        return True
    if key == "data" and isinstance(container, dict):
        # Anthropic {"type":"base64","media_type":..,"data":..}, Gemini inline_data,
        # OpenAI input_audio
        in_binary_slot = container.get("type") == "base64" or parent_key in BASE64_PARENTS
        return in_binary_slot and BASE64_CHARS.fullmatch(value) is not None
    return False


def _children(node):
    return node.items() if isinstance(node, dict) else enumerate(node)


def text_slots(data) -> list[tuple]:
    """Find every string in the JSON tree that could hold user text.

    Returns (container, key) pairs - key is a dict key or a list index - so
    container[key] is the text. The same helper is used to READ the text and
    to REPLACE it in place. Works for any provider's format (OpenAI messages,
    Anthropic system, Gemini contents/parts, OpenAI Responses input, ...).

    Uses an explicit stack instead of recursion, so deeply nested JSON can't
    crash it with RecursionError.
    """
    slots = []
    if not isinstance(data, (dict, list)):
        return slots
    # each entry: (node, nearest dict key above node, iterator over node's children)
    stack = [(data, None, iter(_children(data)))]
    while stack:
        node, parent_key, children = stack[-1]
        for key, value in children:
            if isinstance(value, str):
                if isinstance(node, dict) and key in SKIP_KEYS:
                    continue
                if _is_binary(node, key, value, parent_key):
                    continue
                slots.append((node, key))
            elif isinstance(value, (dict, list)):
                child_parent = key if isinstance(node, dict) else parent_key
                stack.append((value, child_parent, iter(_children(value))))
                break           # visit the child now, come back to this node later
        else:
            stack.pop()         # all children of this node done
    return slots


def extract_prompt(data) -> str:
    return "\n".join(container[key] for container, key in text_slots(data))


# ---------------------------------------------------------------- scanner call

Action = Literal["allow", "tokenize", "block"]


class ScanFinding(BaseModel):
    type: str
    value: str
    action: Action
    detector: str = ""
    start: int | None = None
    end: int | None = None


class ScanResult(BaseModel):
    risk: str
    action: Action
    findings: list[ScanFinding]


class ScannerError(Exception):
    """The scanner could not give a trustworthy answer. Message is safe to log."""


async def call_scanner(text: str) -> ScanResult:
    """Ask the scanner about text. ANY failure raises ScannerError.

    Covers: connection refused, timeout, non-200 status, non-JSON body,
    missing keys, unknown action. The message only names the failure type -
    never str(exception), which (for validation errors) can contain the
    sensitive values themselves.
    """
    try:
        resp = await scanner.post(SCANNER_URL, json={"text": text})
        if resp.status_code != 200:
            raise ScannerError(f"HTTP {resp.status_code}")
        return ScanResult.model_validate_json(resp.content)
    except ScannerError:
        raise
    except Exception as e:
        raise ScannerError(type(e).__name__) from None


# ------------------------------------------------------------------- responses

def block(flow: http.HTTPFlow, status: int, reason: str, types=None):
    # only the TYPES of data are sent back, never the sensitive values
    flow.response = http.Response.make(
        status,
        json.dumps({"error": {"type": "proxy_armour_block",
                              "message": reason,
                              "detected": types or []}}),
        {"Content-Type": "application/json"},
    )


def _media_type(flow: http.HTTPFlow) -> str:
    # "multipart/form-data; boundary=xyz" -> "multipart/form-data"
    return flow.request.headers.get("content-type", "").split(";")[0].strip().lower()


def _is_json_media_type(media_type: str) -> bool:
    return media_type == "application/json" or media_type.endswith("+json")


# ---------------------------------------------------------------- mitmproxy hook

async def request(flow: http.HTTPFlow):
    if flow.request.method != "POST" or not is_llm_host(flow.request.pretty_host):
        return
    try:
        await inspect(flow)
    except Exception as e:
        # last line of defence: a bug in our own code must never let an
        # unscanned request through (mitmproxy would forward it after logging)
        VAULT.pop(flow.id)
        print(f"[ARMOUR] BLOCKED {flow.request.pretty_host} - internal error ({type(e).__name__})")
        block(flow, 500, "Proxy Armour internal error - request blocked for safety")
        return
    if DEMO.enabled and flow.response is None:   # not blocked -> to the mock LLM
        route_to_demo(flow)


async def _scan(text: str, record: dict) -> "ScanResult":
    started = time.perf_counter()
    try:
        return await call_scanner(text)
    finally:
        record["scan_ms"] += (time.perf_counter() - started) * 1000


async def inspect(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    # metadata-only record of this flow (types, counts - never values). Created
    # first, so every outcome - including early blocks - becomes an audit event.
    # "block" until proven otherwise (fail closed).
    record = flow.metadata[META] = {"host": host, "action": "block", "risk": None, "types": [],
                                    "finding_count": 0, "detectors": [], "tokenized": 0,
                                    "scan_ms": 0.0}

    if not flow.request.raw_content:
        # e.g. POST /v1/threads/{id}/runs/{id}/cancel - nothing that could leak
        record["action"] = "allow"
        print(f"[ARMOUR] allowed {host} - empty body")
        return

    # parse the body once; if we can't read it we can't scan it, so block
    try:
        with _Stage(record, "parse_ms"):
            data = json.loads(flow.request.get_text())
            prompt = extract_prompt(data) if isinstance(data, (dict, list)) else ""
    except (ValueError, TypeError, RecursionError):  # JSONDecodeError is a ValueError
        data = None

    if not isinstance(data, (dict, list)):
        media_type = _media_type(flow)
        if data is None and media_type and not _is_json_media_type(media_type):
            print(f"[ARMOUR] BLOCKED {host} - unsupported body type {media_type}")
            block(flow, UNSUPPORTED_BODY.status,
                  f"{UNSUPPORTED_BODY.message} (got {media_type})")
        else:
            print(f"[ARMOUR] BLOCKED {host} - body is not a valid JSON object")
            block(flow, 400, "Request body is not valid JSON - blocked for safety")
        return

    try:
        with _Stage(record, "detect_ms"):
            result = await _scan(prompt, record)
    except ScannerError as e:
        print(f"[ARMOUR] BLOCKED {host} - scanner error ({e})")
        block(flow, 503, "Scanner unavailable - request blocked for safety")
        return

    # the proxy enforces ITS policy (polled from the policies table), whatever
    # action the scanner suggested
    findings = [f.model_copy(update={"action": POLICY.action_for(f.type)}) for f in result.findings]
    action = request_action([f.model_dump() for f in findings])
    types = sorted({f.type for f in findings})
    record.update(action=action, risk=result.risk, types=types, finding_count=len(findings),
                  detectors=sorted({f.detector for f in findings if f.detector}))
    if action != "allow":
        record["action"] = "block"            # until tokenization is verified below

    if action == "block":
        blocked = sorted({f.type for f in findings if f.action == "block"})
        print(f"[ARMOUR] BLOCKED {host} - risk={result.risk} block-policy types: {', '.join(blocked)}")
        block(flow, 403, f"Sensitive data detected (risk: {result.risk})", types)
        return

    if action == "tokenize":
        with _Stage(record, "tokenize_ms"):
            mapping = tokenize_slots(text_slots(data), [f.model_dump() for f in findings],
                                     existing_text=prompt)
            sent = extract_prompt(data)

        # verify: re-scan exactly what will be sent. Findings that lie entirely
        # inside one of our placeholders are expected (e.g. the AST detector sees
        # password = "PA_..."); anything else means a value wasn't replaced -
        # e.g. a match that spanned two JSON fields - so block.
        try:
            with _Stage(record, "verify_ms"):
                check = await _scan(sent, record)
        except ScannerError as e:
            print(f"[ARMOUR] BLOCKED {host} - scanner error on verify ({e})")
            block(flow, 503, "Scanner unavailable - request blocked for safety")
            return
        spans = placeholder_spans(sent, mapping)
        left = sorted({f.type for f in check.findings
                       if POLICY.action_for(f.type) != "allow" and not _inside_any(f, spans)})
        if left:
            print(f"[ARMOUR] BLOCKED {host} - tokenization incomplete, still found: {', '.join(left)}")
            block(flow, 403, "Sensitive data could not be fully tokenized", left)
            return

        with _Stage(record, "tokenize_ms"):
            flow.request.set_text(json.dumps(data))
        record["action"] = "tokenize"
        if mapping:
            VAULT.put(flow.id, mapping)
            record["tokenized"] = len(mapping)
            # the stream restorer must be able to read the response bytes
            flow.request.headers["accept-encoding"] = "identity"
        tokenized_types = sorted({f.type for f in findings if f.action == "tokenize"})
        # types and counts only: the outgoing prompt (placeholders, user text) is never logged
        print(f"[ARMOUR] TOKENIZED {host} - {len(mapping)} value(s): {', '.join(tokenized_types)}")
    else:
        print(f"[ARMOUR] allowed {host}")


def _inside_any(finding: ScanFinding, spans: list[tuple[int, int]]) -> bool:
    if finding.start is None or finding.end is None:
        return False
    return any(s <= finding.start and finding.end <= e for s, e in spans)


def route_to_demo(flow: http.HTTPFlow) -> None:
    """Demo mode: send the (already scanned/tokenized) request to the local mock LLM."""
    flow.request.scheme = "http"
    flow.request.host = DEMO.upstream_host      # also rewrites the Host header
    flow.request.port = DEMO.upstream_port


# ------------------------------------------------------------ response side

def responseheaders(flow: http.HTTPFlow):
    """Streaming (SSE) responses: attach a restorer before any body bytes flow."""
    try:
        _attach_stream_restorer(flow)
    except Exception as e:
        # never let a traceback (whose message could hold data) reach mitmproxy's log;
        # without a restorer the client simply gets placeholders - nothing leaks
        VAULT.pop(flow.id)
        host = flow.metadata.get(META, {}).get("host", "?")
        print(f"[ARMOUR] NOT RESTORED {host} - internal error ({type(e).__name__})")


def _attach_stream_restorer(flow: http.HTTPFlow) -> None:
    if flow.id not in VAULT or flow.response is None:
        return
    if not flow.response.headers.get("content-type", "").startswith("text/event-stream"):
        return                                   # buffered - restored in response()
    host = flow.metadata.get(META, {}).get("host", flow.request.pretty_host)
    mapping = VAULT.pop(flow.id)
    if mapping is None:
        print(f"[ARMOUR] NOT RESTORED {host} - token map expired before the response")
        return
    if flow.response.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
        # can't read compressed bytes: forward as-is (placeholders stay, nothing leaks)
        print(f"[ARMOUR] NOT RESTORED {host} - compressed event stream")
        return
    restorer = StreamRestorer(mapping)
    flow.response.stream = restorer
    flow.metadata[STREAM] = restorer


def response(flow: http.HTTPFlow):
    record = flow.metadata.get(META)
    if not record:
        return                                   # not an inspected LLM request
    if record.get("tokenized"):
        with _Stage(record, "restore_ms"):
            _restore_and_log(flow, record)
    report_event(flow)
    if TIMING_LOG:
        _write_timing(flow, record)


def _write_timing(flow: http.HTTPFlow, record: dict) -> None:
    """Evaluation only (ARMOUR_TIMING_LOG): stage durations and sizes - never content."""
    line = {"action": record["action"], "bytes": len(flow.request.raw_content or b""),
            **{k: round(v, 3) for k, v in record.get("stages", {}).items()}}
    try:
        with open(TIMING_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
    except OSError:
        pass


def _restore_and_log(flow: http.HTTPFlow, record: dict) -> None:
    host = record["host"]
    try:
        stats = _restore(flow)
    except Exception as e:
        # restoring is best-effort: on a bug the client gets placeholders, never originals
        VAULT.pop(flow.id)
        print(f"[ARMOUR] NOT RESTORED {host} - internal error ({type(e).__name__})")
        return
    if stats is None:
        return
    record["restore"] = stats.as_dict()
    print(f"[ARMOUR] RESTORED {host} - restored={stats.restored} missing={stats.missing} "
          f"unknown={stats.unknown} syntax_valid={stats.syntax_valid}")
    if stats.leaked_types:
        # the provider returned an original it should never have seen
        print(f"[ARMOUR] LEAK {host} - original value(s) of type {', '.join(stats.leaked_types)} "
              f"appeared verbatim in the LLM response")


def _restore(flow: http.HTTPFlow):
    host = flow.metadata[META]["host"]
    restorer: StreamRestorer | None = flow.metadata.pop(STREAM, None)
    if restorer is not None:                     # SSE: already restored while streaming
        if restorer.error:
            print(f"[ARMOUR] NOT RESTORED {host} - stream restorer error ({restorer.error}); "
                  f"rest of the stream forwarded unrestored")
        stats = restorer.stats
        restorer.close()                         # drop the originals
        return stats

    mapping = VAULT.pop(flow.id)                 # pop = the map is deleted here
    if mapping is None:
        print(f"[ARMOUR] NOT RESTORED {host} - token map expired before the response")
        flow.metadata[META]["restore"] = {"expired": True}
        return None
    try:
        data = json.loads(flow.response.get_text())
    except (ValueError, TypeError, RecursionError):
        data = None
    if not isinstance(data, (dict, list)):
        print(f"[ARMOUR] NOT RESTORED {host} - response is not JSON")
        return None
    stats = restore_json(data, mapping)
    flow.response.set_text(json.dumps(data, ensure_ascii=False))
    return stats


def error(flow: http.HTTPFlow):
    # upstream failed: no response will come - drop the map now
    VAULT.pop(flow.id)
    restorer = flow.metadata.pop(STREAM, None)
    if restorer is not None:
        restorer.close()
    if META in flow.metadata:
        report_event(flow)


# ------------------------------------------------------------ audit events

_PROVIDERS = (("openai.azure.com", "azure"), ("openai.com", "openai"), ("anthropic.com", "anthropic"),
              ("googleapis.com", "google"), ("mistral.ai", "mistral"), ("groq.com", "groq"))
_PATH_UNSAFE = re.compile(r"[^A-Za-z0-9/_.:\-]")


def provider_of(host: str) -> str:
    host = host.lower().rstrip(".")
    for suffix, name in _PROVIDERS:
        if host == suffix or host.endswith("." + suffix):
            return name
    return "other"


def build_event(flow: http.HTTPFlow) -> dict:
    """The audit event for a flow: METADATA ONLY (see app/schemas.py EventIn).

    No prompt text, no values, no placeholders. The endpoint is the path without
    its query string (Gemini sends the API key as ?key=).
    """
    record = flow.metadata[META]
    restore = record.get("restore") or {}
    path = flow.request.path.split("?", 1)[0]
    endpoint = "/" + _PATH_UNSAFE.sub("_", path.lstrip("/"))[:511]
    started = flow.request.timestamp_start
    ended = (flow.response.timestamp_end if flow.response is not None else None) or time.time()
    return {
        "ts": datetime.fromtimestamp(started, timezone.utc).isoformat(),
        "host": record["host"].lower(),
        "provider": provider_of(record["host"]),
        "endpoint": endpoint,
        "action": record["action"],
        "risk": record["risk"],
        "finding_types": record["types"],
        "finding_count": record["finding_count"],
        "detectors_used": record["detectors"],
        "tokens_issued": record["tokenized"],
        "tokens_restored": restore.get("restored", 0),
        "tokens_missing": restore.get("missing", 0),
        "tokens_unknown": restore.get("unknown", 0),
        "leak_flag": bool(restore.get("leaked_types")),
        "syntax_valid": restore.get("syntax_valid"),
        "latency_ms_scan": round(record["scan_ms"], 2),
        "latency_ms_total": round(max(0.0, (ended - started) * 1000), 2),
        "status_code": flow.response.status_code if flow.response is not None else None,
    }


def report_event(flow: http.HTTPFlow) -> None:
    """Send the flow's event in the background. Never raises, never delays the response."""
    record = flow.metadata.get(META)
    if record is None or record.get("reported"):
        return
    record["reported"] = True
    secret = armour_config.env.events_shared_secret
    if not EVENTS.enabled or secret is None:
        return
    try:
        payload = build_event(flow)
        task = asyncio.get_running_loop().create_task(post_event(payload, secret.get_secret_value()))
    except Exception as e:
        print(f"[ARMOUR] event not recorded ({type(e).__name__})")
        return
    _background.add(task)
    task.add_done_callback(_background.discard)


async def post_event(payload: dict, secret: str) -> bool:
    try:
        r = await scanner.post(f"{API_BASE}/events", json=payload,
                               headers={SECRET_HEADER: secret}, timeout=EVENTS.timeout_seconds)
        if r.status_code != 201:
            print(f"[ARMOUR] event not recorded (HTTP {r.status_code})")
            return False
        return True
    except Exception as e:                       # API down, timeout, ... - the request is unaffected
        print(f"[ARMOUR] event not recorded ({type(e).__name__})")
        return False


# ------------------------------------------------------------ policy sync

async def refresh_policy() -> bool:
    """Fetch the live policy from GET /internal/policies. Keeps the old one on failure."""
    global POLICY
    secret = armour_config.env.events_shared_secret
    if secret is None:
        return False
    try:
        r = await scanner.get(f"{API_BASE}/internal/policies",
                              headers={SECRET_HEADER: secret.get_secret_value()})
        if r.status_code != 200:
            return False
        new = PolicySettings.model_validate(r.json())
    except Exception:
        return False
    if new != POLICY:
        print(f"[ARMOUR] policy updated ({len(new.types)} types)")
    POLICY = new
    return True


async def _poll_policy_forever() -> None:
    while True:
        await refresh_policy()
        await asyncio.sleep(settings.policy_sync.poll_seconds)


# ------------------------------------------------------------ lifecycle

def _start(coro) -> None:
    task = asyncio.get_running_loop().create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)


async def running():
    _start(VAULT.run_cleanup(settings.tokenization.cleanup_interval_seconds))
    _start(_poll_policy_forever())
    if armour_config.env.events_shared_secret is None:
        print("[ARMOUR] EVENTS_SHARED_SECRET not set - audit events and policy sync disabled")
    if DEMO.enabled:
        print(f"[ARMOUR] DEMO MODE - LLM traffic goes to http://{DEMO.upstream_host}:{DEMO.upstream_port}")


async def done():
    for task in list(_background):
        task.cancel()

"""Reversible tokenization: swap sensitive values for placeholders on the way
out to the LLM, and swap them back in the LLM's answer on the way in.

    outgoing:  password = "hunter22"  ->  password = "PA_HARDCODED_SECRET_3F9A0C1B"
    incoming:  "...PA_HARDCODED_SECRET_3F9A0C1B..."  ->  "...hunter22..."

Pure functions and classes - no mitmproxy imports - so everything is unit-testable.

PRIVACY: nothing here logs, prints or persists an original value. The
{placeholder: original} map lives only in TokenVault (process memory, TTL) and
in a StreamRestorer for the life of one response. Stats objects carry counts
and type names only.
"""
import ast
import asyncio
import copy
import json
import re
import secrets
import time
from dataclasses import dataclass, field

# any placeholder-SHAPED string - used only to COUNT unknown placeholders,
# never to restore (restoration matches exact issued placeholders only)
PLACEHOLDER_PATTERN = re.compile(r"(?<![A-Za-z0-9])PA_[A-Z][A-Z0-9_]*?_[0-9A-F]{8}(?![0-9A-Za-z])")

# when two detectors report the same value, label it with the most specific one
DETECTOR_PRIORITY = {"regex": 0, "ast": 1, "entropy": 2}

_PYTHON_FENCE = re.compile(r"```[ \t]*(python3?|py)[^\n]*\n(.*?)```", re.DOTALL | re.IGNORECASE)


def new_placeholder(finding_type: str, taken: set[str], existing_text: str = "") -> str:
    """PA_<TYPE>_<8 uppercase hex>, unique within `taken` and absent from existing_text.

    The hex is cryptographically random (not a hash of the value), so the
    placeholder reveals nothing about the original.
    """
    while True:
        placeholder = f"PA_{finding_type}_{secrets.token_hex(4).upper()}"
        if placeholder not in taken and placeholder not in existing_text:
            return placeholder


def _alternation(strings) -> re.Pattern | None:
    # longest first, so at any position the longest candidate wins
    ordered = sorted(set(strings), key=len, reverse=True)
    return re.compile("|".join(map(re.escape, ordered))) if ordered else None


# ------------------------------------------------------------------ outgoing

def tokenize_slots(slots: list[tuple], findings: list[dict], existing_text: str = "") -> dict[str, str]:
    """Replace every 'tokenize' finding's value inside the slots, in place.

    slots: (container, key) pairs - container[key] is a string in the request JSON.
    Same value -> same placeholder (within this call). Only the value is
    replaced, so surrounding quotes/syntax stay valid. All values are swapped
    in ONE regex pass, so inserted placeholders are never re-scanned.

    Returns {placeholder: original} for the values that were actually replaced.
    """
    value_type: dict[str, str] = {}
    for f in sorted(findings, key=lambda f: DETECTOR_PRIORITY.get(f.get("detector", ""), 9)):
        if f.get("action") == "tokenize" and f.get("value"):
            value_type.setdefault(f["value"], f["type"])
    if not value_type:
        return {}

    taken: set[str] = set()
    placeholder_for: dict[str, str] = {}
    for value, finding_type in value_type.items():
        placeholder_for[value] = new_placeholder(finding_type, taken, existing_text)
        taken.add(placeholder_for[value])

    pattern = _alternation(placeholder_for)
    used: dict[str, str] = {}

    def swap(m: re.Match) -> str:
        placeholder = placeholder_for[m.group()]
        used[placeholder] = m.group()
        return placeholder

    for container, key in slots:
        container[key] = pattern.sub(swap, container[key])
    return used


def placeholder_spans(text: str, placeholders) -> list[tuple[int, int]]:
    """Character spans of the given placeholders in text."""
    pattern = _alternation(placeholders)
    return [m.span() for m in pattern.finditer(text)] if pattern else []


# ------------------------------------------------------------------ incoming

def python_syntax_valid(texts: list[str]) -> bool | None:
    """Parse every ```python fenced block. None if there are none."""
    blocks = [m.group(2) for t in texts for m in _PYTHON_FENCE.finditer(t)]
    if not blocks:
        return None
    for block in blocks:
        try:
            ast.parse(block)
        except Exception:      # SyntaxError, ValueError, RecursionError...
            return False
    return True


@dataclass
class RestoreStats:
    """What happened during restoration - counts and type names only, never values."""
    issued: int
    restored: int = 0                                 # placeholder occurrences put back
    seen: set[str] = field(default_factory=set, repr=False)
    unknown: int = 0                                  # PA_-shaped strings we never issued
    leaked_types: list[str] = field(default_factory=list)  # originals the LLM sent back verbatim
    syntax_valid: bool | None = None                  # restored ```python code parses?

    @property
    def missing(self) -> int:                         # issued but absent from the response
        return self.issued - len(self.seen)

    def as_dict(self) -> dict:
        return {"issued": self.issued, "restored": self.restored, "missing": self.missing,
                "unknown": self.unknown, "leaked_types": self.leaked_types,
                "syntax_valid": self.syntax_valid}


def _type_of(placeholder: str) -> str:
    return placeholder[3:-9]        # PA_<TYPE>_<8 hex>


class Restorer:
    """Restores exact issued placeholders and keeps the statistics."""

    def __init__(self, mapping: dict[str, str]):
        self._mapping = mapping
        self._pattern = _alternation(mapping)
        self.stats = RestoreStats(issued=len(mapping))

    def restore(self, text: str) -> str:
        if not self._pattern or not text:
            return text

        def put_back(m: re.Match) -> str:
            self.stats.restored += 1
            self.stats.seen.add(m.group())
            return self._mapping[m.group()]

        return self._pattern.sub(put_back, text)       # one pass: restored text isn't re-scanned

    def finish(self, raw_texts: list[str], restored_texts: list[str]) -> RestoreStats:
        """Leak check + unknown count on the RAW (pre-restore) response; syntax on restored."""
        leaked = {_type_of(p) for p, original in self._mapping.items()
                  if any(original in t for t in raw_texts)}
        self.stats.leaked_types = sorted(leaked)
        shaped = {m for t in raw_texts for m in PLACEHOLDER_PATTERN.findall(t)}
        self.stats.unknown = len(shaped - self._mapping.keys())
        if self.stats.restored:
            self.stats.syntax_valid = python_syntax_valid(restored_texts)
        return self.stats


def iter_strings(data):
    """Yield (path, container, key) for every string in a JSON tree. Iterative."""
    stack = [((), data)]
    while stack:
        path, node = stack.pop()
        items = node.items() if isinstance(node, dict) else enumerate(node)
        for key, value in items:
            if isinstance(value, str):
                yield path + (key,), node, key
            elif isinstance(value, (dict, list)):
                stack.append((path + (key,), value))


def restore_json(data, mapping: dict[str, str]) -> RestoreStats:
    """Restore placeholders in every string of a (non-streaming) JSON response, in place."""
    restorer = Restorer(mapping)
    slots = list(iter_strings(data))
    raw = [container[key] for _, container, key in slots]
    for _, container, key in slots:
        container[key] = restorer.restore(container[key])
    return restorer.finish(raw, [container[key] for _, container, key in slots])


# ------------------------------------------------------------------ streaming

# keys whose string values are generated text
_TEXT_KEYS = frozenset({"content", "text", "delta", "partial_json", "arguments", "refusal", "thinking"})
_MAX_BUFFER = 1_000_000          # bytes of an unterminated SSE event before giving up
_MAX_ACCUMULATED = 2_000_000     # chars kept for the end-of-stream leak/syntax checks


def _is_incremental(path: tuple) -> bool:
    """Text that continues in the next event at the same path: OpenAI choices[].delta,
    Anthropic delta.text/partial_json, Responses API "delta", Gemini candidates[]."""
    return any(p == "delta" for p in path) or (len(path) > 0 and path[0] == "candidates")


def _shape(path: tuple) -> tuple:
    return tuple(None if isinstance(p, int) else p for p in path)


def _set_path(obj, path: tuple, value: str) -> None:
    for p in path[:-1]:
        obj = obj[p]
    obj[path[-1]] = value


class StreamRestorer:
    """mitmproxy `flow.response.stream` callable for SSE responses.

    Called with each raw chunk, then with b"" at end of stream. Returns the
    bytes to forward to the client. See module docstring for the guarantees.
    """

    def __init__(self, mapping: dict[str, str]):
        self.restorer = Restorer(mapping)
        self._placeholders = tuple(mapping)
        self._max_hold = max(map(len, mapping), default=1) - 1
        self._buffer = b""
        self._carry: dict[tuple, str] = {}                  # path -> held-back text
        self._templates: dict[tuple, tuple] = {}            # path -> (field lines, event obj)
        self._raw: list[str] = []
        self._restored: list[str] = []
        self._accumulated = 0
        self.passthrough = False                            # gave up: forward bytes untouched
        self.finished = False
        self.error: str | None = None                       # exception TYPE name, if one happened

    @property
    def stats(self) -> RestoreStats:
        return self.restorer.stats

    # -- mitmproxy entry point ------------------------------------------------
    def __call__(self, data: bytes) -> bytes:
        """Never raises: on an internal error the rest of the stream passes through
        unrestored (the client sees placeholders - nothing leaks), and only the
        exception type is kept - its message could contain data."""
        before = self._buffer             # unprocessed bytes from earlier calls
        try:
            return self._feed(data)
        except Exception as e:
            self.error = type(e).__name__
            self.passthrough = True
            try:                           # held-back text, so no characters are lost
                held = self._flush_all()
            except Exception:
                held = b""
            self._carry.clear()
            self._buffer = b""
            # this call's events were not emitted: forward everything raw, exactly once
            return held + before + data

    def _feed(self, data: bytes) -> bytes:
        if data == b"":
            return self._finish()
        # data after b"" (e.g. an empty HTTP/2 DATA frame mid-stream): keep going
        self.finished = False
        if self.passthrough:
            return data
        self._buffer = (self._buffer + data).replace(b"\r\n", b"\n")
        out = []
        while (end := self._buffer.find(b"\n\n")) != -1:
            event, self._buffer = self._buffer[:end], self._buffer[end + 2:]
            out.append(self._process(event))
        if len(self._buffer) > _MAX_BUFFER:                 # not SSE after all - stop touching it
            out.append(self._flush_all() + self._buffer)
            self._buffer, self.passthrough = b"", True
        return b"".join(out)

    # -- internals --------------------------------------------------------------
    def _accumulate(self, bucket: list[str], text: str) -> None:
        if self._accumulated < _MAX_ACCUMULATED:
            bucket.append(text)
            self._accumulated += len(text)

    def _split_hold(self, text: str) -> tuple[str, str]:
        """Split off the longest suffix that could be the start of an issued placeholder."""
        for n in range(min(len(text), self._max_hold), 0, -1):
            suffix = text[-n:]
            if any(p.startswith(suffix) for p in self._placeholders):
                return text[:-n], suffix
        return text, ""

    def _process(self, event: bytes) -> bytes:
        try:
            text = event.decode("utf-8")
        except UnicodeDecodeError:
            return self._flush_all() + event + b"\n\n"
        lines = text.split("\n")
        fields = [line for line in lines if not line.startswith("data:")]
        data_lines = [line[5:].removeprefix(" ") for line in lines if line.startswith("data:")]
        if not data_lines:                                  # comment / keep-alive
            return event + b"\n\n"
        try:
            obj = json.loads("\n".join(data_lines))
        except ValueError:
            obj = None
        if not isinstance(obj, (dict, list)):               # e.g. "data: [DONE]"
            return self._flush_all() + event + b"\n\n"

        slots = list(iter_strings(obj))
        incremental = {path for path, _, key in slots if key in _TEXT_KEYS and _is_incremental(path)}
        shapes = {_shape(p) for p in incremental}
        # a held-back path with no continuation in this event has ended: flush it first
        out = [self._flush(p) for p in list(self._carry) if _shape(p) not in shapes]

        changed = False
        for path, container, key in slots:
            original = container[key]
            if path in incremental:
                self._accumulate(self._raw, original)
                emit, hold = self._split_hold(self._carry.pop(path, "") + original)
                if hold:
                    self._carry[path] = hold
                    self._templates[path] = (fields, obj)
                new = self.restorer.restore(emit)
                self._accumulate(self._restored, new)
            else:
                if key in _TEXT_KEYS:
                    self._accumulate(self._raw, original)
                new = self.restorer.restore(original)
                if key in _TEXT_KEYS:
                    self._accumulate(self._restored, new)
            if new != original:
                container[key] = new
                changed = True
        out.append(self._serialize(fields, obj) if changed else event + b"\n\n")
        return b"".join(out)

    def _flush(self, path: tuple) -> bytes:
        """Emit held-back text as a synthetic copy of the last event on that path."""
        held = self._carry.pop(path)
        fields, template = self._templates.pop(path)
        synthetic = copy.deepcopy(template)
        for p, container, key in list(iter_strings(synthetic)):
            if key in _TEXT_KEYS and _is_incremental(p):
                container[key] = ""                          # no duplicated text
        restored = self.restorer.restore(held)               # complete placeholder? restore it
        self._accumulate(self._restored, restored)
        _set_path(synthetic, path, restored)
        return self._serialize(fields, synthetic)

    def _flush_all(self) -> bytes:
        return b"".join(self._flush(p) for p in list(self._carry))

    @staticmethod
    def _serialize(fields: list[str], obj) -> bytes:
        payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        return ("\n".join(fields + [f"data: {payload}"]) + "\n\n").encode("utf-8")

    def _finish(self) -> bytes:
        # held-back text first, as complete synthetic events (it belongs to
        # earlier deltas); then any incomplete event exactly as received. If the
        # stream really ended, SSE clients drop an unterminated event anyway; if
        # more data follows (an empty chunk mid-stream), the bytes rejoin unchanged.
        out = self._flush_all() + self._buffer
        self._buffer = b""
        self.finished = True
        self.restorer.finish(["".join(self._raw)], ["".join(self._restored)])
        return out

    def close(self) -> None:
        """Drop every reference to original values. Call once the response is done."""
        self.restorer = _ClosedRestorer(self.restorer.stats)
        self._placeholders = ()
        self._carry.clear()
        self._templates.clear()
        self._raw.clear()
        self._restored.clear()
        self.passthrough = True


class _ClosedRestorer(Restorer):
    """Stand-in after close(): keeps the stats, holds no mapping."""

    def __init__(self, stats: RestoreStats):
        super().__init__({})
        self.stats = stats


# ------------------------------------------------------------------ vault

class TokenVault:
    """In-memory {flow id: {placeholder: original}} with a time-to-live.

    Never logged, never persisted. Entries are removed when the response is
    restored (pop), when the flow errors, or by purge_expired() once their TTL
    passes - whichever comes first.
    """

    def __init__(self, ttl_seconds: float, clock=time.monotonic):
        self.ttl = ttl_seconds
        self._clock = clock
        self._entries: dict[str, tuple[dict[str, str], float]] = {}

    def put(self, flow_id: str, mapping: dict[str, str]) -> None:
        self._entries[flow_id] = (dict(mapping), self._clock() + self.ttl)

    def pop(self, flow_id: str) -> dict[str, str] | None:
        """Remove and return the map, or None if absent or expired."""
        entry = self._entries.pop(flow_id, None)
        if entry is None or entry[1] <= self._clock():
            return None
        return entry[0]

    def __contains__(self, flow_id: str) -> bool:
        entry = self._entries.get(flow_id)
        return entry is not None and entry[1] > self._clock()

    def purge_expired(self) -> int:
        now = self._clock()
        expired = [k for k, (_, expires) in self._entries.items() if expires <= now]
        for k in expired:
            del self._entries[k]
        return len(expired)

    async def run_cleanup(self, interval_seconds: float) -> None:
        """Background task: purge expired maps forever (cancel to stop)."""
        while True:
            await asyncio.sleep(interval_seconds)
            self.purge_expired()

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:                               # never show the contents
        return f"<TokenVault {len(self._entries)} flows, ttl={self.ttl}s>"

"""Find hard-coded secrets in Python code by reading its syntax tree.

    db_password = "hunter22"              Assign
    api_key: str = "abc123xyz"            AnnAssign
    connect(password="hunter22")          keyword
    {"Authorization": "Bearer abc123"}    Dict      (also catches pasted JSON)

A string literal assigned to a secret-sounding name/key is flagged as
HARDCODED_SECRET (high). The finding covers the literal's CONTENT only - not
the quotes or prefix - so redaction leaves valid code: password = "[HARDCODED_SECRET]".

Text that isn't Python is silently ignored: this detector never raises.
"""
import ast
import re

from app.detectors.base import Finding

SENSITIVE_NAME = re.compile(
    r"(?<![a-z])"
    r"(?:password|passwd|secret|token|api_?key|auth(?:orization)?|credential"
    r"|private_?key|conn(?:ection)?_?str(?:ing)?)"
    r"s?(?![a-z])"
)
MIN_SECRET_LENGTH = 4          # "", "x", "abc" are placeholders, not secrets
MAX_LINE_LENGTH = 5_000        # don't try to parse giant single lines one by one

_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_PARAGRAPH = re.compile(r"(?:[^\n]*\S[^\n]*(?:\n|\Z))+")
_LINE = re.compile(r"[^\r\n]+")
_NEWLINE = re.compile(r"\r\n|\r|\n")       # the line endings Python's tokenizer uses
_STRING_OPEN = re.compile(r"[rRuUbBfF]{0,2}('''|\"\"\"|'|\")")


def is_sensitive_name(name: str) -> bool:
    # apiKey -> api_key, X-Api-Key -> x_api_key, DB_PASSWORD -> db_password
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower().replace("-", "_")
    return SENSITIVE_NAME.search(snake) is not None


def _target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):                       # password = ...
        return node.id
    if isinstance(node, ast.Attribute):                  # self.password = ...
        return node.attr
    if isinstance(node, ast.Subscript):                  # cfg["password"] = ...
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
    return None


def _flagged_literals(tree: ast.AST):
    """Yield every str Constant node assigned to a sensitive name or key."""
    for node in ast.walk(tree):
        pairs: list[tuple[str | None, ast.AST | None]] = []
        if isinstance(node, ast.Assign):
            pairs = [(_target_name(t), node.value) for t in node.targets]
        elif isinstance(node, ast.AnnAssign):
            pairs = [(_target_name(node.target), node.value)]
        elif isinstance(node, ast.keyword):
            pairs = [(node.arg, node.value)]             # arg is None for **kwargs
        elif isinstance(node, ast.Dict):
            pairs = [(k.value if isinstance(k, ast.Constant) and isinstance(k.value, str) else None, v)
                     for k, v in zip(node.keys, node.values)]
        for name, value in pairs:
            if (name and isinstance(value, ast.Constant) and isinstance(value.value, str)
                    and len(value.value.strip()) >= MIN_SECRET_LENGTH
                    and is_sensitive_name(name)):
                yield value


class _Source:
    """Maps ast (lineno, byte col_offset) positions to character offsets in a segment."""

    def __init__(self, src: str):
        self.src = src
        self.line_starts = [0] + [m.end() for m in _NEWLINE.finditer(src)]

    def offset(self, lineno: int, byte_col: int) -> int:
        start = self.line_starts[lineno - 1]
        end = self.line_starts[lineno] if lineno < len(self.line_starts) else len(self.src)
        line = self.src[start:end]
        # col_offset counts UTF-8 BYTES; convert to characters ("é" is 2 bytes, 1 char)
        chars = len(line.encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))
        return start + chars

    def content_span(self, node: ast.Constant) -> tuple[int, int] | None:
        start = self.offset(node.lineno, node.col_offset)
        end = self.offset(node.end_lineno, node.end_col_offset)
        literal = self.src[start:end]                     # e.g. r'''hunter22'''
        m = _STRING_OPEN.match(literal)
        if not m or not literal.endswith(m.group(1)):
            return None
        content_start, content_end = start + m.end(), end - len(m.group(1))
        return (content_start, content_end) if content_end > content_start else None


def _parse(src: str) -> ast.AST | None:
    try:
        return ast.parse(src)
    except Exception:       # SyntaxError, ValueError (null bytes), RecursionError, MemoryError...
        return None


class AstDetector:
    name = "ast"
    finding_type = "HARDCODED_SECRET"

    def _scan_segment(self, src: str, base: int, found: dict) -> bool:
        """Parse one segment; record findings at absolute offsets. True if it parsed."""
        tree = _parse(src)
        if tree is None:
            return False
        source = _Source(src)
        for node in _flagged_literals(tree):
            span = source.content_span(node)
            if span:
                start, end = base + span[0], base + span[1]
                found[(start, end)] = Finding(type=self.finding_type, start=start, end=end,
                                              severity="high", detector=self.name)
        return True

    def detect(self, text: str) -> list[Finding]:
        # Non-Python text can't crash this: _parse() swallows every parse error.
        # A bug in our own code is deliberately NOT swallowed - the scanner then
        # errors and the proxy fails closed (503), instead of silently missing secrets.
        found: dict[tuple[int, int], Finding] = {}
        if self._scan_segment(text, 0, found):         # the whole text is Python
            return sorted(found.values(), key=lambda f: f["start"])
        parsed: list[tuple[int, int]] = []             # ranges already handled
        for m in _FENCE.finditer(text):                # ``` fenced blocks
            if self._scan_segment(m.group(1), m.start(1), found):
                parsed.append((m.start(1), m.end(1)))
        for m in _PARAGRAPH.finditer(text):            # blank-line separated blocks
            if self._scan_segment(m.group(), m.start(), found):
                parsed.append((m.start(), m.end()))
        for m in _LINE.finditer(text):                 # single lines, indentation removed
            if len(m.group()) > MAX_LINE_LENGTH:
                continue
            if any(s <= m.start() and m.end() <= e for s, e in parsed):
                continue
            line = m.group()
            indent = len(line) - len(line.lstrip())
            self._scan_segment(line[indent:], m.start() + indent, found)
        return sorted(found.values(), key=lambda f: f["start"])

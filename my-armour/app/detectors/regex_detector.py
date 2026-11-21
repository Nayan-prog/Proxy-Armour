"""Pattern-based detection of structured identifiers and well-known secret formats.

Each Rule = regex (finds the SHAPE) + optional validator (confirms the MEANING,
e.g. a checksum). Separators inside numbers are a single space or dash - never
\\s, because a newline separates different JSON fields in the proxy and a match
must not join two fields.
"""
import base64
import json
import re
from dataclasses import dataclass
from typing import Callable

from app.detectors.base import Finding, Severity
from app.detectors.checksums import luhn_valid, verhoeff_valid

# a digit run must not continue on either side, directly or after one separator
_NO_DIGIT_BEFORE = r"(?<!\d)(?<!\d[ -])"
_NO_DIGIT_AFTER = r"(?!\d)(?![ -]\d)"
# characters that can continue a token (keys, tokens) - used as boundaries
_TOKEN_CHAR = r"A-Za-z0-9_\-"
_NOT_AFTER_TOKEN = rf"(?<![{_TOKEN_CHAR}])"
_NOT_BEFORE_TOKEN = rf"(?![{_TOKEN_CHAR}])"


@dataclass(frozen=True)
class Rule:
    type: str
    pattern: re.Pattern
    severity: Severity
    validate: Callable[[str], bool] | None = None


# ---------------------------------------------------------------- validators

def _aadhaar_valid(value: str) -> bool:
    return verhoeff_valid(value)


# issuer prefixes: Visa 4, Mastercard 51-55 / 22-27, Amex 34/37, Diners 30/36/38,
# JCB 35, Discover/RuPay 6, RuPay 81/82
_CARD_PREFIX = re.compile(r"(?:4|5[1-5]|2[2-7]|3[0457-8]|6|8[12])")


def _card_valid(value: str) -> bool:
    digits = re.sub(r"[ -]", "", value)
    return bool(_CARD_PREFIX.match(digits)) and luhn_valid(digits)


def _jwt_valid(value: str) -> bool:
    # the header must decode to a JSON object with an "alg" field
    header = value.split(".", 1)[0]
    try:
        decoded = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        return "alg" in json.loads(decoded)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- rules

RULES: tuple[Rule, ...] = (
    # --- personal identifiers ---
    # the lookbehind lets a match start only at the beginning of a run of
    # local-part characters - without it, a long run with no "@" makes the
    # regex retry from every position: O(n^2), 16 s for 100 KB (ReDoS)
    Rule("EMAIL", re.compile(
        r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}"), "low"),
    Rule("PHONE_IN", re.compile(
        _NO_DIGIT_BEFORE
        + r"(?:\+91[ -]?|0)?"                                   # +91 / +91- / trunk 0
        + r"[6-9](?:\d{9}|\d{4}[ -]\d{5}|\d{2}[ -]\d{3}[ -]\d{4})"  # 9876543210 / 98765 43210 / 987 654 3210
        + _NO_DIGIT_AFTER), "low"),
    Rule("PAN", re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.IGNORECASE), "medium"),
    Rule("AADHAAR", re.compile(
        _NO_DIGIT_BEFORE + r"[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}" + _NO_DIGIT_AFTER),
        "high", _aadhaar_valid),
    Rule("CREDIT_CARD", re.compile(
        _NO_DIGIT_BEFORE + r"\d(?:[ -]?\d){12,18}" + _NO_DIGIT_AFTER),
        "high", _card_valid),

    # --- cloud / SaaS credentials ---
    Rule("AWS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    Rule("ANTHROPIC_KEY", re.compile(
        _NOT_AFTER_TOKEN + r"sk-ant-[A-Za-z0-9_\-]{20,}"), "high"),
    Rule("OPENAI_KEY", re.compile(
        _NOT_AFTER_TOKEN + r"sk-(?!ant-)[A-Za-z0-9_\-]{20,}"), "high"),
    Rule("GITHUB_TOKEN", re.compile(
        _NOT_AFTER_TOKEN
        + r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})"
        + _NOT_BEFORE_TOKEN), "high"),
    Rule("GOOGLE_API_KEY", re.compile(
        _NOT_AFTER_TOKEN + r"AIza[0-9A-Za-z_\-]{35}" + _NOT_BEFORE_TOKEN), "high"),
    Rule("STRIPE_KEY", re.compile(
        _NOT_AFTER_TOKEN + r"sk_(?:live|test)_[A-Za-z0-9]{16,}" + _NOT_BEFORE_TOKEN), "high"),
    Rule("SLACK_TOKEN", re.compile(
        _NOT_AFTER_TOKEN + r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "high"),
    Rule("JWT", re.compile(
        _NOT_AFTER_TOKEN
        + r"eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*"), "high", _jwt_valid),

    # --- keys and connection strings ---
    Rule("PRIVATE_KEY", re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"   # complete block
        r"|[A-Za-z0-9+/=\s:,\-]*)"),                                        # or truncated paste
        "high"),
    Rule("DB_CONNECTION_STRING", re.compile(
        r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)(?:\+\w+)?://"   # scheme (+driver)
        # user:password@host... - lengths are capped so each attempt is bounded
        # work (unbounded runs made repeated "postgres://a:" O(n^2))
        r"[^\s:@/'\"`]{1,256}:[^\s@'\"`]{1,256}@[^\s'\"`]{1,2048}",
        re.IGNORECASE), "high"),
)


class RegexDetector:
    name = "regex"

    def __init__(self, rules: tuple[Rule, ...] = RULES):
        self.rules = rules

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            for m in rule.pattern.finditer(text):
                if rule.validate and not rule.validate(m.group()):
                    continue
                findings.append(Finding(type=rule.type, start=m.start(), end=m.end(),
                                        severity=rule.severity, detector=self.name))
        return findings

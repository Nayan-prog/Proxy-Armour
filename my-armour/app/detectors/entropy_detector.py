"""Flag long random-looking tokens (API keys with no known prefix) by Shannon entropy.

    H = -sum(p(c) * log2 p(c))   over the characters c of the token

Random keys use many different characters evenly -> high H. Words and
identifiers repeat letters -> lower H. Hex (16 symbols) and base64 (64 symbols)
have different maximums, so each has its own threshold (config.yaml).

Thresholds were chosen by measurement: on ~2,000 real identifiers/paths from
Python source vs random keys, "mixed case + >= 2 digits + H >= 4.0" caught 87%
of random base64 keys at a 0.5% false-positive rate.
"""
import math
import re
from collections import Counter

from app.detectors.base import Finding

# base64 / base64url alphabet (hex is a subset). "=" is only padding at the END
# of base64, so it is not part of the alphabet - otherwise "api_key=<secret>"
# would become one token including the name.
_ALPHABET = r"A-Za-z0-9+/_\-"
_HEX = re.compile(r"[0-9a-fA-F]+")
_UUID = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                   r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9A-Za-z])")
# words that say "the hex string after me is a hash, not a secret"
_HASH_CONTEXT = re.compile(r"(?i)(?:\b|_)(?:commit|sha(?:1|224|256|384|512)?|hash|digest|checksum"
                           r"|revision|rev|md5|git|etag|fingerprint)(?:\b|_)")
# Subresource Integrity values: sha384-<base64>
_SRI_PREFIX = re.compile(r"sha(?:256|384|512)-")
_CONTEXT_WINDOW = 40   # characters to look back on the same line


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


class EntropyDetector:
    name = "entropy"
    finding_type = "HIGH_ENTROPY_STRING"

    def __init__(self, min_length: int = 20, base64_threshold: float = 4.0,
                 hex_threshold: float = 3.0, min_digits: int = 2):
        self.min_length = min_length
        self.base64_threshold = base64_threshold
        self.hex_threshold = hex_threshold
        self.min_digits = min_digits
        self._token = re.compile(rf"[{_ALPHABET}]{{{min_length},}}={{0,2}}")

    def _in_hash_context(self, text: str, start: int) -> bool:
        line_start = text.rfind("\n", 0, start) + 1
        before = text[max(line_start, start - _CONTEXT_WINDOW):start]
        return _HASH_CONTEXT.search(before) is not None

    def _is_secret_like(self, token: str, text: str, start: int) -> bool:
        digits = sum(ch.isdigit() for ch in token)
        if digits == len(token) or not any(ch.isalpha() for ch in token):
            return False                      # plain numbers belong to the regex detector
        if _SRI_PREFIX.match(token):
            return False                      # integrity hash, e.g. sha384-oqVu...
        if _HEX.fullmatch(token):
            if digits == 0 or self._in_hash_context(text, start):
                return False                  # git SHA / checksum named as such
            return shannon_entropy(token) >= self.hex_threshold
        # base64-like: random keys mix upper, lower and digits; identifiers rarely do
        if digits < self.min_digits or token.lower() == token or token.upper() == token:
            return False
        return shannon_entropy(token) >= self.base64_threshold

    def detect(self, text: str) -> list[Finding]:
        # blank out UUIDs (same length, so offsets stay correct) - always identifiers
        masked = _UUID.sub(lambda m: " " * len(m.group()), text)
        findings: list[Finding] = []
        for m in self._token.finditer(masked):
            if self._is_secret_like(m.group(), masked, m.start()):
                findings.append(Finding(type=self.finding_type, start=m.start(), end=m.end(),
                                        severity="medium", detector=self.name))
        return findings

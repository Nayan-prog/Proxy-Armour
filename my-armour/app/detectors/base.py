"""Shared types for all detectors.

Every detector returns findings in the same shape, so the engine, redaction
and the evaluation harness can treat them identically:

    {"type": "AADHAAR", "start": 10, "end": 24, "severity": "high", "detector": "regex"}

Offsets are character positions in the scanned text (end is exclusive), so
text[start:end] is exactly the sensitive value.
"""
from typing import Literal, Protocol, TypedDict

Severity = Literal["low", "medium", "high"]

# higher number = more serious; used to pick the "worst" finding
RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


class Finding(TypedDict):
    type: str
    start: int
    end: int
    severity: Severity
    detector: str        # "regex" | "entropy" | "ast" - which detector found it


class Detector(Protocol):
    name: str

    def detect(self, text: str) -> list[Finding]:
        """Return every finding in text. Must never raise on arbitrary input."""
        ...

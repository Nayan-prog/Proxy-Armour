"""Detection package. Public API:

    from app.detectors import scan_text, overall_risk, redact

Detectors (each returns {type, start, end, severity, detector}):
    regex_detector.RegexDetector     structured identifiers + known secret formats
    entropy_detector.EntropyDetector random-looking tokens
    ast_detector.AstDetector         hard-coded secrets in Python code
"""
from app.detectors.base import RISK_ORDER, Detector, Finding
from app.detectors.engine import DETECTORS, merge_overlaps, overall_risk, redact, scan_text

__all__ = ["DETECTORS", "RISK_ORDER", "Detector", "Finding",
           "merge_overlaps", "overall_risk", "redact", "scan_text"]

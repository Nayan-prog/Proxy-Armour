"""Runs every enabled detector and combines their findings.

    scan_text(text)        -> findings from all detectors (+ "value")
    overall_risk(findings) -> "none" | "low" | "medium" | "high"
    redact(text, findings) -> text with each finding replaced by [TYPE]
"""
from armour_config import DetectorsSettings, settings
from app.detectors.ast_detector import AstDetector
from app.detectors.base import RISK_ORDER, Detector
from app.detectors.entropy_detector import EntropyDetector
from app.detectors.regex_detector import RegexDetector


def build_detectors(cfg: DetectorsSettings) -> list[Detector]:
    detectors: list[Detector] = []
    if cfg.regex.enabled:
        detectors.append(RegexDetector())
    if cfg.entropy.enabled:
        detectors.append(EntropyDetector(
            min_length=cfg.entropy.min_length,
            base64_threshold=cfg.entropy.base64_threshold,
            hex_threshold=cfg.entropy.hex_threshold,
            min_digits=cfg.entropy.min_digits,
        ))
    if cfg.ast.enabled:
        detectors.append(AstDetector())
    return detectors


DETECTORS = build_detectors(settings.detectors)


def default_severities() -> dict[str, str]:
    """Every finding type any detector can emit, with its built-in severity."""
    from app.detectors.regex_detector import RULES
    severities = {rule.type: rule.severity for rule in RULES}
    severities[EntropyDetector.finding_type] = "medium"
    severities[AstDetector.finding_type] = "high"
    return severities


def scan_text(text: str, detectors: list[Detector] | None = None) -> list[dict]:
    """All findings from all detectors, sorted by position.

    Each finding is {type, start, end, severity, detector, value}. The same span
    may be reported by several detectors - kept on purpose, so evaluation can
    credit each detector; merge_overlaps() handles it for redaction.
    """
    findings = []
    for detector in DETECTORS if detectors is None else detectors:
        for f in detector.detect(text):
            findings.append({**f, "value": text[f["start"]:f["end"]]})
    return sorted(findings, key=lambda f: (f["start"], f["end"]))


def overall_risk(findings: list[dict]) -> str:
    # the highest severity among all findings wins
    risk = "none"
    for f in findings:
        if RISK_ORDER[f["severity"]] > RISK_ORDER[risk]:
            risk = f["severity"]
    return risk


def merge_overlaps(findings: list[dict]) -> list[dict]:
    """Collapse overlapping findings into non-overlapping spans.

    Each group of overlapping findings becomes ONE span covering the union of
    the group (so no character of any member is left unredacted), labelled
    with the strongest member: highest severity first, then the longest match.

    e.g. "9876543210@gmail.com": PHONE_IN (0-10) inside EMAIL (0-20)
         -> one span 0-20 labelled EMAIL (same severity, EMAIL is longer)
    """
    groups: list[dict] = []
    for f in sorted(findings, key=lambda f: f["start"]):
        if groups and f["start"] < groups[-1]["end"]:   # overlaps current group
            groups[-1]["end"] = max(groups[-1]["end"], f["end"])
            groups[-1]["members"].append(f)
        else:                                            # starts a new group
            groups.append({"start": f["start"], "end": f["end"], "members": [f]})

    merged = []
    for g in groups:
        winner = max(g["members"],
                     key=lambda m: (RISK_ORDER[m["severity"]], m["end"] - m["start"]))
        merged.append({"type": winner["type"], "severity": winner["severity"],
                       "start": g["start"], "end": g["end"]})
    return merged


def redact(text: str, findings: list[dict]) -> str:
    # merge first: replacing two overlapping spans would corrupt the text
    # then replace from the end so earlier positions don't shift
    for f in sorted(merge_overlaps(findings), key=lambda f: f["start"], reverse=True):
        text = text[:f["start"]] + f"[{f['type']}]" + text[f["end"]:]
    return text

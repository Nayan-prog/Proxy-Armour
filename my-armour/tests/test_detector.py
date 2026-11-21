"""Engine tests: combining detectors, risk scoring, overlap merging, redaction."""
from app.detectors import merge_overlaps, overall_risk, redact, scan_text
from app.detectors.ast_detector import AstDetector
from app.detectors.entropy_detector import EntropyDetector
from app.detectors.regex_detector import RegexDetector

AADHAAR = "2345 6789 0124"     # fake, but Verhoeff-valid


def types_found(text):
    return sorted({f["type"] for f in scan_text(text)})


def test_clean_text_is_none():
    findings = scan_text("What is the capital of France?")
    assert findings == []
    assert overall_risk(findings) == "none"


def test_email_and_phone_is_low():
    findings = scan_text("Mail rahul@acme.com or call 9876543210")
    assert types_found("Mail rahul@acme.com or call 9876543210") == ["EMAIL", "PHONE_IN"]
    assert all(f["severity"] == "low" for f in findings)
    assert overall_risk(findings) == "low"


def test_pan_is_medium():
    findings = scan_text("My PAN is ABCDE1234F")
    assert types_found("My PAN is ABCDE1234F") == ["PAN"]
    assert overall_risk(findings) == "medium"


def test_aws_key_is_high():
    findings = scan_text("key: AKIAIOSFODNN7EXAMPLE")
    assert types_found("key: AKIAIOSFODNN7EXAMPLE") == ["AWS_KEY"]
    assert overall_risk(findings) == "high"


def test_highest_severity_wins():
    # low (email) + medium (PAN) + high (Aadhaar) -> high
    findings = scan_text(f"rahul@acme.com ABCDE1234F {AADHAAR}")
    assert overall_risk(findings) == "high"


def test_aadhaar_is_not_also_a_phone():
    # starts with 9, so the first 10 digits look like a phone number
    for text in ["987654321012", "9876 5432 1012"]:
        assert types_found(text) == ["AADHAAR"]


# ---- finding shape / detector attribution ----

def test_every_finding_has_the_common_shape_and_value():
    text = 'password = "hunter22"\nkey AKIAIOSFODNN7EXAMPLE token q8Zr2LxV9mP3kT7wN4bYc6Hd'
    findings = scan_text(text)
    assert {f["detector"] for f in findings} == {"regex", "entropy", "ast"}
    for f in findings:
        assert set(f) == {"type", "start", "end", "severity", "detector", "value"}
        assert f["value"] == text[f["start"]:f["end"]]


def test_same_span_from_two_detectors_is_kept_for_evaluation():
    # a GitHub token is a regex hit AND high entropy - both are reported
    token = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5b"
    detectors = {f["detector"] for f in scan_text(f"t {token}") if f["start"] == 2}
    assert detectors == {"regex", "entropy"}


def test_scan_text_with_chosen_detectors():
    text = 'password = "hunter22"\nmail rahul@acme.com'
    assert {f["detector"] for f in scan_text(text, [RegexDetector()])} == {"regex"}
    assert {f["detector"] for f in scan_text(text, [AstDetector()])} == {"ast"}
    assert scan_text(text, [EntropyDetector()]) == []


# ---- overlapping findings (merge_overlaps / redact) ----

def finding(type_, start, end, severity="low"):
    return {"type": type_, "start": start, "end": end, "severity": severity}


def test_phone_inside_email_redacts_as_email():
    text = "mail 9876543210@gmail.com"
    assert redact(text, scan_text(text)) == "mail [EMAIL]"


def test_higher_severity_wins_the_label_over_longer_span():
    # PAN (medium) inside an email (low, longer) -> whole span, PAN label
    text = "ABCDE1234F@x.com"
    assert redact(text, scan_text(text)) == "[PAN]"


def test_db_url_password_is_not_left_behind():
    # the password part also looks like an email - the whole URL must go
    text = "use postgres://admin:hunter22@db.acme.io:5432/app now"
    assert redact(text, scan_text(text)) == "use [DB_CONNECTION_STRING] now"


def test_ast_redaction_keeps_code_valid():
    text = 'password = "hunter22"'
    assert redact(text, scan_text(text)) == 'password = "[HARDCODED_SECRET]"'


def test_partial_overlap_redacts_the_union():
    # A = 0-10, B = 5-20 -> one span 0-20; no character of A or B survives
    merged = merge_overlaps([finding("A", 0, 10), finding("B", 5, 20, "high")])
    assert [(m["type"], m["start"], m["end"]) for m in merged] == [("B", 0, 20)]
    assert redact("0123456789abcdefghij!", [finding("A", 0, 10), finding("B", 5, 20, "high")]) == "[B]!"


def test_touching_spans_are_not_merged():
    merged = merge_overlaps([finding("A", 0, 4), finding("B", 4, 9)])
    assert [(m["type"], m["start"], m["end"]) for m in merged] == [("A", 0, 4), ("B", 4, 9)]


def test_separate_findings_redact_independently():
    text = "a@b.com and 9876543210"
    assert redact(text, scan_text(text)) == "[EMAIL] and [PHONE_IN]"


def test_merge_of_nothing_is_nothing():
    assert merge_overlaps([]) == []

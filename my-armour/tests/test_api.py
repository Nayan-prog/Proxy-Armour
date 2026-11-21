"""Tests for the FastAPI scanner endpoints, using FastAPI's TestClient
(requests go straight into the app in memory - no server needed)."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def scan(text):
    resp = client.post("/scan", json={"text": text})
    assert resp.status_code == 200
    return resp.json()


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_clean_text_is_allowed():
    r = scan("What is the capital of France?")
    assert r == {"risk": "none", "action": "allow", "findings": [],
                 "sanitized": "What is the capital of France?"}


def test_email_is_tokenized():
    r = scan("Mail rahul@acme.com today")
    assert (r["risk"], r["action"]) == ("low", "tokenize")
    assert r["findings"][0]["action"] == "tokenize"
    assert r["sanitized"] == "Mail [EMAIL] today"


def test_secrets_are_tokenized_identifiers_are_blocked():
    assert scan("key AKIAIOSFODNN7EXAMPLE")["action"] == "tokenize"
    assert scan('password = "hunter22"')["action"] == "tokenize"
    assert scan("PAN ABCDE1234F")["action"] == "block"
    assert scan("aadhaar 2345 6789 0124")["action"] == "block"
    assert scan("card 4111 1111 1111 1111")["action"] == "block"


def test_one_block_finding_blocks_the_request():
    r = scan("mail rahul@acme.com, key AKIAIOSFODNN7EXAMPLE, aadhaar 2345 6789 0124")
    assert {f["action"] for f in r["findings"]} == {"tokenize", "block"}
    assert r["action"] == "block"


def test_overlapping_findings_sanitize_cleanly():
    r = scan("mail 9876543210@gmail.com")
    # every detection is still reported...
    assert sorted(f["type"] for f in r["findings"]) == ["EMAIL", "PHONE_IN"]
    # ...but the redacted text is not corrupted
    assert r["sanitized"] == "mail [EMAIL]"


def test_finding_shape():
    f = scan("rahul@acme.com")["findings"][0]
    assert f == {"type": "EMAIL", "value": "rahul@acme.com", "start": 0, "end": 14,
                 "severity": "low", "detector": "regex", "action": "tokenize"}


def test_missing_text_is_rejected():
    assert client.post("/scan", json={}).status_code == 422

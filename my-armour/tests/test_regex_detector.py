"""Regex detector: one positive and at least one negative per rule.

Fake secrets are assembled at runtime ("sk_" + "live_" ...) so this file never
contains a secret-shaped literal that would trip GitHub push protection.
"""
import base64
import json

import pytest

from app.detectors.regex_detector import RegexDetector

detector = RegexDetector()


def found(text):
    """[(type, matched text)] for every finding."""
    return [(f["type"], text[f["start"]:f["end"]]) for f in detector.detect(text)]


def types(text):
    return sorted({f["type"] for f in detector.detect(text)})


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


JWT = b64url({"alg": "HS256", "typ": "JWT"}) + "." + b64url({"sub": "42"}) + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
PEM_BEGIN = "-----BEGIN RSA " + "PRIVATE KEY-----"
PEM_END = "-----END RSA " + "PRIVATE KEY-----"


# ---------------------------------------------------------------- interface

def test_findings_have_the_common_shape():
    f = detector.detect("mail rahul@acme.com")[0]
    assert f == {"type": "EMAIL", "start": 5, "end": 19, "severity": "low", "detector": "regex"}


# ---------------------------------------------------------------- Aadhaar

@pytest.mark.parametrize("value", ["234567890124", "2345 6789 0124", "2345-6789-0124", "987654321012"])
def test_valid_aadhaar_matches(value):
    assert found(f"id {value} ok") == [("AADHAAR", value)]


@pytest.mark.parametrize("text", [
    "order id 100020003000",     # starts with 1
    "ref 012345678901",          # starts with 0
    "id 234567890123",           # right shape, wrong Verhoeff digit
    "id 2345 6789 01245",        # 13 digits
])
def test_invalid_aadhaar_does_not_match(text):
    assert "AADHAAR" not in types(text)


# ---------------------------------------------------------------- PAN / phone

@pytest.mark.parametrize("value", ["ABCDE1234F", "abcde1234f", "AbCdE1234f"])
def test_pan_any_case(value):
    assert found(f"pan {value}.") == [("PAN", value)]


def test_pan_inside_a_word_does_not_match():
    assert types("XABCDE1234FX") == []


@pytest.mark.parametrize("value", ["9876543210", "98765 43210", "98765-43210", "987 654 3210",
                                   "987-654-3210", "+919876543210", "+91 98765 43210",
                                   "+91-98765-43210", "09876543210"])
def test_phone_variants(value):
    assert found(f"call {value} now") == [("PHONE_IN", value)]


@pytest.mark.parametrize("text", [
    "call 5876543210",           # Indian mobiles start 6-9
    "version 98765432101234",    # part of a longer number
    "call +91\n9876543210",      # newline is not a separator (would join JSON fields)
])
def test_phone_negatives(text):
    assert ("PHONE_IN", "+91\n9876543210") not in found(text)
    if "\n" not in text:
        assert "PHONE_IN" not in types(text)


# ---------------------------------------------------------------- credit card

@pytest.mark.parametrize("value", ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111",
                                   "5555555555554444", "378282246310005"])
def test_luhn_valid_cards_match(value):
    assert found(f"card {value} exp") == [("CREDIT_CARD", value)]


@pytest.mark.parametrize("text", [
    "card 4111111111111112",     # fails Luhn
    "id 1234567812345670",       # passes Luhn but no card network starts with 1
    "invoice 0000000000000000",  # zeros pass Luhn, no network prefix
])
def test_card_negatives(text):
    assert "CREDIT_CARD" not in types(text)


def test_spaced_card_is_not_also_an_aadhaar():
    assert types("4111 1111 1111 1111") == ["CREDIT_CARD"]


# ---------------------------------------------------------------- API keys / tokens

POSITIVES = {
    "AWS_KEY": "AKIA" + "IOSFODNN7EXAMPLE",
    "ANTHROPIC_KEY": "sk-" + "ant-api03-" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9v",
    "OPENAI_KEY": "sk-" + "proj-" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9v",
    "GITHUB_TOKEN": "ghp_" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5",
    "GOOGLE_API_KEY": "AIza" + "SyAb3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xYz",   # 35 after AIza
    "STRIPE_KEY": "sk_" + "live_" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7",
    "SLACK_TOKEN": "xox" + "b-1234567890-1234567890123-Ab3dE5fG7hJ9",
    "JWT": JWT,
    "DB_CONNECTION_STRING": "postgres://admin:hunter22@db.acme.io:5432/app",
}


@pytest.mark.parametrize("type_,value", POSITIVES.items(), ids=list(POSITIVES))
def test_secret_formats_match(type_, value):
    assert (type_, value) in found(f"use {value} here")
    assert all(f["severity"] == "high" for f in detector.detect(value) if f["type"] == type_)


@pytest.mark.parametrize("value", [
    "github_pat_" + "11ABCDEFG0" + "Ab3dE5fG7hJ9kL1mN3pQ5r_S7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3vW5xY7zA9",
    "gho_" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5",
])
def test_other_github_token_kinds(value):
    assert found(value) == [("GITHUB_TOKEN", value)]


def test_stripe_test_key_matches():
    value = "sk_" + "test_" + "Ab3dE5fG7hJ9kL1mN3pQ5rS7"
    assert found(value) == [("STRIPE_KEY", value)]


def test_anthropic_key_is_not_also_an_openai_key():
    assert types(POSITIVES["ANTHROPIC_KEY"]) == ["ANTHROPIC_KEY"]


@pytest.mark.parametrize("value", [
    "mongodb+srv://user:p4ss@cluster0.x.mongodb.net/db",
    "mysql://root:toor@localhost:3306/shop",
    "postgresql+psycopg2://app:s3cret@10.0.0.5/app",
])
def test_db_url_variants(value):
    assert ("DB_CONNECTION_STRING", value) in found(f"url={value}")


@pytest.mark.parametrize("text", [
    "postgres://localhost/app",            # no credentials
    "mongodb://cluster0.example.net/db",   # no credentials
    "see https://user:pw@example.com/",    # not a database scheme
])
def test_db_urls_without_credentials_do_not_match(text):
    assert "DB_CONNECTION_STRING" not in types(text)


@pytest.mark.parametrize("text", [
    "the task-runner uses sk-short",               # too short for a key
    "ghp_tooshort",
    "xoxq-1234567890-abc",                         # unknown Slack prefix
    "eyJub3QiOiJqd3QifQ.eyJzdWIiOiI0MiJ9.abc",     # header has no "alg"
    "AIzaShort",
])
def test_lookalike_tokens_do_not_match(text):
    assert types(text) == []


# ---------------------------------------------------------------- private keys

def test_complete_private_key_block():
    pem = f"{PEM_BEGIN}\nMIIEowIBAAKCAQEAu1SU1L7VLPHCgcBIjb\nq8Zr2LxV9mP3kT7wN4bY==\n{PEM_END}"
    assert found(f"key:\n{pem}\nthanks") == [("PRIVATE_KEY", pem)]


def test_truncated_private_key_still_matches_body():
    pem = "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nBG5vbmUAAAAEbm9uZQ"
    (type_, value), = found(pem)
    assert type_ == "PRIVATE_KEY" and value.endswith("BG5vbmUAAAAEbm9uZQ")


def test_public_key_and_certificate_do_not_match():
    assert types("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh\n-----END PUBLIC KEY-----") == []
    assert types("-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+g\n-----END CERTIFICATE-----") == []


# ---------------------------------------------------------------- prose

@pytest.mark.parametrize("text", [
    "What is the capital of France?",
    "The meeting is on 12/03/2024 at 10:30 in room 4512.",
    "Our revenue grew 1234567 rupees in Q3, up 12.5%.",
    "Please review PR #4821 and issue 1029.",
])
def test_prose_has_no_findings(text):
    assert detector.detect(text) == []

import math

import pytest

from app.detectors.entropy_detector import EntropyDetector, shannon_entropy

detector = EntropyDetector()        # defaults match config.yaml

RANDOM_B64 = "q8Zr2LxV9mP3kT7wN4bYc6Hd"                      # 24 chars, mixed
RANDOM_HEX = "a8f5f167f44f4964e6c998dee827110c"              # 32 hex chars
GIT_SHA = "d6d9d8cd4f27c52edac1f537e236ec48a01e54cb"


def spans(text):
    return [text[f["start"]:f["end"]] for f in detector.detect(text)]


def test_shannon_entropy_values():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abab") == 1
    assert math.isclose(shannon_entropy("abcdefgh"), 3)       # 8 equally likely symbols


def test_findings_have_the_common_shape():
    f = detector.detect(f"key {RANDOM_B64}")[0]
    assert f == {"type": "HIGH_ENTROPY_STRING", "start": 4, "end": 28,
                 "severity": "medium", "detector": "entropy"}


@pytest.mark.parametrize("text,token", [
    (f"api key {RANDOM_B64} done", RANDOM_B64),
    (f"X-Api-Key: {RANDOM_HEX}", RANDOM_HEX),
    (f"token={RANDOM_B64}_7Gh2", RANDOM_B64 + "_7Gh2"),         # name= is not part of it
    (f"API_KEY={RANDOM_B64}==", RANDOM_B64 + "=="),              # trailing padding is
    (f"value: {GIT_SHA}", GIT_SHA),                # 40-hex with NO hash context = could be a key
])
def test_random_tokens_are_flagged(text, token):
    assert spans(text) == [token]


@pytest.mark.parametrize("text", [
    "id 550e8400-e29b-41d4-a716-446655440000 created",          # UUID
    "request 6F9619FF-8B86-D011-B42D-00C04FC964FF failed",      # uppercase UUID
    f"commit {GIT_SHA}",                                        # git SHA in context
    f"git checkout {GIT_SHA}",
    f"sha256: {RANDOM_HEX}{RANDOM_HEX}",
    f"file_hash = '{RANDOM_HEX}'",
    "integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"",
], ids=["uuid", "uuid-upper", "commit", "git-checkout", "sha256", "hash-var", "sri"])
def test_ids_and_hashes_in_context_are_not_flagged(text):
    assert spans(text) == []


@pytest.mark.parametrize("text", [
    "12345678901234567890123",                                  # plain number
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",                          # low entropy
    "get_user_by_email_address_v2",                             # identifier, lowercase
    "ThisIsAVeryLongCamelCaseIdentifier",                       # no digits
    "STATE_OF_THE_ART_MODEL_2024_V2",                           # uppercase only
    "state-of-the-art-machine-learning-2024",                   # hyphenated prose
    "--------------------------------",                         # markdown rule
    "What is the capital of France? Paris has 2148271 people.",
])
def test_normal_text_is_not_flagged(text):
    assert spans(text) == []


def test_short_tokens_are_ignored():
    assert spans("k=q8Zr2LxV9mP3kT7wN4b") == []                 # 19 chars


def test_thresholds_are_configurable():
    strict = EntropyDetector(base64_threshold=5.5)
    assert strict.detect(f"key {RANDOM_B64}") == []
    # a 13-char token can't reach 4.0 bits (max is log2(13) = 3.7) - lower both
    loose = EntropyDetector(min_length=12, base64_threshold=3.5)
    assert loose.detect("key q8Zr2LxV9mP3k") != []

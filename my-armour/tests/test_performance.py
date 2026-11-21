"""Guard against catastrophic regex backtracking (ReDoS).

A quadratic pattern takes 5-16 s on these 100 KB inputs (it did, before the
EMAIL and DB_CONNECTION_STRING fixes); linear ones take well under 0.2 s.
The budget is generous so slow machines don't flake, but O(n^2) still fails.
"""
import random
import string
import time

import pytest

from app.detectors import scan_text

N = 100_000
random.seed(0)
ADVERSARIAL = {
    "long-word": "a" * N,
    "long-number": "1" * N,
    "random-alnum": "".join(random.choice(string.ascii_letters + string.digits) for _ in range(N)),
    "random-printable": "".join(random.choice(string.printable) for _ in range(N)),
    "at-signs": "a@" * (N // 2),
    "dotted-domain": "x@" + "a." * (N // 2),
    "dashed-digits": "1-" * (N // 2),
    "db-scheme-repeated": "postgres://a:" * (N // 13),
    "pem-begin-no-end": ("-----BEGIN RSA " + "PRIVATE KEY-----\n" + "x " * 30) * 1000,
    "many-short-lines": "\n".join(f"line {i}: summarise topic {i}." for i in range(4000)),
}
BUDGET_SECONDS = 2.0


@pytest.mark.parametrize("text", ADVERSARIAL.values(), ids=list(ADVERSARIAL))
def test_scan_is_fast_on_adversarial_input(text):
    start = time.perf_counter()
    scan_text(text)
    assert time.perf_counter() - start < BUDGET_SECONDS

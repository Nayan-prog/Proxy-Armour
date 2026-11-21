"""GET /api/stats."""
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import add_events, event_payload


@pytest.fixture
def traffic(api):
    now = datetime.now(timezone.utc)
    add_events(
        {"action": "block", "finding_types": ["AADHAAR", "EMAIL"], "ts": now - timedelta(minutes=10),
         "latency_ms_total": 100.0},
        {"action": "tokenize", "finding_types": ["EMAIL"], "ts": now - timedelta(hours=3),
         "leak_flag": True, "latency_ms_total": 300.0},
        {"action": "allow", "finding_types": [], "provider": "anthropic", "host": "api.anthropic.com",
         "ts": now - timedelta(hours=5), "latency_ms_total": 200.0},
        {"action": "tokenize", "finding_types": ["HARDCODED_SECRET"], "provider": "google",
         "host": "generativelanguage.googleapis.com", "ts": now - timedelta(days=2)},
        {"action": "block", "finding_types": ["PAN"], "ts": now - timedelta(days=30)},   # outside 7d
    )


def test_stats_24h(api, auth, traffic):
    r = api.get("/api/stats?range=24h", headers=auth)
    assert r.status_code == 200
    s = r.json()
    assert s["totals"] == {"requests": 3, "blocked": 1, "tokenized": 1, "allowed": 1, "leaks": 1,
                           "tokens_issued": 3, "tokens_restored": 3, "tokens_missing": 0,
                           "restoration_rate": 1.0,
                           "avg_latency_ms_total": 200.0, "avg_latency_ms_scan": 3.5}
    assert s["by_action"] == {"block": 1, "tokenize": 1, "allow": 1}
    assert s["by_type"] == {"EMAIL": 2, "AADHAAR": 1}
    assert s["by_provider"] == {"openai": 2, "anthropic": 1}
    assert len(s["timeseries"]) in (24, 25)                         # hourly, zero-filled
    assert sum(b["total"] for b in s["timeseries"]) == 3
    assert sum(b["block"] for b in s["timeseries"]) == 1
    assert s["live_counters"] is None                                # no Redis configured


def test_stats_7d(api, auth, traffic):
    s = api.get("/api/stats?range=7d", headers=auth).json()
    assert s["totals"]["requests"] == 4
    assert s["by_type"] == {"EMAIL": 2, "AADHAAR": 1, "HARDCODED_SECRET": 1}
    assert len(s["timeseries"]) in (7, 8)                            # daily
    assert sum(b["tokenize"] for b in s["timeseries"]) == 2


def test_stats_on_an_empty_database(api, auth):
    s = api.get("/api/stats", headers=auth).json()
    assert s["totals"]["requests"] == 0 and s["by_type"] == {}
    assert s["totals"]["avg_latency_ms_total"] is None
    assert s["totals"]["restoration_rate"] is None          # nothing tokenized: no rate


def test_restoration_rate(api, auth):
    add_events({"tokens_issued": 4, "tokens_restored": 3, "tokens_missing": 1},
               {"tokens_issued": 0, "tokens_restored": 0, "action": "allow"})
    t = api.get("/api/stats", headers=auth).json()["totals"]
    assert (t["tokens_issued"], t["tokens_restored"], t["restoration_rate"]) == (4, 3, 0.75)


def test_stats_include_live_redis_counters(api, auth, secret_header, fake_redis):
    api.post("/events", json=event_payload(action="tokenize"), headers=secret_header)
    counters = api.get("/api/stats", headers=auth).json()["live_counters"]
    assert len(counters) == 60
    assert counters[-1]["requests"] == 1 and counters[-1]["tokenized"] == 1


def test_bad_range_is_422(api, auth):
    assert api.get("/api/stats?range=1y", headers=auth).status_code == 422

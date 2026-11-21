"""POST /events (proxy -> API) and GET /api/events[/{id}] (dashboard)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

import armour_config
from app import db, live
from app.models import Event
from tests.conftest import EVENTS_SECRET, add_events, event_payload, make_env


def stored(event_id):
    with db.session_factory()() as session:
        return session.get(Event, event_id)


# ------------------------------------------------------------------ POST /events

def test_event_is_stored(api, secret_header):
    r = api.post("/events", json=event_payload(), headers=secret_header)
    assert r.status_code == 201
    row = stored(r.json()["id"])
    assert (row.action, row.finding_types, row.detectors_used, row.tokens_issued) == \
           ("tokenize", ["EMAIL"], ["regex"], 1)
    assert row.ts is not None                                  # server fills ts if absent


@pytest.mark.parametrize("headers", [{}, {"X-Armour-Secret": "wrong"},
                                     {"X-Armour-Secret": EVENTS_SECRET + "x"}],
                         ids=["missing", "wrong", "longer"])
def test_event_needs_the_shared_secret(api, headers):
    assert api.post("/events", json=event_payload(), headers=headers).status_code == 401


def test_events_are_503_without_a_configured_secret(api, monkeypatch):
    monkeypatch.setattr(armour_config, "env", make_env())
    r = api.post("/events", json=event_payload(), headers={"X-Armour-Secret": "anything"})
    assert r.status_code == 503


def test_events_are_503_without_a_database(api, secret_header):
    db.configure(None)
    assert api.post("/events", json=event_payload(), headers=secret_header).status_code == 503


@pytest.mark.parametrize("override", [
    {"prompt": "my email is rahul@acme.com"},                       # unknown field
    {"value": "hunter22"},
    {"finding_types": ["rahul@acme.com"]},                           # value smuggled as a type
    {"finding_types": ["PA_EMAIL_7D2E91F0 x"]},
    {"endpoint": "/v1beta/models/x:generateContent?key=AIzaSecret"}, # query string (API key)
    {"endpoint": "/v1/chat completions"},
    {"host": "API.OPENAI.COM/../x"},
    {"action": "redact"},
    {"provider": "someone"},
    {"detectors_used": ["regex", "guesswork"]},
    {"tokens_issued": -1},
    {"status_code": 42},
], ids=lambda o: next(iter(o)))
def test_anything_but_metadata_is_rejected(api, secret_header, override):
    r = api.post("/events", json=event_payload(**override), headers=secret_header)
    assert r.status_code == 422
    with db.session_factory()() as session:
        assert session.query(Event).count() == 0


def test_event_updates_redis_counters_and_publishes(api, secret_header, fake_redis):
    pubsub = fake_redis.pubsub()
    pubsub.subscribe(live.CHANNEL)
    pubsub.get_message(timeout=1)                                    # subscribe confirmation
    ts = datetime(2026, 11, 19, 10, 15, tzinfo=timezone.utc)
    api.post("/events", json=event_payload(ts=ts.isoformat(), action="block",
                                           finding_types=["AADHAAR", "EMAIL"]), headers=secret_header)
    counters = fake_redis.hgetall("armour:m:202611191015")
    assert counters == {"requests": "1", "blocked": "1", "type:AADHAAR": "1", "type:EMAIL": "1",
                        "blocked:type:AADHAAR": "1", "blocked:type:EMAIL": "1"}
    assert 0 < fake_redis.ttl("armour:m:202611191015") <= live.COUNTER_TTL_SECONDS
    message = pubsub.get_message(timeout=1)
    assert json.loads(message["data"])["finding_types"] == ["AADHAAR", "EMAIL"]


def test_redis_down_does_not_break_event_logging(api, secret_header, monkeypatch):
    monkeypatch.setattr(armour_config, "env", armour_config.env.model_copy(
        update={"redis_url": armour_config.SecretStr("redis://127.0.0.1:1/0")}))   # nothing listens
    r = api.post("/events", json=event_payload(), headers=secret_header)
    assert r.status_code == 201
    assert live.LINK.sync() is None                                  # backed off, no more timeouts


# ------------------------------------------------------------------ GET /api/events

NOW = datetime.now(timezone.utc)


@pytest.fixture
def some_events(api):
    return add_events(
        {"action": "block", "finding_types": ["AADHAAR"], "provider": "openai", "ts": NOW - timedelta(minutes=5)},
        {"action": "tokenize", "finding_types": ["EMAIL", "HARDCODED_SECRET"], "provider": "anthropic",
         "host": "api.anthropic.com", "ts": NOW - timedelta(hours=2)},
        {"action": "allow", "finding_types": [], "provider": "openai", "ts": NOW - timedelta(days=3)},
        {"action": "tokenize", "finding_types": ["EMAIL"], "provider": "google",
         "host": "generativelanguage.googleapis.com", "ts": NOW - timedelta(days=10)},
    )


def ids_of(response):
    return [item["id"] for item in response.json()["items"]]


def test_events_are_listed_newest_first(api, auth, some_events):
    r = api.get("/api/events", headers=auth)
    assert r.status_code == 200
    assert ids_of(r) == some_events and r.json()["total"] == 4


def test_pagination(api, auth, some_events):
    r = api.get("/api/events?page=2&page_size=3", headers=auth)
    assert ids_of(r) == some_events[3:]
    assert (r.json()["total"], r.json()["page"], r.json()["page_size"]) == (4, 2, 3)


@pytest.mark.parametrize("query,expected", [
    ("action=tokenize", [1, 3]),
    ("type=EMAIL", [1, 3]),
    ("type=HARDCODED_SECRET", [1]),
    ("provider=openai", [0, 2]),
    ("action=tokenize&type=EMAIL&provider=google", [3]),
])
def test_filters(api, auth, some_events, query, expected):
    assert ids_of(api.get(f"/api/events?{query}", headers=auth)) == [some_events[i] for i in expected]


def test_date_range_filter(api, auth, some_events):
    params = {"from": (NOW - timedelta(days=4)).isoformat(), "to": (NOW - timedelta(hours=1)).isoformat()}
    assert ids_of(api.get("/api/events", params=params, headers=auth)) == [some_events[1], some_events[2]]


@pytest.mark.parametrize("query", ["page=0", "page_size=101", "action=redact", "type=email",
                                   "provider=nobody", "from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z"])
def test_bad_query_parameters_are_422(api, auth, query):
    assert api.get(f"/api/events?{query}", headers=auth).status_code == 422


def test_get_one_event(api, auth, some_events):
    r = api.get(f"/api/events/{some_events[1]}", headers=auth)
    assert r.status_code == 200
    assert r.json()["finding_types"] == ["EMAIL", "HARDCODED_SECRET"]
    assert api.get("/api/events/999999", headers=auth).status_code == 404

"""GET /api/live (SSE) and POST /api/playground/scan."""
import asyncio
import json

from app import db, live
from app.api.admin import _poll_new_events
from app.models import Event
from tests.conftest import add_events, event_payload

EMAIL, SECRET = "rahul@acme.com", "hunter22"


def collect(max_events, while_streaming=None, timeout=5.0):
    """Run event_stream until max_events arrive; while_streaming() runs once subscribed."""
    async def scenario():
        chunks = []

        async def never_disconnected():
            return False

        async def consume():
            async for chunk in live.event_stream(never_disconnected, _poll_new_events,
                                                 poll_seconds=0.05, heartbeat_seconds=60,
                                                 max_events=max_events):
                chunks.append(chunk)

        task = asyncio.create_task(consume())
        await asyncio.sleep(0.2)                    # let it subscribe / take its first poll
        if while_streaming:
            await asyncio.to_thread(while_streaming)
        await asyncio.wait_for(task, timeout)
        return chunks

    return asyncio.run(scenario())


def events_in(chunks):
    return [json.loads(c.split("data: ", 1)[1]) for c in chunks if c.startswith("event: event")]


def test_live_feed_from_redis_pubsub(api, secret_header, fake_redis):
    chunks = collect(2, lambda: [api.post("/events", json=event_payload(action=a), headers=secret_header)
                                 for a in ("block", "tokenize")])
    assert ": source=redis\n\n" in chunks
    assert [e["action"] for e in events_in(chunks)] == ["block", "tokenize"]


def test_live_feed_falls_back_to_db_polling_without_redis(api):
    add_events({"action": "allow"})                 # history: must NOT be replayed
    chunks = collect(1, lambda: add_events({"action": "block", "finding_types": ["PAN"]}))
    assert ": source=polling\n\n" in chunks
    (event,) = events_in(chunks)
    assert (event["action"], event["finding_types"]) == ("block", ["PAN"])


def test_live_endpoint_requires_auth(api):
    # the authorised stream never ends, so its body is tested via event_stream above
    assert api.get("/api/live").status_code == 401
    assert api.get("/api/live", headers={"Authorization": "Bearer nope"}).status_code == 401


# ------------------------------------------------------------------ playground

def test_playground_returns_findings_and_tokenized_preview(api, auth):
    text = f'mail {EMAIL}\npassword = "{SECRET}"'
    r = api.post("/api/playground/scan", headers=auth, json={"text": text})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "tokenize" and body["risk"] == "high"
    found = {(f["type"], text[f["start"]:f["end"]], f["detector"]) for f in body["findings"]}
    assert ("EMAIL", EMAIL, "regex") in found and ("HARDCODED_SECRET", SECRET, "ast") in found
    preview = body["tokenized_preview"]
    assert EMAIL not in preview and SECRET not in preview
    assert sorted(body["placeholders"].values()) == ["EMAIL", "HARDCODED_SECRET"]
    for placeholder in body["placeholders"]:
        assert placeholder in preview
    assert EMAIL not in r.text and SECRET not in r.text            # values never echoed


def test_playground_reports_block_policy(api, auth):
    body = api.post("/api/playground/scan", headers=auth, json={"text": "aadhaar 2345 6789 0124"}).json()
    assert body["action"] == "block" and body["tokenized_preview"] == "aadhaar 2345 6789 0124"


def test_playground_never_stores_or_publishes(api, auth, fake_redis):
    pubsub = fake_redis.pubsub()
    pubsub.subscribe(live.CHANNEL)
    pubsub.get_message(timeout=1)
    api.post("/api/playground/scan", headers=auth, json={"text": f"mail {EMAIL}"})
    with db.session_factory()() as session:
        assert session.query(Event).count() == 0
    assert pubsub.get_message(timeout=0.2) is None
    assert fake_redis.keys("armour:*") == []


def test_playground_limits(api, auth):
    assert api.post("/api/playground/scan", json={"text": "x"}).status_code == 401
    r = api.post("/api/playground/scan", headers=auth, json={"text": "x" * 100_001})
    assert r.status_code == 422

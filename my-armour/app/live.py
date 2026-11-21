"""Optional Redis: per-minute live counters + pub/sub for the dashboard live feed.

Everything here degrades to a no-op when REDIS_URL is unset or Redis is down;
after a failure Redis is skipped for RETRY_SECONDS so an outage can't slow
requests down with connection timeouts.
"""
import asyncio
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timedelta, timezone

import redis
import redis.asyncio as aioredis

import armour_config

CHANNEL = "armour:events"
COUNTER_PREFIX = "armour:m:"            # one hash per minute: armour:m:202611191530
COUNTER_TTL_SECONDS = 2 * 24 * 3600
RETRY_SECONDS = 30
ACTION_FIELD = {"block": "blocked", "tokenize": "tokenized", "allow": "allowed"}


class RedisLink:
    def __init__(self):
        self._sync: redis.Redis | None = None
        self._async: aioredis.Redis | None = None
        self._down_until = 0.0
        self.injected = False

    def use(self, sync_client, async_client) -> None:
        """Tests: plug in (fake) clients regardless of REDIS_URL."""
        self._sync, self._async, self.injected, self._down_until = sync_client, async_client, True, 0.0

    def reset(self) -> None:
        self.__init__()

    def _url(self) -> str | None:
        url = armour_config.env.redis_url
        return url.get_secret_value() if url else None

    def _available(self) -> bool:
        return (self.injected or self._url() is not None) and time.monotonic() >= self._down_until

    def sync(self) -> redis.Redis | None:
        if not self._available():
            return None
        if self._sync is None:
            self._sync = redis.Redis.from_url(self._url(), decode_responses=True,
                                              socket_timeout=0.5, socket_connect_timeout=0.5)
        return self._sync

    def aio(self) -> aioredis.Redis | None:
        if not self._available():
            return None
        if self._async is None:
            self._async = aioredis.Redis.from_url(self._url(), decode_responses=True,
                                                  socket_connect_timeout=0.5)
        return self._async

    def mark_down(self) -> None:
        if not self.injected:
            print(f"[ARMOUR-API] Redis unavailable - live counters/feed paused for {RETRY_SECONDS}s")
        self._down_until = time.monotonic() + RETRY_SECONDS


LINK = RedisLink()


def minute_key(ts: datetime) -> str:
    return COUNTER_PREFIX + ts.astimezone(timezone.utc).strftime("%Y%m%d%H%M")


def record(event: dict, ts: datetime) -> bool:
    """Increment this minute's counters and publish the event. False if Redis is off."""
    r = LINK.sync()
    if r is None:
        return False
    key = minute_key(ts)
    action_field = ACTION_FIELD.get(event["action"], event["action"])
    try:
        pipe = r.pipeline()
        pipe.hincrby(key, "requests", 1)
        pipe.hincrby(key, action_field, 1)
        for t in event.get("finding_types", []):
            pipe.hincrby(key, f"type:{t}", 1)
            pipe.hincrby(key, f"{action_field}:type:{t}", 1)
        pipe.expire(key, COUNTER_TTL_SECONDS)
        pipe.publish(CHANNEL, json.dumps(event, default=str))
        pipe.execute()
        return True
    except redis.RedisError:
        LINK.mark_down()
        return False


def recent_counters(minutes: int = 60, now: datetime | None = None) -> list[dict] | None:
    """Per-minute counters for the last `minutes` minutes, oldest first. None if Redis is off."""
    r = LINK.sync()
    if r is None:
        return None
    now = now or datetime.now(timezone.utc)
    stamps = [now - timedelta(minutes=i) for i in range(minutes - 1, -1, -1)]
    try:
        pipe = r.pipeline()
        for ts in stamps:
            pipe.hgetall(minute_key(ts))
        rows = pipe.execute()
    except redis.RedisError:
        LINK.mark_down()
        return None
    return [{"minute": ts.strftime("%Y-%m-%dT%H:%M:00Z"), **{k: int(v) for k, v in row.items()}}
            for ts, row in zip(stamps, rows)]


async def event_stream(is_disconnected: Callable[[], Awaitable[bool]],
                       poll_db: Callable[[int | None], Awaitable[tuple[int | None, list[dict]]]],
                       *, poll_seconds: float, heartbeat_seconds: float,
                       max_events: int | None = None) -> AsyncIterator[str]:
    """SSE body for /api/live: Redis pub/sub, or DB polling if Redis is unavailable.

    poll_db(last_id) -> (new last_id, events with id > last_id); poll_db(None)
    returns the current max id without events (so history isn't replayed).
    max_events stops the stream after that many events (used by tests).
    """
    yield "retry: 3000\n\n"
    sent = 0
    client = LINK.aio()
    if client is not None:
        pubsub = client.pubsub()
        try:
            await pubsub.subscribe(CHANNEL)
            yield ": source=redis\n\n"
            last_beat = time.monotonic()
            while not await is_disconnected():
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message is not None:
                    yield f"event: event\ndata: {message['data']}\n\n"
                    sent += 1
                    if max_events is not None and sent >= max_events:
                        return
                elif time.monotonic() - last_beat >= heartbeat_seconds:
                    yield ": keep-alive\n\n"
                    last_beat = time.monotonic()
            return
        except redis.RedisError:
            LINK.mark_down()                     # fall through to polling
        finally:
            try:
                await pubsub.aclose()
            except Exception:
                pass

    yield ": source=polling\n\n"
    last_id, _ = await poll_db(None)
    last_beat = time.monotonic()
    while not await is_disconnected():
        last_id, events = await poll_db(last_id)
        for event in events:
            yield f"event: event\ndata: {json.dumps(event, default=str)}\n\n"
            sent += 1
            if max_events is not None and sent >= max_events:
                return
        if not events and time.monotonic() - last_beat >= heartbeat_seconds:
            yield ": keep-alive\n\n"
            last_beat = time.monotonic()
        await asyncio.sleep(poll_seconds)

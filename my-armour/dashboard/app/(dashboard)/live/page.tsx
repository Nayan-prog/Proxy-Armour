"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { ActionBadge, Button, Card, EmptyState, PageHeader, TypeChip, cx } from "@/components/ui";
import { LIVE_URL, type AuditEvent } from "@/lib/api";
import { PROVIDER_LABEL, formatMs } from "@/lib/format";

const MAX_ROWS = 200;
type Status = "connecting" | "live" | "reconnecting";

export default function LivePage() {
  const router = useRouter();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [queued, setQueued] = useState<AuditEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [status, setStatus] = useState<Status>("connecting");
  const pausedRef = useRef(paused);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    // same-origin: the httpOnly session cookie goes with it; the route handler
    // adds the bearer token for the admin API
    const source = new EventSource(LIVE_URL);
    source.onopen = () => setStatus("live");
    source.addEventListener("event", (message) => {
      let event: AuditEvent;
      try {
        event = JSON.parse((message as MessageEvent<string>).data) as AuditEvent;
      } catch {
        return;
      }
      if (pausedRef.current) setQueued((q) => [event, ...q].slice(0, MAX_ROWS));
      else setEvents((list) => [event, ...list].slice(0, MAX_ROWS));
    });
    source.onerror = async () => {
      setStatus("reconnecting");               // EventSource retries by itself
      const session = await fetch("/api/auth/session", { cache: "no-store" }).catch(() => null);
      if (session?.status === 401) {
        source.close();
        router.replace("/login?next=%2Flive");
      }
    };
    return () => source.close();
  }, [router]);

  function togglePause() {
    if (paused) {
      setEvents((list) => [...queued, ...list].slice(0, MAX_ROWS));
      setQueued([]);
    }
    setPaused(!paused);
  }

  const indicator = paused ? ["bg-warn", "Paused"] : {
    connecting: ["bg-subtle", "Connecting…"],
    live: ["bg-ok animate-pulse", "Live"],
    reconnecting: ["bg-warn", "Reconnecting…"],
  }[status];

  return (
    <>
      <PageHeader
        title="Live feed"
        description="Requests as the proxy finishes them, newest first."
        actions={
          <>
            <span className="inline-flex h-9 items-center gap-2 rounded-full bg-raised px-3.5 text-[13px] font-semibold text-fg"
              aria-live="polite">
              <span className={cx("h-2 w-2 rounded-full", indicator[0])} />
              {indicator[1]}
            </span>
            <Button variant={paused ? "primary" : "secondary"} onClick={togglePause}>
              {paused ? `Resume${queued.length ? ` (${queued.length} new)` : ""}` : "Pause"}
            </Button>
            <Button variant="ghost" disabled={!events.length} onClick={() => setEvents([])}>Clear</Button>
          </>
        }
      />

      <Card>
        {events.length === 0 ? (
          <EmptyState title={status === "live" ? "Waiting for traffic…" : "Connecting to the live feed…"}>
            Send a prompt through the proxy and it will appear here within a second
            (or a few seconds when Redis is not configured).
          </EmptyState>
        ) : (
          <ol className="-mx-2 -my-2" aria-label="Live events">
            {events.map((e) => (
              <li key={e.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-xl px-2 py-2.5 text-sm transition-colors hover:bg-raised/70">
                <time className="w-20 shrink-0 tabular-nums text-subtle" dateTime={e.ts}>
                  {new Date(e.ts).toLocaleTimeString()}
                </time>
                <span className="w-28 shrink-0"><ActionBadge action={e.action} /></span>
                <span className="w-32 shrink-0 font-medium text-fg">{PROVIDER_LABEL[e.provider]}</span>
                <span className="flex min-w-0 flex-1 flex-wrap gap-1">
                  {e.finding_types.length ? e.finding_types.map((t) => <TypeChip key={t} type={t} />)
                    : <span className="text-subtle">no findings</span>}
                </span>
                <span className="tabular-nums text-muted">
                  {e.tokens_issued ? `${e.tokens_restored}/${e.tokens_issued} restored` : ""}
                  {e.leak_flag && <span className="ml-2 text-danger">leak</span>}
                </span>
                <span className="w-16 whitespace-nowrap text-right tabular-nums text-subtle">{formatMs(e.latency_ms_total)}</span>
                <Link href={`/events/${e.id}`} className="rounded-full px-2 py-1 text-xs font-semibold text-accent hover:bg-elevated">Details</Link>
              </li>
            ))}
          </ol>
        )}
      </Card>
    </>
  );
}

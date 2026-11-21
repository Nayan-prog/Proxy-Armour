"use client";

import Link from "next/link";
import { use, type ReactNode } from "react";

import {
  ActionBadge, Banner, Card, EmptyState, ICONS, Icon, ErrorState, LoadingBlock, PageHeader, SeverityBadge, TypeChip, cx,
} from "@/components/ui";
import { api } from "@/lib/api";
import { PROVIDER_LABEL, formatMs, formatTime } from "@/lib/format";
import { useApi } from "@/lib/useApi";

const DETECTOR_INFO: Record<string, string> = {
  regex: "Pattern + checksum rules (Aadhaar, PAN, cards, API keys, …)",
  entropy: "Random-looking tokens (unknown key formats)",
  ast: "Hard-coded secrets in Python code",
};

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-4 py-3 text-sm">
      <dt className="text-[13.5px] text-muted">{label}</dt>
      <dd className="col-span-2 text-fg">{children}</dd>
    </div>
  );
}

function Flag({ ok, good, bad, na }: { ok: boolean | null; good: string; bad: string; na: string }) {
  if (ok === null) return <span className="text-subtle">{na}</span>;
  return (
    <span className={cx("inline-flex items-center gap-1.5", ok ? "text-ok" : "text-danger")}>
      <span className={cx("h-1.5 w-1.5 rounded-full", ok ? "bg-ok" : "bg-danger")} />
      {ok ? good : bad}
    </span>
  );
}

export function EventDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const eventId = Number(id);
  const valid = Number.isInteger(eventId) && eventId > 0;
  const { data: e, error, reload } = useApi(`event:${id}`, () =>
    valid ? api.event(eventId) : Promise.reject(new Error("invalid id")));

  const back = (
    <Link href="/events"
      className="inline-flex h-9 items-center gap-2 rounded-full bg-raised px-4 text-[13px] font-semibold text-fg hover:bg-elevated">
      <Icon d={ICONS.back} className="h-4 w-4" /> All events
    </Link>
  );

  if (!valid || error?.status === 404) {
    return (
      <>
        <PageHeader title="Event not found" actions={back} />
        <Card><EmptyState title={`There is no event #${id}.`} /></Card>
      </>
    );
  }
  if (error) return <><PageHeader title={`Event #${id}`} actions={back} /><ErrorState message={error.message} onRetry={reload} /></>;
  if (!e) return <><PageHeader title={`Event #${id}`} actions={back} /><LoadingBlock /></>;

  return (
    <>
      <PageHeader
        title={`Event #${e.id}`}
        description={formatTime(e.ts, true)}
        actions={back}
      />
      {e.leak_flag && (
        <div className="mb-6">
          <Banner>
            <strong className="font-semibold text-danger">Possible leak.</strong> The LLM response contained an original
            value that had been tokenized - the provider may already know it.
          </Banner>
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <Card title="Request">
          <dl className="divide-y divide-edge/60">
            <Row label="Provider">{PROVIDER_LABEL[e.provider]}</Row>
            <Row label="Host"><span className="font-mono text-xs">{e.host}</span></Row>
            <Row label="Endpoint"><span className="break-all font-mono text-xs">{e.endpoint}</span></Row>
            <Row label="Status">{e.status_code ?? <span className="text-danger">upstream error</span>}</Row>
            <Row label="Scan time">{formatMs(e.latency_ms_scan)} <span className="text-subtle">(added by Proxy Armour)</span></Row>
            <Row label="Total time">{formatMs(e.latency_ms_total)}</Row>
          </dl>
        </Card>

        <Card title="Decision">
          <dl className="divide-y divide-edge/60">
            <Row label="Action"><ActionBadge action={e.action} /></Row>
            <Row label="Risk">{e.risk ? <SeverityBadge level={e.risk} /> : <span className="text-subtle">not scanned</span>}</Row>
            <Row label="Findings">
              {e.finding_count} finding{e.finding_count === 1 ? "" : "s"}
              <div className="mt-2 flex flex-wrap gap-1">
                {e.finding_types.length ? e.finding_types.map((t) => <TypeChip key={t} type={t} />)
                  : <span className="text-subtle">no sensitive data detected</span>}
              </div>
            </Row>
            <Row label="Detectors used">
              {e.detectors_used.length ? (
                <ul className="flex flex-col gap-1.5">
                  {e.detectors_used.map((d) => (
                    <li key={d}>
                      <span className="rounded-md bg-elevated px-1.5 py-0.5 font-mono text-xs text-accent">{d}</span>
                      <span className="ml-2 text-xs text-subtle">{DETECTOR_INFO[d]}</span>
                    </li>
                  ))}
                </ul>
              ) : <span className="text-subtle">none</span>}
            </Row>
          </dl>
        </Card>

        <Card title="Tokenization & restoration" className="lg:col-span-2">
          {e.tokens_issued === 0 ? (
            <p className="text-sm text-subtle">No values were tokenized for this request.</p>
          ) : (
            <div className="grid gap-6 md:grid-cols-2">
              <div className="grid grid-cols-4 gap-3 text-center">
                {([["Issued", e.tokens_issued, "text-fg"], ["Restored", e.tokens_restored, "text-ok"],
                   ["Missing", e.tokens_missing, e.tokens_missing ? "text-warn" : "text-muted"],
                   ["Unknown", e.tokens_unknown, e.tokens_unknown ? "text-warn" : "text-muted"]] as const)
                  .map(([label, value, color]) => (
                    <div key={label} className="rounded-2xl bg-raised p-3">
                      <p className={cx("text-[22px] font-bold tabular-nums", color)}>{value}</p>
                      <p className="text-xs text-subtle">{label}</p>
                    </div>
                  ))}
              </div>
              <dl className="divide-y divide-edge/60">
                <Row label="Leak check"><Flag ok={!e.leak_flag} good="no original value in the response" bad="original value returned by the LLM" na="" /></Row>
                <Row label="Python syntax">
                  <Flag ok={e.syntax_valid} good="restored code parses" bad="restored code does not parse" na="no Python code in the response" />
                </Row>
              </dl>
            </div>
          )}
          <p className="mt-4 text-xs text-subtle">
            Missing = placeholders the LLM did not return. Unknown = PA_-shaped strings that were never issued (left untouched).
            Original values and placeholders are never stored, so they cannot be shown here.
          </p>
        </Card>
      </div>
    </>
  );
}

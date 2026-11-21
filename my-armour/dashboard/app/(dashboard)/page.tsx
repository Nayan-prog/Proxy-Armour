"use client";

import { useState } from "react";

import { ActionTimeline, ProviderBreakdown, TypeBars } from "@/components/charts";
import {
  Banner, Card, EmptyState, ErrorState, ICONS, LoadingBlock, PageHeader, SectionTitle, Segmented, Spinner, StatCard,
} from "@/components/ui";
import { api, type Range } from "@/lib/api";
import { formatMs, formatNumber, formatPercent } from "@/lib/format";
import { useApi } from "@/lib/useApi";

export default function OverviewPage() {
  const [range, setRange] = useState<Range>("24h");
  const { data, error, loading, reload } = useApi(`stats:${range}`, () => api.stats(range));
  const t = data?.totals;
  const share = (n: number) => (t && t.requests ? `${Math.round((n / t.requests) * 100)}%` : undefined);

  return (
    <>
      <PageHeader
        title="Overview"
        description="What Proxy Armour did to LLM traffic - counts and timings only."
      />

      {error && !data ? (
        <ErrorState message={error.message} onRetry={reload} />
      ) : (
        <div className="flex flex-col gap-[30px]">
          {t && t.leaks > 0 && (
            <Banner>
              <strong className="font-semibold text-danger">{t.leaks} possible leak{t.leaks === 1 ? "" : "s"}.</strong>{" "}
              An LLM response contained an original value that had been tokenized. Check Events for this time range.
            </Banner>
          )}

          <section>
            <SectionTitle actions={loading && data ? <Spinner /> : undefined}>Performance</SectionTitle>
            <Segmented label="Time range" value={range} onChange={setRange}
              options={[{ value: "24h", label: "Last 24 hours" }, { value: "7d", label: "Last 7 days" }]} />
            <div className="mt-3.5 grid grid-cols-2 gap-3 lg:grid-cols-3 xl:grid-cols-5">
              <StatCard label="Requests" icon={ICONS.requests} loading={!t} value={t && formatNumber(t.requests)}
                hint={t && `${formatNumber(t.allowed)} allowed unchanged`} />
              <StatCard label="Blocked" icon={ICONS.block} loading={!t} value={t && formatNumber(t.blocked)}
                pill={t && share(t.blocked)} hint="of all requests" />
              <StatCard label="Tokenized" icon={ICONS.token} loading={!t} value={t && formatNumber(t.tokenized)}
                pill={t && share(t.tokenized)} hint="of all requests" />
              <StatCard label="Restored" icon={ICONS.check} loading={!t}
                value={t && formatPercent(t.restoration_rate)}
                hint={t && (t.tokens_issued
                  ? `${formatNumber(t.tokens_restored)} of ${formatNumber(t.tokens_issued)} placeholders`
                  : "nothing tokenized yet")} />
              <StatCard label="Added latency" icon={ICONS.clock} loading={!t}
                value={t && formatMs(t.avg_latency_ms_scan)}
                hint={t && `avg scan · ${formatMs(t.avg_latency_ms_total)} total`} />
            </div>
          </section>

          <section>
            <SectionTitle>Traffic</SectionTitle>
            <Card title="Requests by action" subtitle={range === "24h" ? "Hourly, last 24 hours" : "Daily, last 7 days"}>
              {!data ? <LoadingBlock /> : t?.requests === 0 ? (
                <EmptyState title="No traffic in this range">
                  Send a prompt through the proxy, e.g.{" "}
                  <code className="rounded-md bg-raised px-1.5 py-0.5 font-mono text-xs text-fg">
                    python test_client.py &quot;mail rahul@acme.com&quot;
                  </code>
                </EmptyState>
              ) : (
                <ActionTimeline data={data.timeseries} range={range} />
              )}
            </Card>
          </section>

          <section>
            <SectionTitle>What was found</SectionTitle>
            <div className="grid gap-3 lg:grid-cols-3">
              <Card title="Findings by type" subtitle="Requests containing each type" className="lg:col-span-2">
                {!data ? <LoadingBlock /> : Object.keys(data.by_type).length === 0
                  ? <EmptyState title="No sensitive data detected in this range" />
                  : <TypeBars data={data.by_type} />}
              </Card>
              <Card title="Providers" subtitle="Share of requests">
                {!data ? <LoadingBlock /> : Object.keys(data.by_provider).length === 0
                  ? <EmptyState title="No requests yet" />
                  : <ProviderBreakdown data={data.by_provider} />}
              </Card>
            </div>
          </section>
        </div>
      )}
    </>
  );
}

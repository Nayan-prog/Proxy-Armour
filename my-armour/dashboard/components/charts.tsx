"use client";

import {
  Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";

import type { Provider, Range, TimeBucket } from "@/lib/api";
import { ACTIONS } from "@/lib/api";
import { ACTION_STYLE, PROVIDER_LABEL, formatBucket } from "@/lib/format";

/* Colours mirror the tokens in app/globals.css (Recharts needs literal values). */
const SURFACE = "#111113";
const AXIS = { stroke: "#8b8b93", fontSize: 11, tickLine: false, axisLine: false } as const;
const GRID = "#1d1d21";
const TOOLTIP = {
  contentStyle: {
    background: "#17171a", border: "none", borderRadius: 12, fontSize: 12,
    boxShadow: "0 8px 24px rgba(0,0,0,0.45)", padding: "8px 12px",
  },
  labelStyle: { color: "#f2f2f3", fontWeight: 600, marginBottom: 4 },
  itemStyle: { padding: 0, color: "#a1a1a8" },
  cursor: { fill: "rgba(255,255,255,0.04)" },
} as const;

/** Requests per bucket, stacked by action. Rounded top on the stack, 2px surface gaps between segments. */
export function ActionTimeline({ data, range }: { data: TimeBucket[]; range: Range }) {
  const top = ACTIONS[ACTIONS.length - 1];
  return (
    <div className="h-72" role="img" aria-label="Requests over time, stacked by action">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: -18 }} barCategoryGap="22%">
          <CartesianGrid stroke={GRID} vertical={false} />
          <XAxis dataKey="bucket" {...AXIS} minTickGap={24}
            tickFormatter={(value: string) => formatBucket(value, range)} />
          <YAxis {...AXIS} allowDecimals={false} />
          <Tooltip {...TOOLTIP} labelFormatter={(label) => formatBucket(String(label), range)} />
          {/* legend text stays in text ink; the dot carries the series colour */}
          <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12.5, paddingTop: 10 }}
            formatter={(value: string) => <span style={{ color: "#a1a1a8" }}>{value}</span>} />
          {ACTIONS.map((action) => (
            <Bar key={action} dataKey={action} name={ACTION_STYLE[action].label} stackId="actions"
              fill={ACTION_STYLE[action].chart} stroke={SURFACE} strokeWidth={2}
              radius={action === top ? [4, 4, 0, 0] : 0} maxBarSize={18} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/** Scaleagee "Views by source" bar: label · 8px track · value. */
function TrackRow({ label, value, share, mono, detail }: {
  label: string;
  value: number;
  share: number;
  mono?: boolean;
  detail?: string;
}) {
  return (
    <li className="group flex items-center gap-3" title={`${label}: ${value.toLocaleString()}${detail ? ` · ${detail}` : ""}`}>
      <span className={mono
        ? "w-[150px] shrink-0 truncate font-mono text-[11.5px] text-muted group-hover:text-fg"
        : "w-[110px] shrink-0 truncate text-[13px] text-muted group-hover:text-fg"}>
        {label}
      </span>
      <span className="h-2 min-w-0 flex-1 rounded-full bg-elevated">
        <span className="block h-2 rounded-full bg-brand transition-[width] group-hover:bg-accent"
          style={{ width: `${Math.max(2, share * 100)}%` }} />
      </span>
      <span className="w-14 shrink-0 text-right text-[13.5px] font-semibold tabular-nums text-fg">
        {value.toLocaleString()}
      </span>
    </li>
  );
}

export function TypeBars({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 12);
  const max = Math.max(1, ...rows.map(([, n]) => n));
  return (
    <ul className="flex flex-col gap-3" aria-label="Findings by type">
      {rows.map(([type, count]) => (
        <TrackRow key={type} label={type} value={count} share={count / max} mono detail="requests" />
      ))}
    </ul>
  );
}

export function ProviderBreakdown({ data }: { data: Partial<Record<Provider, number>> }) {
  const rows = (Object.entries(data) as [Provider, number][]).sort((a, b) => b[1] - a[1]);
  const total = rows.reduce((sum, [, n]) => sum + n, 0);
  return (
    <ul className="flex flex-col gap-3" aria-label="Requests by provider">
      {rows.map(([provider, count]) => {
        const share = total ? count / total : 0;
        return (
          <TrackRow key={provider} label={PROVIDER_LABEL[provider] ?? provider} value={count} share={share}
            detail={`${Math.round(share * 100)}% of requests`} />
        );
      })}
    </ul>
  );
}

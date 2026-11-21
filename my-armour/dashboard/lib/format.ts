import type { Action, Provider, Risk, Severity } from "./api";

/** Pill = dark chip + coloured dot + coloured label (Scaleagee status style). */
export const ACTION_STYLE: Record<Action, { label: string; badge: string; dot: string; chart: string }> = {
  allow: { label: "Allowed", badge: "text-muted", dot: "bg-subtle", chart: "#6b6b74" },
  tokenize: { label: "Tokenized", badge: "text-accent", dot: "bg-brand", chart: "#3b82f6" },
  block: { label: "Blocked", badge: "text-danger", dot: "bg-danger", chart: "#f87171" },
};

export const SEVERITY_STYLE: Record<Severity | Risk, string> = {
  none: "text-muted",
  low: "text-muted",
  medium: "text-warn",
  high: "text-danger",
};

export const PROVIDER_LABEL: Record<Provider, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  google: "Google Gemini",
  azure: "Azure OpenAI",
  mistral: "Mistral",
  groq: "Groq",
  other: "Other",
};

export function formatTime(iso: string, withSeconds = false): string {
  return new Date(iso).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    ...(withSeconds ? { second: "2-digit" } : {}),
  });
}

export function formatBucket(iso: string, range: "24h" | "7d"): string {
  const date = new Date(iso);
  return range === "24h"
    ? date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function formatMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`;
}

export function formatPercent(ratio: number | null | undefined): string {
  if (ratio === null || ratio === undefined) return "—";
  return `${(ratio * 100).toFixed(ratio === 1 || ratio === 0 ? 0 : 1)}%`;
}

export function formatNumber(n: number): string {
  return n.toLocaleString();
}

/** "2026-11-19T10:15" (datetime-local) -> ISO in UTC, or undefined. */
export function localInputToIso(value: string): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/** ISO -> value for <input type="datetime-local"> in the browser's timezone. */
export function isoToLocalInput(iso: string | null): string {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

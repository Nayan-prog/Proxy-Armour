/**
 * Typed client for the admin API, used by client components.
 *
 * Calls go to this app's own route handlers (/api/admin/*, /api/auth/*), which
 * attach the JWT from the httpOnly cookie - so no token handling here. Types
 * mirror app/schemas.py in the Python service.
 *
 * Privacy: nothing here carries original values - the API only stores metadata,
 * and the playground returns offsets + placeholder types.
 */

// ------------------------------------------------------------------ types

export type Action = "allow" | "tokenize" | "block";
export type Risk = "none" | "low" | "medium" | "high";
export type Severity = "low" | "medium" | "high";
export type Provider = "openai" | "anthropic" | "google" | "azure" | "mistral" | "groq" | "other";
export type DetectorName = "regex" | "entropy" | "ast";
export type Range = "24h" | "7d";

export const ACTIONS: Action[] = ["allow", "tokenize", "block"];
export const PROVIDERS: Provider[] = ["openai", "anthropic", "google", "azure", "mistral", "groq", "other"];

/** One proxied request. Metadata only: no prompt text, values or placeholders. */
export interface AuditEvent {
  id: number;
  ts: string;
  host: string;
  provider: Provider;
  endpoint: string;
  action: Action;
  risk: Risk | null;
  finding_types: string[];
  finding_count: number;
  detectors_used: DetectorName[];
  tokens_issued: number;
  tokens_restored: number;
  tokens_missing: number;
  tokens_unknown: number;
  leak_flag: boolean;
  syntax_valid: boolean | null;
  latency_ms_scan: number | null;
  latency_ms_total: number | null;
  status_code: number | null;
}

export interface EventPage {
  items: AuditEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface EventFilters {
  page?: number;
  page_size?: number;
  action?: Action;
  type?: string;
  provider?: Provider;
  from?: string; // ISO 8601
  to?: string;
}

export interface StatsTotals {
  requests: number;
  blocked: number;
  tokenized: number;
  allowed: number;
  leaks: number;
  tokens_issued: number;
  tokens_restored: number;
  tokens_missing: number;
  restoration_rate: number | null; // 0..1, null when nothing was tokenized
  avg_latency_ms_total: number | null;
  avg_latency_ms_scan: number | null;
}

export interface TimeBucket {
  bucket: string;
  allow: number;
  tokenize: number;
  block: number;
  total: number;
}

export interface LiveCounter {
  minute: string;
  [field: string]: string | number;
}

export interface Stats {
  range: Range;
  since: string;
  totals: StatsTotals;
  by_action: Partial<Record<Action, number>>;
  by_type: Record<string, number>;
  by_provider: Partial<Record<Provider, number>>;
  timeseries: TimeBucket[];
  live_counters: LiveCounter[] | null; // null when Redis is not configured
}

export interface Policy {
  type: string;
  action: Action;
  severity: Severity;
  updated_at: string | null;
  updated_by: string;
}

export interface PolicyUpdate {
  type: string;
  action: Action;
  severity?: Severity;
}

export interface PlaygroundFinding {
  type: string;
  start: number;
  end: number;
  severity: Severity;
  detector: DetectorName;
  action: Action;
}

export interface PlaygroundResult {
  risk: Risk;
  action: Action;
  findings: PlaygroundFinding[];
  tokenized_preview: string;
  placeholders: Record<string, string>; // placeholder -> finding type
}

// ------------------------------------------------------------------ client

export class ApiError extends Error {
  constructor(public status: number, message: string, public retryAfter?: number) {
    super(message);
    this.name = "ApiError";
  }
}

function detailOf(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    // FastAPI validation errors: [{loc, msg}, ...]
    return detail.map((d: { msg?: string }) => d.msg ?? "invalid value").join("; ");
  }
  return `request failed (HTTP ${status})`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: init?.body ? { "Content-Type": "application/json", ...init.headers } : init?.headers,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "network error - is the dashboard server running?");
  }
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const retry = Number(response.headers.get("retry-after")) || undefined;
    if (response.status === 401 && typeof window !== "undefined" && !path.startsWith("/api/auth/")) {
      // Session expired or revoked: back to the login page, then return here.
      // Deliberately a FULL page load (not client navigation) so nothing the
      // previous session held in memory survives.
      const login = new URL("/login", window.location.origin);
      login.searchParams.set("next", window.location.pathname + window.location.search);
      window.location.assign(login.href);
    }
    throw new ApiError(response.status, detailOf(body, response.status), retry);
  }
  return body as T;
}

function query(params: object): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const s = search.toString();
  return s ? `?${s}` : "";
}

export const api = {
  login: (username: string, password: string) =>
    request<{ ok: true; expires_at: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  logout: () => request<{ ok: true }>("/api/auth/logout", { method: "POST" }),

  stats: (range: Range) => request<Stats>(`/api/admin/stats${query({ range })}`),

  events: (filters: EventFilters = {}) => request<EventPage>(`/api/admin/events${query(filters)}`),

  event: (id: number) => request<AuditEvent>(`/api/admin/events/${id}`),

  policies: () => request<Policy[]>("/api/admin/policies"),

  savePolicies: (policies: PolicyUpdate[]) =>
    request<Policy[]>("/api/admin/policies", { method: "PUT", body: JSON.stringify({ policies }) }),

  playgroundScan: (text: string) =>
    request<PlaygroundResult>("/api/admin/playground/scan", { method: "POST", body: JSON.stringify({ text }) }),
};

/** Same-origin SSE URL for EventSource (the route handler adds the token). */
export const LIVE_URL = "/api/live";

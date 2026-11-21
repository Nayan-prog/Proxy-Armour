"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import {
  ActionBadge, Button, Card, EmptyState, ErrorState, Field, LoadingBlock, Spinner, TypeChip, inputClass,
} from "@/components/ui";
import { ACTIONS, PROVIDERS, api, type Action, type EventFilters, type Provider } from "@/lib/api";
import {
  ACTION_STYLE, PROVIDER_LABEL, formatMs, formatTime, isoToLocalInput, localInputToIso,
} from "@/lib/format";
import { useApi } from "@/lib/useApi";

const PAGE_SIZE = 25;

function filtersFrom(params: URLSearchParams): EventFilters {
  const action = params.get("action");
  const provider = params.get("provider");
  return {
    page: Math.max(1, Number(params.get("page")) || 1),
    page_size: PAGE_SIZE,
    action: ACTIONS.includes(action as Action) ? (action as Action) : undefined,
    provider: PROVIDERS.includes(provider as Provider) ? (provider as Provider) : undefined,
    type: params.get("type") || undefined,
    from: params.get("from") || undefined,
    to: params.get("to") || undefined,
  };
}

export function EventsView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const filters = filtersFrom(params);

  const { data, error, loading, reload } = useApi(`events:${params.toString()}`, () => api.events(filters));
  const types = useApi("policy-types", () => api.policies());

  /** Filters live in the URL: shareable, bookmarkable, back-button friendly. */
  function update(changes: Record<string, string | undefined>, resetPage = true) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    if (resetPage) next.delete("page");
    router.replace(`${pathname}${next.size ? `?${next}` : ""}`, { scroll: false });
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const hasFilters = ["action", "type", "provider", "from", "to"].some((k) => params.has(k));

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
          <Field label="Action">
            <select className={inputClass} value={filters.action ?? ""}
              onChange={(e) => update({ action: e.target.value })}>
              <option value="">All actions</option>
              {ACTIONS.map((a) => <option key={a} value={a}>{ACTION_STYLE[a].label}</option>)}
            </select>
          </Field>
          <Field label="Finding type">
            <select className={inputClass} value={filters.type ?? ""}
              onChange={(e) => update({ type: e.target.value })}>
              <option value="">All types</option>
              {(types.data ?? []).map((p) => <option key={p.type} value={p.type}>{p.type}</option>)}
            </select>
          </Field>
          <Field label="Provider">
            <select className={inputClass} value={filters.provider ?? ""}
              onChange={(e) => update({ provider: e.target.value })}>
              <option value="">All providers</option>
              {PROVIDERS.map((p) => <option key={p} value={p}>{PROVIDER_LABEL[p]}</option>)}
            </select>
          </Field>
          <Field label="From">
            <input type="datetime-local" className={inputClass} value={isoToLocalInput(filters.from ?? null)}
              onChange={(e) => update({ from: localInputToIso(e.target.value) })} />
          </Field>
          <Field label="To">
            <input type="datetime-local" className={inputClass} value={isoToLocalInput(filters.to ?? null)}
              onChange={(e) => update({ to: localInputToIso(e.target.value) })} />
          </Field>
          <div className="flex items-end gap-2 pb-1">
            <Button variant="ghost" disabled={!hasFilters}
              onClick={() => update({ action: undefined, type: undefined, provider: undefined, from: undefined, to: undefined })}>
              Clear
            </Button>
            {loading && data && <Spinner />}
          </div>
        </div>
      </Card>

      <Card>
        {error && !data ? (
          <ErrorState message={error.message} onRetry={reload} />
        ) : !data ? (
          <LoadingBlock />
        ) : data.items.length === 0 ? (
          <EmptyState title={hasFilters ? "No events match these filters" : "No events yet"}>
            {hasFilters ? "Try widening the date range or clearing a filter."
              : "Events appear here once traffic flows through the proxy."}
          </EmptyState>
        ) : (
          <>
            <div className="-mx-[18px] -mt-[18px] overflow-x-auto">
              <table className="w-full min-w-[860px] text-left text-sm">
                <thead className="text-[12.5px] text-subtle">
                  <tr>
                    <th scope="col" className="px-[18px] py-3 font-medium">Time</th>
                    <th scope="col" className="px-[18px] py-3 font-medium">Action</th>
                    <th scope="col" className="px-[18px] py-3 font-medium">Provider</th>
                    <th scope="col" className="px-[18px] py-3 font-medium">Findings</th>
                    <th scope="col" className="px-[18px] py-3 font-medium">Tokens</th>
                    <th scope="col" className="px-[18px] py-3 font-medium">Status</th>
                    <th scope="col" className="px-[18px] py-3 text-right font-medium">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-edge/60">
                  {data.items.map((e) => (
                    <tr key={e.id} onClick={() => router.push(`/events/${e.id}`)}
                      className="cursor-pointer transition-colors hover:bg-raised/70">
                      <td className="whitespace-nowrap px-[18px] py-3">
                        <Link href={`/events/${e.id}`} onClick={(ev) => ev.stopPropagation()}
                          className="text-fg hover:text-accent focus:outline-none focus-visible:underline">
                          {formatTime(e.ts, true)}
                        </Link>
                      </td>
                      <td className="px-[18px] py-3"><ActionBadge action={e.action} /></td>
                      <td className="px-[18px] py-3">
                        <span className="text-fg">{PROVIDER_LABEL[e.provider]}</span>
                        <span className="block max-w-[220px] truncate font-mono text-[11px] text-subtle">{e.endpoint}</span>
                      </td>
                      <td className="px-[18px] py-3">
                        <div className="flex flex-wrap gap-1">
                          {e.finding_types.length === 0 && <span className="text-subtle">none</span>}
                          {e.finding_types.slice(0, 3).map((t) => <TypeChip key={t} type={t} />)}
                          {e.finding_types.length > 3 && <span className="text-xs text-subtle">+{e.finding_types.length - 3}</span>}
                        </div>
                      </td>
                      <td className="whitespace-nowrap px-[18px] py-3 tabular-nums text-fg">
                        {e.tokens_issued ? `${e.tokens_restored}/${e.tokens_issued} restored` : <span className="text-subtle">—</span>}
                        {e.leak_flag && <span className="ml-2 rounded-full bg-elevated px-2 py-0.5 text-xs font-semibold text-danger">leak</span>}
                      </td>
                      <td className="px-[18px] py-3 tabular-nums text-muted">{e.status_code ?? "error"}</td>
                      <td className="whitespace-nowrap px-[18px] py-3 text-right tabular-nums text-muted">{formatMs(e.latency_ms_total)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <nav aria-label="Pagination" className="mt-4 flex flex-wrap items-center justify-between gap-3 text-[13px] text-muted">
              <span>
                {((data.page - 1) * PAGE_SIZE + 1).toLocaleString()}–{Math.min(data.page * PAGE_SIZE, data.total).toLocaleString()} of {data.total.toLocaleString()}
              </span>
              <div className="flex items-center gap-2">
                <Button variant="secondary" disabled={data.page <= 1}
                  onClick={() => update({ page: String(data.page - 1) }, false)}>Previous</Button>
                <span className="tabular-nums">Page {data.page} / {totalPages}</span>
                <Button variant="secondary" disabled={data.page >= totalPages}
                  onClick={() => update({ page: String(data.page + 1) }, false)}>Next</Button>
              </div>
            </nav>
          </>
        )}
      </Card>
    </div>
  );
}

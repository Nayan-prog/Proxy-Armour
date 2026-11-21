"use client";

import { useState } from "react";

import {
  ActionBadge, Banner, Button, Card, ErrorState, LoadingBlock, PageHeader, SeverityBadge, Spinner, cx, inputClass,
} from "@/components/ui";
import { ACTIONS, ApiError, api, type Action, type Policy } from "@/lib/api";
import { ACTION_STYLE, formatTime } from "@/lib/format";
import { useApi } from "@/lib/useApi";

const IDENTITY_TYPES = new Set(["EMAIL", "PHONE_IN", "AADHAAR", "PAN", "CREDIT_CARD"]);

export default function PoliciesPage() {
  const { data, error, loading, reload, setData } = useApi("policies", () => api.policies());
  const [edits, setEdits] = useState<Record<string, Action>>({});
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(null);

  const changed = data?.filter((p) => edits[p.type] && edits[p.type] !== p.action) ?? [];

  async function save() {
    setSaving(true);
    setNotice(null);
    try {
      const saved = await api.savePolicies(changed.map((p) => ({ type: p.type, action: edits[p.type] })));
      setData(saved);
      setEdits({});
      setNotice({ kind: "ok", text: `Saved ${changed.length} change${changed.length === 1 ? "" : "s"}. The proxy applies them within about 10 seconds.` });
    } catch (e) {
      const message = e instanceof ApiError && e.status === 503
        ? "Policies are read-only: the admin API has no database configured."
        : e instanceof Error ? e.message : "Save failed.";
      setNotice({ kind: "error", text: message });
    } finally {
      setSaving(false);
    }
  }

  const groups: [string, Policy[]][] = data ? [
    ["Personal & financial identifiers", data.filter((p) => IDENTITY_TYPES.has(p.type))],
    ["Secrets & credentials", data.filter((p) => !IDENTITY_TYPES.has(p.type))],
  ] : [];

  return (
    <>
      <PageHeader
        title="Policies"
        description={<>What the proxy does with each finding type. A request is blocked if any finding is <em>block</em>,
          otherwise tokenized if any is <em>tokenize</em>.</>}
        actions={
          <>
            {loading && data && <Spinner />}
            <Button variant="ghost" disabled={!changed.length || saving} onClick={() => setEdits({})}>Discard</Button>
            <Button disabled={!changed.length || saving} onClick={save}>
              {saving && <Spinner className="border-white/30 border-t-white" />}
              Save{changed.length ? ` ${changed.length} change${changed.length === 1 ? "" : "s"}` : ""}
            </Button>
          </>
        }
      />

      {notice && (
        <div className="mb-4">
          <Banner tone={notice.kind === "ok" ? "ok" : "danger"}>{notice.text}</Banner>
        </div>
      )}

      {error && !data ? <ErrorState message={error.message} onRetry={reload} /> : !data ? <LoadingBlock /> : (
        <div className="flex flex-col gap-3">
          {groups.map(([title, rows]) => (
            <Card key={title} title={title} subtitle={`${rows.length} types`}>
              <div className="-mx-[18px] -mb-[18px] overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <thead className="text-[12.5px] text-subtle">
                    <tr>
                      <th scope="col" className="px-[18px] py-3 font-medium">Finding type</th>
                      <th scope="col" className="px-[18px] py-3 font-medium">Severity</th>
                      <th scope="col" className="px-[18px] py-3 font-medium">Action</th>
                      <th scope="col" className="px-[18px] py-3 font-medium">Last changed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-edge/60">
                    {rows.map((p) => {
                      const value = edits[p.type] ?? p.action;
                      const dirty = value !== p.action;
                      return (
                        <tr key={p.type} className={cx(dirty && "bg-brand/[0.06]")}>
                          <td className="px-[18px] py-2.5 font-mono text-xs text-fg">
                            {p.type}
                            {dirty && <span className="ml-2 rounded-full bg-elevated px-2 py-0.5 font-sans text-[11px] font-semibold text-accent">unsaved</span>}
                          </td>
                          <td className="px-[18px] py-2.5"><SeverityBadge level={p.severity} /></td>
                          <td className="px-[18px] py-2.5">
                            <div className="flex items-center gap-3">
                              <select aria-label={`Action for ${p.type}`} className={cx(inputClass, "w-36")} value={value}
                                onChange={(e) => setEdits({ ...edits, [p.type]: e.target.value as Action })}>
                                {ACTIONS.map((a) => <option key={a} value={a}>{ACTION_STYLE[a].label}</option>)}
                              </select>
                              <ActionBadge action={value} />
                            </div>
                          </td>
                          <td className="px-[18px] py-2.5 text-xs text-subtle">
                            {p.updated_by}{p.updated_at && ` · ${formatTime(p.updated_at)}`}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Card>
          ))}
          <p className="px-1 text-[12.5px] leading-relaxed text-subtle">
            <strong className="text-fg">allow</strong> sends the value to the LLM unchanged ·{" "}
            <strong className="text-fg">tokenize</strong> replaces it with a placeholder and restores it in the answer ·{" "}
            <strong className="text-fg">block</strong> stops the whole request (HTTP 403).
          </p>
        </div>
      )}
    </>
  );
}

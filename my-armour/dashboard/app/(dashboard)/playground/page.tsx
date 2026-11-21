"use client";

import { useState } from "react";

import {
  ActionBadge, Button, Card, EmptyState, ErrorState, ICONS, Icon, PageHeader, SeverityBadge, Spinner, TypeChip, cx,
} from "@/components/ui";
import { api, type Action, type PlaygroundResult } from "@/lib/api";
import { segmentText, splitPlaceholders } from "@/lib/highlight";

const SAMPLE = `Hi! Can you review this before I deploy? Ping rahul@acme.com or +91 98765 43210 if it breaks.

\`\`\`python
import psycopg

DB_URL = "postgresql://admin:Sup3rS3cret@db.internal:5432/payments"
STRIPE_KEY = "sk_${"test"}_4eC39HqLyjWDarjtT1zdp7dc"

def connect():
    return psycopg.connect(DB_URL, password="hunter2-prod")
\`\`\`

Also, does this look right? Customer PAN on file: ABCDE1234F`;

const MARK: Record<Action, string> = {
  allow: "bg-white/10 text-fg ring-white/25",
  tokenize: "bg-brand/25 text-fg ring-accent/50",
  block: "bg-danger/25 text-fg ring-danger/60",
};

export default function PlaygroundPage() {
  const [text, setText] = useState("");
  const [scanned, setScanned] = useState<{ text: string; result: PlaygroundResult } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);

  async function scan() {
    if (!text.trim()) return;
    setScanning(true);
    setError(null);
    try {
      setScanned({ text, result: await api.playgroundScan(text) });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed.");
    } finally {
      setScanning(false);
    }
  }

  const result = scanned?.result;

  return (
    <>
      <PageHeader
        title="Playground"
        description="Paste a prompt to see what Proxy Armour detects and exactly what the LLM would receive. Nothing is stored."
      />

      <div className="grid gap-3 xl:grid-cols-2">
        <Card title="Prompt" actions={
          <Button variant="secondary" onClick={() => { setText(SAMPLE); setScanned(null); }}>
            Load demo sample
          </Button>}>
          <textarea
            aria-label="Prompt to scan"
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) scan(); }}
            placeholder="Paste text or code, e.g. an email, an API key or a config file…"
            spellCheck={false}
            className="h-80 w-full resize-y rounded-xl bg-raised p-3.5 font-mono text-[13px]
                       leading-relaxed text-fg placeholder:text-subtle focus:outline-none focus:ring-2 focus:ring-accent/70"
          />
          <div className="mt-3 flex items-center justify-between gap-3">
            <span className="text-xs text-subtle">{text.length.toLocaleString()} / 100,000 characters · Ctrl+Enter to scan</span>
            <Button onClick={scan} disabled={scanning || !text.trim() || text.length > 100_000}>
              {scanning && <Spinner className="border-white/30 border-t-white" />}
              {scanning ? "Scanning…" : "Scan"}
            </Button>
          </div>
          {error && <div className="mt-3"><ErrorState message={error} /></div>}
        </Card>

        <Card title="Result" actions={result && (
          <span className="flex items-center gap-2 text-xs text-muted">
            Request would be <ActionBadge action={result.action} /> · risk <SeverityBadge level={result.risk} />
          </span>)}>
          {!result ? (
            <EmptyState title="No scan yet">Results appear here: highlighted findings and the tokenized prompt.</EmptyState>
          ) : (
            <div className="flex flex-col gap-5">
              {result.action === "block" && (
                <div className="flex items-start gap-3 rounded-2xl bg-raised px-4 py-3 text-sm text-fg" role="status">
                  <Icon d={ICONS.block} className="mt-0.5 h-[18px] w-[18px] text-danger" />
                  <p>This prompt would be <strong className="text-danger">blocked</strong> (HTTP 403) - it contains a type
                    whose policy is block. The preview below shows what tokenization alone would do.</p>
                </div>
              )}
              <section>
                <h3 className="mb-2 font-display text-[13px] font-bold text-muted">
                  Detected in your prompt ({result.findings.length})
                </h3>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-raised p-3.5
                                font-mono text-[13px] leading-relaxed text-fg">
                  {segmentText(scanned.text, result.findings).map((segment, i) =>
                    segment.findings ? (
                      <mark key={i} title={segment.findings.map((f) => `${f.type} · ${f.detector} · ${f.action}`).join("\n")}
                        className={cx("rounded px-0.5 ring-1 ring-inset", MARK[segment.action!])}>
                        {segment.text}
                      </mark>
                    ) : <span key={i}>{segment.text}</span>)}
                </pre>
              </section>

              <section>
                <h3 className="mb-2 font-display text-[13px] font-bold text-muted">
                  Sent to the LLM
                </h3>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-raised p-3.5
                                font-mono text-[13px] leading-relaxed text-fg ring-1 ring-inset ring-brand/40">
                  {splitPlaceholders(result.tokenized_preview).map((part, i) =>
                    part.placeholder ? (
                      <span key={i} className="rounded bg-brand/20 px-0.5 text-accent">{part.text}</span>
                    ) : <span key={i}>{part.text}</span>)}
                </pre>
                <p className="mt-1.5 text-xs text-subtle">
                  Placeholders are random - the LLM learns only the kind of value. Its answer is restored locally.
                </p>
              </section>

              {result.findings.length > 0 && (
                <section className="-mx-[18px] -mb-[18px] overflow-x-auto">
                  <table className="w-full min-w-[560px] text-left text-sm">
                    <thead className="text-[12.5px] text-subtle">
                      <tr>
                        <th scope="col" className="px-[18px] py-2.5 font-medium">Type</th>
                        <th scope="col" className="px-[18px] py-2.5 font-medium">Detector</th>
                        <th scope="col" className="px-[18px] py-2.5 font-medium">Severity</th>
                        <th scope="col" className="px-[18px] py-2.5 font-medium">Action</th>
                        <th scope="col" className="px-[18px] py-2.5 text-right font-medium">Position</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-edge/60">
                      {result.findings.map((f, i) => (
                        <tr key={i}>
                          <td className="px-[18px] py-2.5"><TypeChip type={f.type} /></td>
                          <td className="px-[18px] py-2.5 font-mono text-xs text-muted">{f.detector}</td>
                          <td className="px-[18px] py-2.5"><SeverityBadge level={f.severity} /></td>
                          <td className="px-[18px] py-2.5"><ActionBadge action={f.action} /></td>
                          <td className="whitespace-nowrap px-[18px] py-2.5 text-right tabular-nums text-xs text-subtle">{f.start}–{f.end}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </section>
              )}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}

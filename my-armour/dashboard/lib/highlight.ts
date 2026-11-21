import type { Action, PlaygroundFinding } from "./api";

export interface Segment {
  text: string;
  /** null for plain text; otherwise the findings covering this span */
  findings: PlaygroundFinding[] | null;
  action?: Action; // strictest action among the findings
}

const STRICTNESS: Record<Action, number> = { allow: 0, tokenize: 1, block: 2 };

/**
 * Split text into plain and highlighted segments. Overlapping findings (a phone
 * number inside an email, an email inside a DB URL) become ONE highlighted span
 * covering their union, coloured by the strictest action.
 */
export function segmentText(text: string, findings: PlaygroundFinding[]): Segment[] {
  const groups: { start: number; end: number; members: PlaygroundFinding[] }[] = [];
  for (const f of [...findings].sort((a, b) => a.start - b.start)) {
    const last = groups[groups.length - 1];
    if (last && f.start < last.end) {
      last.end = Math.max(last.end, f.end);
      last.members.push(f);
    } else {
      groups.push({ start: f.start, end: f.end, members: [f] });
    }
  }

  const segments: Segment[] = [];
  let cursor = 0;
  for (const g of groups) {
    if (g.start > cursor) segments.push({ text: text.slice(cursor, g.start), findings: null });
    const action = g.members.reduce<Action>(
      (worst, m) => (STRICTNESS[m.action] > STRICTNESS[worst] ? m.action : worst), "allow");
    segments.push({ text: text.slice(g.start, g.end), findings: g.members, action });
    cursor = g.end;
  }
  if (cursor < text.length) segments.push({ text: text.slice(cursor), findings: null });
  return segments;
}

/** Placeholder pattern issued by the proxy: PA_<TYPE>_<8 uppercase hex>. */
export const PLACEHOLDER = /PA_[A-Z][A-Z0-9_]*?_[0-9A-F]{8}/g;

export function splitPlaceholders(text: string): { text: string; placeholder: boolean }[] {
  const parts: { text: string; placeholder: boolean }[] = [];
  let cursor = 0;
  for (const match of text.matchAll(PLACEHOLDER)) {
    const index = match.index ?? 0;
    if (index > cursor) parts.push({ text: text.slice(cursor, index), placeholder: false });
    parts.push({ text: match[0], placeholder: true });
    cursor = index + match[0].length;
  }
  if (cursor < text.length) parts.push({ text: text.slice(cursor), placeholder: false });
  return parts;
}

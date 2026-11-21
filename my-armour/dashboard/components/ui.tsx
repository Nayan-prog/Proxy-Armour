import type { ReactNode } from "react";

import type { Action, Risk, Severity } from "@/lib/api";
import { ACTION_STYLE, SEVERITY_STYLE } from "@/lib/format";

export function cx(...classes: (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

/* ------------------------------------------------------------------ icons */

/** 24-px stroke icons in the Scaleagee style (1.75 stroke, round caps). */
export const ICONS = {
  overview: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  events: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  live: "M5 12a7 7 0 0 1 14 0M8 12a4 4 0 0 1 8 0M12 12h.01M5 19h14",
  shield: "M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z",
  code: "M8 9l-3 3 3 3M16 9l3 3-3 3M13 6l-2 12",
  requests: "M21 3L10 14M21 3l-7 18-4-8-8-4z",
  block: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM5.6 5.6l12.8 12.8",
  token: "M7 8h10M7 12h10M7 16h6M4 4h16v16H4z",
  check: "M5 12l5 5L20 7",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  back: "M19 12H5M11 6l-6 6 6 6",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h11",
  alert: "M12 4l9 16H3zM12 10v4M12 17h.01",
  chevron: "M9 6l6 6-6 6",
} as const;

export function Icon({ d, className = "h-5 w-5", strokeWidth = 1.75 }: {
  d: string;
  className?: string;
  strokeWidth?: number;
}) {
  return (
    <svg viewBox="0 0 24 24" className={cx("shrink-0", className)} fill="none" stroke="currentColor"
      strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  );
}

/* ------------------------------------------------------------------ layout */

export function PageHeader({ title, description, actions }: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h1 className="text-[30px] font-bold leading-tight tracking-[-0.4px] text-fg">{title}</h1>
        {description && <p className="mt-1.5 max-w-2xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Section label above a group of cards - Comfortaa, quiet (Scaleagee "Performance"). */
export function SectionTitle({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-3">
      <h2 className="font-display text-[15px] font-bold text-muted">{children}</h2>
      {actions}
    </div>
  );
}

export function Card({ title, subtitle, actions, children, className, flush }: {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  /** no inner padding below the header - for edge-to-edge tables */
  flush?: boolean;
}) {
  return (
    <section className={cx("min-w-0 rounded-[18px] bg-surface", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 px-[18px] pt-[18px]">
          <div>
            {title && <h3 className="text-[15px] font-bold text-fg">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-[12.5px] text-subtle">{subtitle}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className={flush ? "pt-3" : "p-[18px]"}>{children}</div>
    </section>
  );
}

export function StatCard({ label, value, hint, icon, pill, loading }: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: string;
  /** small chip next to the value, e.g. a share */
  pill?: ReactNode;
  loading?: boolean;
}) {
  return (
    <div className="min-w-0 rounded-2xl bg-surface p-4">
      <p className="flex items-center gap-1.5 text-[13px] text-muted">
        {icon && <Icon d={icon} className="h-3.5 w-3.5" />}
        {label}
      </p>
      {loading ? (
        <div className="mt-2 h-8 w-24 animate-pulse rounded-lg bg-raised" />
      ) : (
        <div className="mt-1.5 flex flex-wrap items-center gap-2">
          <span className="text-[26px] font-bold leading-tight tracking-[-0.3px] tabular-nums text-fg">{value}</span>
          {pill && (
            <span className="rounded-[10px] bg-elevated px-[7px] py-0.5 text-xs font-semibold tabular-nums text-fg">{pill}</span>
          )}
        </div>
      )}
      {hint && <p className="mt-1 text-[12.5px] text-subtle">{hint}</p>}
    </div>
  );
}

/** Label / value line inside a card (Scaleagee "Subscribers gained  +420"). */
export function MetricRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 py-1.5">
      <span className="text-[13.5px] text-muted">{label}</span>
      <span className="text-right text-sm font-bold tabular-nums text-fg">{children}</span>
    </div>
  );
}

/* ------------------------------------------------------------------ badges */

const PILL = "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full bg-elevated px-2.5 py-0.5 text-xs font-semibold";

export function ActionBadge({ action }: { action: Action }) {
  const style = ACTION_STYLE[action];
  return (
    <span className={cx(PILL, style.badge)}>
      <span className={cx("h-1.5 w-1.5 rounded-full", style.dot)} />
      {style.label}
    </span>
  );
}

export function SeverityBadge({ level }: { level: Severity | Risk }) {
  return <span className={cx(PILL, SEVERITY_STYLE[level], "capitalize")}>{level}</span>;
}

export function TypeChip({ type }: { type: string }) {
  return (
    <span className="inline-flex rounded-md bg-elevated px-1.5 py-0.5 font-mono text-[11px] text-muted">
      {type}
    </span>
  );
}

/** Inline alert banner: danger for leaks/blocks, ok/info for confirmations. */
export function Banner({ tone = "danger", children }: { tone?: "danger" | "ok" | "info"; children: ReactNode }) {
  const color = { danger: "text-danger", ok: "text-ok", info: "text-accent" }[tone];
  return (
    <div role={tone === "danger" ? "alert" : "status"}
      className="flex items-start gap-3 rounded-2xl bg-surface px-4 py-3 text-sm text-fg">
      <Icon d={tone === "danger" ? ICONS.alert : ICONS.check} className={cx("mt-0.5 h-[18px] w-[18px]", color)} />
      <div className="min-w-0">{children}</div>
    </div>
  );
}

/* ------------------------------------------------------------------ states */

export function Spinner({ className }: { className?: string }) {
  return (
    <span
      role="status"
      aria-label="Loading"
      className={cx("inline-block h-4 w-4 animate-spin rounded-full border-2 border-elevated border-t-accent", className)}
    />
  );
}

export function LoadingBlock({ label = "Loading…", className }: { label?: string; className?: string }) {
  return (
    <div className={cx("flex items-center justify-center gap-2 py-12 text-sm text-muted", className)}>
      <Spinner /> {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center gap-3 rounded-[18px] bg-surface px-4 py-10 text-center">
      <Icon d={ICONS.alert} className="h-6 w-6 text-danger" />
      <p className="max-w-md text-sm text-fg">{message}</p>
      {onRetry && <Button variant="secondary" onClick={onRetry}>Try again</Button>}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-1.5 px-4 py-12 text-center">
      <p className="text-[15px] font-semibold text-fg">{title}</p>
      {children && <p className="max-w-md text-sm text-muted">{children}</p>}
    </div>
  );
}

/* ------------------------------------------------------------------ controls */

export const focusRing =
  "focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-canvas";

export function Button({ variant = "primary", className, ...props }:
  React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger" | "light" }) {
  const styles = {
    primary: "bg-brand text-white hover:bg-[#5592f7] disabled:bg-brand/40 disabled:text-white/60",
    secondary: "bg-raised text-fg hover:bg-elevated disabled:opacity-50",
    ghost: "text-muted hover:bg-raised hover:text-fg disabled:opacity-40",
    danger: "bg-danger text-canvas hover:bg-[#fa8c8c] disabled:opacity-50",
    light: "bg-fg text-canvas hover:bg-white disabled:opacity-60",
  }[variant];
  return (
    <button
      type="button"
      {...props}
      className={cx(
        "inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-full px-4 text-[13px] font-semibold",
        "transition-colors disabled:cursor-not-allowed", focusRing, styles, className)}
    />
  );
}

export const inputClass =
  "h-11 rounded-xl bg-raised px-3.5 text-sm text-fg placeholder:text-subtle " +
  "focus:outline-none focus:ring-2 focus:ring-accent/70";

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex min-w-0 flex-col gap-1.5 text-[13px] font-medium text-muted">
      {label}
      {children}
    </label>
  );
}

/** Text tabs (Scaleagee "Today · Last 7 days · Last 28 days"): selected = accent + bold. */
export function Segmented<T extends string>({ value, options, onChange, label }: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
  label: string;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-wrap items-center gap-1">
      {options.map((o) => {
        const selected = value === o.value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={selected}
            onClick={() => onChange(o.value)}
            className={cx(
              "h-9 rounded-full px-3 text-[14.5px] transition-colors", focusRing,
              selected ? "font-bold text-accent" : "font-medium text-muted hover:text-fg")}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState, type FormEvent } from "react";

import { Button, Field, Spinner, cx, inputClass } from "@/components/ui";
import { ApiError, api } from "@/lib/api";
import { safeNextPath } from "@/lib/session";

function messageFor(error: unknown): string {
  if (!(error instanceof ApiError)) return "Sign-in failed.";
  if (error.status === 401) return "Invalid username or password.";
  if (error.status === 429) {
    const minutes = error.retryAfter ? Math.ceil(error.retryAfter / 60) : undefined;
    return `Too many failed attempts. Try again${minutes ? ` in ${minutes} min` : " later"}.`;
  }
  if (error.status === 503) return `Admin login is not configured on the server: ${error.message}`;
  return error.message;
}

export function LoginForm() {
  const router = useRouter();
  const next = safeNextPath(useSearchParams().get("next"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.login(username, password);
      router.replace(next);
      router.refresh();
    } catch (e) {
      setError(messageFor(e));
      setPassword("");
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-5">
      <Field label="Username">
        <input className={cx(inputClass, "h-12 text-[15px]")} autoComplete="username" required autoFocus
          value={username} onChange={(e) => setUsername(e.target.value)} />
      </Field>
      <Field label="Password">
        <input className={cx(inputClass, "h-12 text-[15px]")} type="password" autoComplete="current-password" required
          value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      {error && (
        <p role="alert" className="rounded-2xl bg-surface px-4 py-3 text-sm text-danger">
          {error}
        </p>
      )}
      <Button type="submit" variant="light" disabled={submitting} className="mt-6 h-14 text-base">
        {submitting && <Spinner className="border-canvas/30 border-t-canvas" />}
        {submitting ? "Signing in…" : "Sign in"}
      </Button>
      <p className="text-center text-[13px] text-subtle">Session lasts 8 hours.</p>
    </form>
  );
}

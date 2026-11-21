/**
 * Server-side helpers for the route handlers (the BFF). The browser never talks
 * to the admin API directly: route handlers read the JWT from the httpOnly
 * cookie and call FastAPI with an Authorization header.
 */
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { SESSION_COOKIE } from "./session";

/** Admin API base URL. NEXT_PUBLIC_ values are inlined at build time. */
export const API_URL = (process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000").replace(/\/+$/, "");

export async function sessionToken(): Promise<string | undefined> {
  return (await cookies()).get(SESSION_COOKIE)?.value;
}

/**
 * CSRF defence for state-changing requests: the Origin header must match the
 * host this dashboard is served from (the cookie is also SameSite=Strict).
 */
export function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  if (!origin || !host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

export function jsonError(status: number, detail: string, headers?: HeadersInit): NextResponse {
  return NextResponse.json({ detail }, { status, headers });
}

export function clearSession(response: NextResponse): NextResponse {
  response.cookies.set(SESSION_COOKIE, "", { httpOnly: true, sameSite: "strict", path: "/", maxAge: 0 });
  return response;
}

export async function backendFetch(path: string, init: RequestInit = {}, token?: string): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch(`${API_URL}${path}`, { ...init, headers, cache: "no-store" });
}

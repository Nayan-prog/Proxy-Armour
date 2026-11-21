import { NextResponse } from "next/server";

import { backendFetch, isSameOrigin, jsonError } from "@/lib/backend";
import { SESSION_COOKIE } from "@/lib/session";

/** POST {username, password} -> admin API /api/login -> JWT stored in an httpOnly cookie. */
export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError(403, "cross-origin request refused");

  const body = (await request.json().catch(() => null)) as { username?: unknown; password?: unknown } | null;
  if (typeof body?.username !== "string" || typeof body?.password !== "string") {
    return jsonError(400, "username and password are required");
  }

  let upstream: Response;
  try {
    upstream = await backendFetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: body.username, password: body.password }),
    });
  } catch {
    return jsonError(502, "admin API unreachable - is `python -m app.main` running?");
  }

  const data = (await upstream.json().catch(() => ({}))) as {
    access_token?: string;
    expires_at?: string;
    detail?: string;
  };
  if (!upstream.ok || !data.access_token || !data.expires_at) {
    const retryAfter = upstream.headers.get("retry-after");
    return jsonError(upstream.ok ? 502 : upstream.status, data.detail ?? "login failed",
      retryAfter ? { "Retry-After": retryAfter } : undefined);
  }

  const response = NextResponse.json({ ok: true, expires_at: data.expires_at });
  response.cookies.set(SESSION_COOKIE, data.access_token, {
    httpOnly: true,                                  // not readable by page JavaScript (XSS)
    sameSite: "strict",                              // not sent on cross-site requests (CSRF)
    secure: process.env.NODE_ENV === "production",   // HTTPS only in production
    path: "/",
    expires: new Date(data.expires_at),              // same 8 h lifetime as the JWT
  });
  return response;
}

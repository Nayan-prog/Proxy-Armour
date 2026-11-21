import { NextResponse } from "next/server";

import { backendFetch, clearSession, isSameOrigin, jsonError, sessionToken } from "@/lib/backend";

/**
 * BFF: /api/admin/<path> -> admin API /api/<path> with the session's bearer token.
 * Only the dashboard's own endpoints are reachable through it.
 */
const ALLOWED_ROOTS = new Set(["stats", "events", "policies", "playground"]);
const SEGMENT = /^[A-Za-z0-9_-]+$/;

type Context = { params: Promise<{ path: string[] }> };

async function forward(request: Request, { params }: Context): Promise<NextResponse> {
  const { path } = await params;
  if (!ALLOWED_ROOTS.has(path[0]) || !path.every((segment) => SEGMENT.test(segment))) {
    return jsonError(404, "not found");
  }
  if (request.method !== "GET" && !isSameOrigin(request)) {
    return jsonError(403, "cross-origin request refused");
  }
  const token = await sessionToken();
  if (!token) return jsonError(401, "not signed in");

  const { search } = new URL(request.url);
  let upstream: Response;
  try {
    upstream = await backendFetch(`/api/${path.join("/")}${search}`, {
      method: request.method,
      headers: request.method === "GET" ? undefined : { "Content-Type": "application/json" },
      body: request.method === "GET" ? undefined : await request.text(),
    }, token);
  } catch {
    return jsonError(502, "admin API unreachable");
  }

  const body = await upstream.text();
  const response = new NextResponse(body, {
    status: upstream.status,
    headers: { "Content-Type": upstream.headers.get("content-type") ?? "application/json" },
  });
  // the API rejected the token (expired, secret rotated): drop the cookie too
  return upstream.status === 401 ? clearSession(response) : response;
}

export const GET = forward;
export const PUT = forward;
export const POST = forward;

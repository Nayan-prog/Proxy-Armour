import { backendFetch, jsonError, sessionToken } from "@/lib/backend";

/**
 * Server-sent events for the /live page. The browser opens a plain
 * EventSource("/api/live") - same origin, so the httpOnly cookie is sent - and
 * this handler streams the admin API's /api/live through, adding the bearer
 * header. The token never appears in a URL or in browser JavaScript.
 */
export async function GET(request: Request) {
  const token = await sessionToken();
  if (!token) return jsonError(401, "not signed in");

  let upstream: Response;
  try {
    // request.signal: when the browser disconnects, the upstream stream is closed too
    upstream = await backendFetch("/api/live", { signal: request.signal }, token);
  } catch {
    return jsonError(502, "admin API unreachable");
  }
  if (!upstream.ok || !upstream.body) {
    return jsonError(upstream.status === 200 ? 502 : upstream.status, "live feed unavailable");
  }
  return new Response(upstream.body, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}

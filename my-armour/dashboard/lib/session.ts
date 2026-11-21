/**
 * Session constants and helpers shared by proxy.ts and the route handlers.
 * Pure functions only - no Node or browser APIs beyond atob.
 */

/** httpOnly cookie that holds the admin JWT. Browser JavaScript can never read it. */
export const SESSION_COOKIE = "armour_session";

/**
 * Expiry (ms since epoch) from a JWT's payload, WITHOUT verifying the signature.
 * Only used to skip pointless round trips with an obviously expired token -
 * the admin API verifies every token properly.
 */
export function tokenExpiry(token: string): number | null {
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const exp = (JSON.parse(json) as { exp?: unknown }).exp;
    return typeof exp === "number" ? exp * 1000 : null;
  } catch {
    return null;
  }
}

export function isUsableToken(token: string | undefined): token is string {
  if (!token) return false;
  const expiry = tokenExpiry(token);
  return expiry !== null && expiry > Date.now();
}

/** Only allow same-site relative redirects after login (no open redirect). */
export function safeNextPath(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return "/";
  return next;
}

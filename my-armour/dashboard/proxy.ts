/**
 * Route protection (Next.js 16 renamed middleware.ts to proxy.ts - same feature).
 *
 * Every page and BFF route needs a session cookie holding a not-yet-expired JWT;
 * otherwise pages redirect to /login?next=... and API routes answer 401.
 * This is a UX gate: the admin API verifies the token's signature on every call.
 */
import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE, isUsableToken } from "@/lib/session";

const PUBLIC_PATHS = new Set(["/login", "/api/auth/login", "/api/auth/logout"]);

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const signedIn = isUsableToken(request.cookies.get(SESSION_COOKIE)?.value);

  if (PUBLIC_PATHS.has(pathname)) {
    // already signed in: skip the login form
    if (pathname === "/login" && signedIn) return NextResponse.redirect(new URL("/", request.url));
    return NextResponse.next();
  }
  if (signedIn) return NextResponse.next();

  if (pathname.startsWith("/api/")) {
    return NextResponse.json({ detail: "not signed in" }, { status: 401 });
  }
  const login = new URL("/login", request.url);
  login.searchParams.set("next", pathname + search);
  return NextResponse.redirect(login);
}

export const config = {
  // everything except Next's own assets and files with an extension (favicon, svgs)
  matcher: ["/((?!_next/static|_next/image|.*\\.[a-zA-Z0-9]+$).*)"],
};

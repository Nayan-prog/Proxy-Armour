import { NextResponse } from "next/server";

import { sessionToken } from "@/lib/backend";
import { isUsableToken, tokenExpiry } from "@/lib/session";

/** Is there a (not yet expired) session cookie? Never returns the token itself. */
export async function GET() {
  const token = await sessionToken();
  if (!isUsableToken(token)) return NextResponse.json({ authenticated: false }, { status: 401 });
  return NextResponse.json({ authenticated: true, expires_at: new Date(tokenExpiry(token)!).toISOString() });
}

import { NextResponse } from "next/server";

import { clearSession, isSameOrigin, jsonError } from "@/lib/backend";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return jsonError(403, "cross-origin request refused");
  return clearSession(NextResponse.json({ ok: true }));
}

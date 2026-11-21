# Proxy Armour dashboard

Next.js 16 (App Router) + TypeScript + Tailwind v4 + Recharts admin console for the
Proxy Armour admin API.

```powershell
copy .env.example .env.local      # NEXT_PUBLIC_API_URL -> the FastAPI service
npm install
npm run dev                       # http://localhost:3000 (sign in with the admin from ../.env)
npm run build; npm start          # production
```

## How it talks to the API (BFF)

The browser only calls this app (same origin). Route handlers forward to the admin
API with the JWT from an httpOnly cookie, so the token never reaches browser
JavaScript and never appears in a URL.

| Route | Purpose |
|---|---|
| `POST /api/auth/login` | `/api/login` on the API, sets the `armour_session` cookie (httpOnly, SameSite=Strict, Secure in production) |
| `POST /api/auth/logout`, `GET /api/auth/session` | clear / check the session (never returns the token) |
| `/api/admin/{stats,events,policies,playground}/...` | forwarded with `Authorization: Bearer`; only these roots |
| `GET /api/live` | SSE stream for `EventSource`, piped from the API's `/api/live` |
| `proxy.ts` | route guard (Next 16's renamed middleware): no session -> `/login?next=...` or 401 |

State-changing routes also require a same-origin `Origin` header (CSRF).

## Pages

`/` overview · `/events` (filters in the URL) · `/events/[id]` · `/live` · `/policies` ·
`/playground` · `/login`. Typed API client: `lib/api.ts`.

The dashboard shows metadata only - the API never stores prompts, values or placeholders.
The playground highlights the text you paste yourself and is never stored.

# Proxy Armour

Capstone project: a **Data Loss Prevention (DLP) gateway** that sits between developer
apps and LLM APIs (OpenAI, Anthropic, Gemini). It inspects every outgoing prompt and
allows, tokenizes, or blocks it before sensitive data leaves the machine. Tokenized
values are swapped for placeholders on the way out and restored locally in the LLM's
answer (incl. streaming), so the provider never sees the real data.

## The one rule that must never be broken

**Original sensitive values must NEVER be written to logs, the database, Redis, the
dashboard, error messages, or test fixtures that get committed.**

- Store and display only *metadata*: detected type (e.g. `AADHAAR`), severity, count,
  offsets/lengths, placeholder token IDs, timestamps, host, action taken.
- Block responses return detected *types* only (see `block()` in `proxy/armour_addon.py`).
- Log lines print placeholders/redacted text, never raw prompts that contained findings.
- The {placeholder: original} map lives **only in process memory** (`TokenVault`, keyed
  by `flow.id`, TTL `tokenization.ttl_seconds`) and in one `StreamRestorer` for the life of
  one response. It is deleted on response (`VAULT.pop`), on upstream error, or by the TTL
  cleanup task - whichever is first. It is never logged, persisted, or put in Redis/DB in
  plaintext; `TokenVault.__repr__` and `RestoreStats` expose counts/types only.
- Placeholders are `PA_<TYPE>_<8 uppercase hex>` from `secrets.token_hex` - random, not
  a hash of the value (a hash would let anyone confirm a guessed value).
- Restoration replaces only *exact placeholders issued for that flow*. Anything else
  PA_-shaped is counted as `unknown` and left untouched.
- `flow.metadata["proxy_armour"]` is the metadata-only record of a flow (host, action,
  types, counts, detectors, scan time, restore stats); `build_event` turns it into the
  audit event.
- The audit log (`events` table) and Redis hold METADATA ONLY. This is enforced by the
  server, not just the proxy: `app/schemas.py EventIn` forbids extra fields and
  pattern-restricts every string (finding types `^[A-Z][A-Z0-9_]*$`, endpoint is a
  path with no `?query` - Gemini sends the API key as `?key=`, host is hostname chars).
  Never loosen those patterns or add a free-text column.
- The playground (`POST /api/playground/scan`) never stores or publishes anything and
  returns offsets + placeholders -> types, not values.
- If a change would make a raw value reachable from any store or log, it is a bug -
  treat it as such in review.

Other security principles in force:
- **Fail closed**: never forward traffic that wasn't successfully scanned.
  - malformed JSON -> 400; non-JSON body (multipart, form, binary) -> 415 (configurable
    4xx/5xx via `proxy.unsupported_body`)
  - scanner unreachable / timeout / non-200 / malformed reply -> 503 (`call_scanner`
    turns every failure into `ScannerError`)
  - any unexpected exception in the addon -> 500 (guard in `request()`); mitmproxy would
    otherwise log the error and forward the request
  - after tokenization the outgoing text is re-scanned; anything still detected that
    is not entirely inside an issued placeholder -> 403
  - restoration is best-effort the other way: if it fails (expired map, compressed
    stream, non-JSON body, bug) the client gets *placeholders*, never an error that
    exposes originals
- Log exception *type names* only, never `str(exception)` - Pydantic validation errors
  include the input values, which can be the secrets.
- No prompt text in logs either: the proxy logs host, action, types and counts only. Every
  hook that can see content is wrapped so a traceback (whose message could hold data) never
  reaches mitmproxy's or uvicorn's log: `request()` (500 + block), `responseheaders()`,
  `StreamRestorer.__call__` (pass-through on error, `restorer.error` = type name), the restore
  path, and the API's `no_tracebacks` middleware (Starlette's own handler re-raises).
- mitmproxy runs with `flow_detail=0` (`run_proxy.py`, docker-compose). Level 1 prints URLs
  (Gemini sends the API key as `?key=`), level 2+ headers (API keys) and bodies (prompts) -
  never raise it on real traffic.
- `tests/test_privacy.py` drives normal traffic plus injected failures (exceptions carrying a
  secret in their message) through every component and searches stdout/stderr, all logging
  records, the DB, Redis keys/hashes/pub-sub, dashboard API responses and the timing log for
  originals and `PA_` placeholders. Keep it green; extend it when adding a sink.
- The only places placeholders are deliberately visible: the admin playground (fresh
  placeholders for text the admin pasted, never stored) and the mock LLM's
  `MOCK_LLM_SHOW_RECEIVED=1` "provider view" (the LLM's side of the wire, demo only).
- Config is validated at startup (`armour_config.py`); an invalid policy stops the service.
- Docker: secrets live in `.env.docker` (git-ignored; generated with random values by
  `stack.py up`, admin hash written by `stack.py seed` in single quotes so compose
  doesn't expand the `$` in bcrypt hashes). `./certs` holds the mitmproxy CA **including
  its private key** - git-ignored; trust only `certs/mitmproxy-ca-cert.pem`. Container
  config = config.yaml + `ARMOUR_CONFIG_OVERLAY` (`docker/config.overlay.yaml`) - put
  only differences there, never a copy of config.yaml.
- Secrets (DB/Redis URLs, admin credentials, JWT and shared secrets) go in `.env`
  (git-ignored; template `.env.example`), loaded by `armour_config.EnvSettings` as
  `SecretStr`. Never in `config.yaml`. Code reads `armour_config.env` at call time.
- Missing secrets disable features instead of weakening them: no JWT_SECRET (or < 32
  chars) / admin credentials -> admin API 503; no EVENTS_SHARED_SECRET -> no events or
  policy sync; no DATABASE_URL -> no audit log; no REDIS_URL -> no live counters.
- Availability: `/scan` never touches the DB or Redis (policy is in memory), so a DB or
  Redis outage can't make the proxy fail closed on all traffic. Event logging and policy
  polling are best-effort background work that never delays or breaks a request.
- Admin auth: bcrypt hash only in .env; HS256 JWT (8 h) with algorithm pinned on decode,
  required exp/iat/sub/iss; dummy bcrypt check for wrong usernames (no timing oracle);
  login throttled per IP; shared secrets compared with `hmac.compare_digest`.
- `/api/live` takes the token from the Authorization header only - tokens in URLs end up
  in access logs. The dashboard satisfies this with a BFF: the browser's EventSource
  hits the dashboard's own `/api/live` route handler (same origin, cookie), which adds
  the bearer header server-side.
- Dashboard (`dashboard/`): the JWT lives only in the `armour_session` httpOnly,
  SameSite=Strict cookie (Secure in production); browser JS never sees it. State-changing
  BFF routes also check the `Origin` header. The BFF forwards only
  `stats|events|policies|playground` under `/api/admin/*`. Never render values: events
  are metadata; the playground shows only the text the admin pasted and placeholders.

## Current architecture (implemented)

```
client --HTTPS via proxy :8080--> mitmproxy + proxy/armour_addon.py --POST /scan--> FastAPI scanner :8000
   ^                                    |  allow / tokenize / block                     (app/)
   |  restored answer                   |  placeholders only
   |                                    v
   +---- restore (JSON or SSE) <--- api.openai.com | api.anthropic.com | generativelanguage.googleapis.com
                                    *.openai.azure.com | api.mistral.ai | api.groq.com
                                    (demo mode: mock_llm on :9000 instead)

proxy --POST /events, GET /internal/policies (X-Armour-Secret)--> FastAPI :8000 --> PostgreSQL (events, policies)
dashboard --Bearer JWT--> /api/*  (login, stats, events, policies, live SSE, playground)  --> Redis (optional:
                                                                            per-minute counters, pub/sub feed)

browser --cookie--> Next.js dashboard :3000 (route handlers = BFF) --Bearer--> FastAPI :8000 /api/*
```

| Path | Role |
|---|---|
| `config.yaml` | All runtime settings: scanner/proxy host+port, scanner timeout, LLM hosts, detectors, per-type policy, tokenization TTL, demo mode |
| `armour_config.py` | Loads `config.yaml` (safe YAML loader), validates with Pydantic, exposes `settings`. Override path with `ARMOUR_CONFIG` env var |
| `app/main.py` | FastAPI scanner: `GET /health`, `POST /scan` -> `{risk, action, findings, sanitized}`; each finding carries its `action` |
| `app/policy.py` | `apply_policy` (finding type -> action + optional severity override, unlisted -> `default_action`), `request_action` (block > tokenize > allow). No DB imports - the proxy uses it too |
| `app/policy_store.py` | `STORE`: live policy in memory = config.yaml overlaid with the `policies` table; `seed()` fills an empty table, `load()` refreshes (startup, after PUT, every `policy_sync.poll_seconds` per worker) |
| `app/models.py` | SQLAlchemy 2.0: `events` (metadata per flow; arrays are TEXT[] on Postgres, JSON on SQLite) and `policies` |
| `app/db.py` | Engine from DATABASE_URL (UTC on Postgres); `get_session` dependency -> 503 if no/unreachable DB |
| `app/schemas.py` | Pydantic API models; `EventIn` is the metadata-only gatekeeper; timestamps always serialised as UTC |
| `app/queries.py` | Event filtering/pagination and `/api/stats` aggregates; the only per-dialect SQL (`= ANY`/`unnest`/`date_trunc` vs `json_each`/`strftime`) |
| `app/auth.py` | bcrypt verify, JWT issue/verify, `require_admin`, `LoginThrottle` |
| `app/live.py` | Optional Redis (`LINK`, 30 s back-off after a failure): per-minute counter hashes `armour:m:<YYYYMMDDHHMM>`, pub/sub channel `armour:events`, `event_stream` (pub/sub or DB polling fallback) |
| `app/api/internal.py` | `POST /events`, `GET /internal/policies` (shared secret) |
| `app/api/admin.py` | `/api/login`, `/api/stats`, `/api/events[/{id}]`, `GET/PUT /api/policies`, `/api/live`, `/api/playground/scan` |
| `app/hash_password.py` | `python -m app.hash_password` -> ADMIN_PASSWORD_HASH line for .env |
| `migrations/`, `alembic.ini` | Alembic; URL from `-x url=...` or DATABASE_URL. The app never creates tables itself |
| `docker-compose.yml` | postgres, redis, scanner (`alembic upgrade head` then uvicorn), proxy (mitmdump, confdir `/certs` = `./certs`, `connection_strategy=lazy`), mock-llm, dashboard; healthchecks + `depends_on: service_healthy`; ports bound to 127.0.0.1; Postgres not published |
| `docker/` | `python.Dockerfile` (one image for scanner/proxy/mock-llm, non-root), `config.overlay.yaml` (container hostnames, demo on), `postgres-init/` (creates `armour_test`) |
| `scripts/stack.py` | Stack CLI (stdlib only): up, down, logs, ps, test (args after `test` go to pytest verbatim), seed, demo. `Makefile` and `scripts/armour.ps1` wrap it |
| `README.md`, `DEMO.md` | User-facing docs: setup, CA trust per OS, client configuration, limitations; 5-minute viva script |
| `scripts/demo.py` | Sends runtime-generated sample secrets in every provider format through the proxy; checks restore/block/allow; exit 1 on failure |
| `app/seed.py` | `python -m app.seed hash` (password on stdin -> bcrypt), `python -m app.seed policies [--reset]` |
| `eval/` | Evaluation harness (synthetic data only). `generate.py` seeded corpus -> `eval/data/` (git-ignored: realistic fake keys); `run_detection.py` (regex / +entropy / +AST / detect-secrets), `run_restoration.py` (+ `mangling_mock.py`), `run_latency.py` (real processes on ports 18000/18080/18081/19000), `report.py` -> `eval/results/RESULTS.md` + CSVs; `run_all.py` runs everything |
| `dashboard/` | Next.js 16 App Router + TS + Tailwind v4 + Recharts admin console (see `dashboard/README.md`). `lib/api.ts` typed client (mirrors `app/schemas.py`); `app/api/**` route handlers = BFF; `proxy.ts` = route guard (Next 16 renamed middleware -> proxy); pages under `app/(dashboard)/`: overview, events, events/[id], live, policies, playground; `app/login` |
| `app/detectors/base.py` | Common interface: `Finding` = `{type, start, end, severity, detector}`, `Detector` protocol (`name`, `detect(text)`), `RISK_ORDER` |
| `app/detectors/engine.py` | Builds enabled detectors from config; `scan_text` (adds `value`), `overall_risk`, `merge_overlaps`, `redact`. Public API re-exported from `app.detectors` |
| `app/detectors/regex_detector.py` | `RegexDetector`: rules = regex + optional validator. PII: EMAIL, PHONE_IN, PAN, AADHAAR (2-9 start + Verhoeff), CREDIT_CARD (issuer prefix + Luhn). Secrets: AWS, OpenAI, Anthropic, GitHub, Google, Stripe, Slack, JWT (header must decode with `alg`), PEM private keys, DB URLs with credentials |
| `app/detectors/checksums.py` | `verhoeff_valid` / `verhoeff_check_digit`, `luhn_valid` |
| `app/detectors/entropy_detector.py` | `EntropyDetector`: HIGH_ENTROPY_STRING (medium) for tokens >= `min_length` above per-alphabet Shannon thresholds; base64-like needs mixed case + `min_digits`; skips UUIDs, SRI hashes, hex in hash/commit context |
| `app/detectors/ast_detector.py` | `AstDetector`: HARDCODED_SECRET (high) - str literal assigned to a sensitive name/key via Assign/AnnAssign/keyword/Dict; parses whole text, fenced blocks, paragraphs, single lines; span = literal content only (UTF-8 byte cols -> chars) |
| `proxy/armour_addon.py` | mitmproxy hooks. `request`: POSTs to LLM hosts -> `text_slots` (every string; skips model/role/type/id, base64) -> `call_scanner` -> actions from the proxy's `POLICY` -> block 403 / tokenize (+ verify re-scan, map into `VAULT`, `Accept-Encoding: identity`) / allow; demo rerouting. `responseheaders`: attach `StreamRestorer` to SSE. `response`: restore + `report_event`. `error`: delete map + `report_event`. `running`: TTL cleanup + policy polling tasks. `build_event` = metadata-only event; `post_event` runs as a background task and never raises |
| `proxy/tokenization.py` | Pure, no mitmproxy: `tokenize_slots` (one regex pass, same value -> same placeholder), `Restorer`/`restore_json` (exact issued placeholders, one pass; stats: restored/missing/unknown/leaked_types/syntax_valid), `StreamRestorer` (SSE), `TokenVault` (TTL) |
| `mock_llm/` | FastAPI mock of OpenAI `/v1/chat/completions` and Anthropic `/v1/messages`, JSON + SSE (4-char deltas, so placeholders always split). Echoes the user's fenced code with one added comment line. `python -m mock_llm` |
| `run_proxy.py` | Starts mitmdump with the addon on the configured host/port |
| `test_client.py` | Manual client through the proxy: `--stream`, `--provider openai|anthropic`; prints reassembled SSE text |
| `tests/` | pytest. `conftest.py`: every test starts with no secrets; the `api` fixture configures credentials + a fresh DB (SQLite per test; also PostgreSQL when TEST_DATABASE_URL is set). Detectors: `test_*_detector`, `test_checksums`, `test_detector`, `test_performance` (ReDoS). Scanner: `test_api`, `test_policy`. Admin API: `test_api_auth`, `test_api_events`, `test_api_stats`, `test_api_policies`, `test_api_live_playground`, `test_migrations`. Proxy: `test_addon`, `test_tokenization`, `test_roundtrip`, `test_proxy_events` (one event per flow, failure isolation, policy sync, raw DB file contains no values). `test_mock_llm`, `test_config` |

Policy: the `policies` table is the source of truth once a database is configured
(seeded from config.yaml `policy.types` on first start; config.yaml stays the fallback
without a DB). Defaults: EMAIL, PHONE_IN and all secret types -> tokenize; AADHAAR, PAN,
CREDIT_CARD -> block; unlisted -> `default_action: block` (may not be allow). Changes via
PUT /api/policies apply to /scan immediately and to the proxy within
`policy_sync.poll_seconds` (the proxy enforces its own polled copy; on poll failure it
keeps the last good policy).

Streaming restoration (`StreamRestorer`, attached as mitmproxy `flow.response.stream`):
- bytes are buffered until a complete SSE event (blank line), so TCP chunk splits and
  multi-byte UTF-8 characters are never cut
- a delta ending in a prefix of an issued placeholder holds that suffix back and
  prepends it to the next delta at the same JSON path; the held text is flushed as a
  synthetic copy of the last delta event when an event arrives without that path
  (OpenAI finish chunk, Anthropic `content_block_stop`, `[DONE]`) or at end of stream
- carry-over applies to incremental paths only (contains `delta`, or Gemini
  `candidates`); complete strings (Responses `output_text.done`) are restored whole
- events we don't change are forwarded byte-for-byte

## Target architecture (from the review paper)

1. ~~Reversible placeholder tokenization~~ - done (`proxy/tokenization.py`).
2. ~~Local restoration of LLM responses, incl. streaming~~ - done.
3. ~~Regex + Python AST detection~~ - done (`app/detectors/`).
4. ~~PostgreSQL audit log~~ - done (`app/models.py`, `migrations/`).
5. ~~Redis~~ - done for live counters + pub/sub (optional).
6. ~~Next.js admin dashboard~~ - done (`dashboard/`).
7. ~~Docker Compose stack~~ - done (`docker-compose.yml`, `scripts/stack.py`).
8. ~~Evaluation harness~~ - done (`eval/`, results in `eval/results/RESULTS.md`): labelled
   synthetic corpus, precision / recall / F1 per detector, restoration integrity, latency.

Detection rules of thumb:
- Number separators are a single space or dash, never `\s` - the proxy joins JSON
  fields with `\n`, and a match must not span two fields.
- Every regex must be linear-time: anchor the start with a lookbehind and cap
  repetition lengths. `tests/test_performance.py` fails on O(n^2) patterns (ReDoS).
- A detector must not raise on arbitrary *input*, but must not swallow its own bugs
  either (scanner error -> proxy fails closed).
- The same span may be reported by several detectors; keep it (evaluation credits
  each detector), `merge_overlaps` handles it for redaction.

Known gaps in the current code:
- Encoded/obfuscated secrets (base64-encoded, split with spaces) are missed.
- Entropy: random tokens that are single-case (base32, lowercase-only) are not
  flagged; long code identifiers with digits (`X509_STORE_CTX_get_error_depth`)
  can be; 40/64-hex hashes without a context word are flagged as secrets.
- AST: name heuristics only - ML vocab like `pad_token = "[PAD]"` is flagged;
  function default args (`def f(password="x")`) and non-Python code are not scanned.
- Base64 image/audio/file content is skipped, not inspected (no OCR / decoding).
- JSON object *keys* and non-string values (numbers) are not scanned.
- Non-JSON bodies (e.g. multipart audio transcription uploads) are blocked, not scanned.
- Restoration limits: an LLM that alters a placeholder (case, spacing, truncation)
  gets it counted as `missing` and not restored; the map must outlive the upstream
  response time (`ttl_seconds`, default 120 s - slow reasoning models may need more);
  compressed SSE streams and non-JSON responses are forwarded with placeholders.
- SSE: an event split by an empty chunk mid-stream is forwarded unrestored; OpenAI
  `n > 1` streams whose choices interleave mid-placeholder may leave that placeholder
  unrestored; bare-CR line endings are not supported (LF and CRLF are).
- Responses are restored but not *scanned* for new sensitive data; the leak check
  only looks for the tokenized originals.
- Python `str` objects can't be securely wiped; dropping references (`pop`, `close()`)
  is the best available in CPython.
- Admin API: single admin account; no token revocation (rotate JWT_SECRET to log
  everyone out); the login throttle is per API process (not shared between workers).
- Stats aggregate in SQL but `by_type` on SQLite uses `json_each` - fine for tests and
  small installs; PostgreSQL is the supported production database.
- Docker: every service that needs secrets gets the whole `.env.docker` (the proxy can
  read the DB URL it doesn't use); Redis counters are not persisted (by design); the
  stack runs in demo mode - set `demo.enabled: false` in the overlay for real providers.
- Dashboard: no automated UI tests (verified manually + headless-Chrome screenshots);
  logins all come from the Next server's IP, so the API's per-IP login throttle is
  effectively global for dashboard users; the Secure cookie needs HTTPS (or localhost)
  in production mode.
- Azure AI endpoints other than `*.openai.azure.com` (e.g. `*.cognitiveservices.azure.com`)
  are not in `llm_hosts`.

## Commands

All commands run from the project root (`my-armour/`) with the venv active.
Windows PowerShell shown; on Linux/macOS use `source venv/bin/activate`.

```powershell
# one-time setup
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 1. scanner (terminal 1) - host/port from config.yaml
python -m app.main
#    equivalent: uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. proxy (terminal 2) - host/port from config.yaml
python run_proxy.py
#    equivalent: mitmdump -s proxy/armour_addon.py --listen-host 127.0.0.1 --listen-port 8080
#    first run creates the CA cert at ~/.mitmproxy/mitmproxy-ca-cert.pem

# 3. tests (coverage: add --cov=app --cov=proxy --cov=mock_llm --cov=armour_config --cov=eval --cov=scripts)
python -m pytest
#    also against PostgreSQL (throwaway DB - tables are dropped):
#    $env:TEST_DATABASE_URL="postgresql+psycopg://armour:pw@127.0.0.1:5432/armour_test"; python -m pytest

# 4. manual end-to-end check (needs scanner + proxy running)
python test_client.py "What is the capital of France?"   # allowed   -> 401 from OpenAI (fake key)
python test_client.py "Email rahul@acme.com"              # tokenized -> proxy log: PA_EMAIL_...
python test_client.py "aadhaar 2345 6789 0124"           # blocked   -> 403 proxy_armour_block

# 5. demo mode: full tokenize -> LLM -> restore round trip, no API keys needed
#    set demo.enabled: true in config.yaml (or point ARMOUR_CONFIG at a copy), then:
python -m mock_llm                                        # terminal 3 (port 9000)
python test_client.py "mail rahul@acme.com"               # reply: You said: mail rahul@acme.com
python test_client.py --stream --provider anthropic "mail rahul@acme.com"
#    proxy log shows PA_EMAIL_... was sent and "RESTORED ... restored=1 missing=0" 

# 6. database + admin API
copy .env.example .env                                    # then fill it in
python -m app.hash_password                               # -> ADMIN_PASSWORD_HASH='...'
alembic upgrade head                                      # create/upgrade the schema
python -m app.main                                        # API docs: http://127.0.0.1:8000/docs
curl -X POST http://127.0.0.1:8000/api/login -H "Content-Type: application/json" `
     -d '{"username":"admin","password":"..."}'           # -> access_token

# 7. dashboard (needs the API from step 6)
cd dashboard; copy .env.example .env.local; npm install
npm run dev                                               # http://localhost:3000
npm run build; npm run lint                               # must stay at 0 type/lint errors

# 8. everything in Docker (needs Docker Desktop / Engine + any Python 3 on the host)
python scripts/stack.py up        # or: make up  |  .\scripts\armour.ps1 up   (creates .env.docker)
python scripts/stack.py seed      # admin login (prints a random password) + default policies
python scripts/stack.py demo      # every provider format through proxy -> mock LLM, 12 checks
python scripts/stack.py test      # pytest in the scanner container, incl. PostgreSQL (armour_test)
python scripts/stack.py logs proxy
python scripts/stack.py down      # --volumes also deletes the database
#    after the first `up`, plain `docker compose up -d` works too
#    host client through the container proxy:
python test_client.py --ca certs/mitmproxy-ca-cert.pem "mail rahul@acme.com"

# 9. evaluation (paper results) - stop other heavy processes first for clean latency numbers
python -m eval.run_all            # ~20 min -> eval/results/RESULTS.md + *.csv
python -m eval.run_detection      # or one benchmark at a time

# health check
curl http://127.0.0.1:8000/health
```

## Conventions

- Python 3.13, dependencies pinned in `requirements.txt` (direct deps only).
- Every runtime setting goes in `config.yaml` + a field in `armour_config.py`; no new
  hardcoded hosts/ports/policies in code.
- New behaviour needs tests; `tests/test_config.py` guards that config reproduces the
  original behaviour - update it deliberately when behaviour is meant to change.
- Use obviously fake test data (`AKIAIOSFODNN7EXAMPLE`, `rahul@acme.com`), never real
  identifiers. Assemble secret-shaped test values at runtime (`"sk_" + "live_" + ...`)
  so the repo never contains literals that trip GitHub push protection. Fake Aadhaar
  numbers must be Verhoeff-valid (use `verhoeff_check_digit`).
- New detector: implement the `Detector` protocol in `app/detectors/`, register it in
  `engine.build_detectors`, add an `enabled` toggle under `detectors:` in config.yaml,
  and give each new finding type an explicit entry under `policy.types`
  (`test_every_detector_type_has_an_explicit_policy` enforces it).
- Restoration/tokenization logic goes in `proxy/tokenization.py` (pure, unit-testable);
  `armour_addon.py` only wires it into mitmproxy hooks.
- Schema changes: edit `app/models.py` AND add an Alembic revision in
  `migrations/versions/` (`test_migrations_match_the_models` fails otherwise).
- Evaluation rules: never tune detector thresholds on the corpus test split (and keep
  dev-split results as a sanity check only); never commit `eval/data/`; detect-secrets must
  be run via `SecretsCollection.scan_file` (its `scan_line` ad-hoc mode ignores entropy
  limits). `ARMOUR_TIMING_LOG` (addon) writes per-stage durations for `run_latency.py` -
  durations and sizes only, never content.
- New event field: add it to the model, a migration, `EventIn` (pattern-restricted or
  numeric/enum only) and `build_event` - and the `AuditEvent` type in `dashboard/lib/api.ts`.
- Dashboard (Next.js 16 - read `dashboard/node_modules/next/dist/docs/` before using an
  API; see `dashboard/AGENTS.md`): Cache Components is on, so request data (`params`,
  `searchParams`, `cookies()`, `usePathname` on dynamic routes) must be read inside
  `<Suspense>`; `export const dynamic` is not allowed. Data loads client-side through
  `lib/api.ts` + `useApi`. NEXT_PUBLIC_API_URL is inlined at build time.

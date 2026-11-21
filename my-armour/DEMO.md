# Proxy Armour - 5-minute viva demo

Commands are for Windows PowerShell from the repository root (`my-armour/`) with the venv
active (`.\venv\Scripts\Activate.ps1`). Linux/macOS: same commands, `/` paths.

## Before the viva (10 minutes, not on the clock)

1. Start Docker Desktop, then bring everything up and create the admin login:
   ```powershell
   python scripts/stack.py up
   python scripts/stack.py seed --password "choose-a-demo-password"
   python scripts/stack.py demo          # must print 12/12 scenarios passed
   ```
2. Browser: sign in at http://localhost:3000. Open three tabs: **Playground**, **Live feed**, **Overview**.
3. Terminal A (big font): repo root, venv active. Prepare the prompt (paste once, it stays in the session):
   ```powershell
   $prompt = @'
   Why does this fail?
   ```python
   DB_PASSWORD = "Summer2024!"
   ADMIN_EMAIL = "rahul@acme.com"
   connect(host="db.internal", password=DB_PASSWORD)
   ```
   '@
   ```
4. Terminal B: `python scripts/stack.py logs mock-llm` (the "LLM provider" - shows what it receives).
5. Editor: open `eval/results/RESULTS.md` in preview, scrolled to **Table D2**.
6. Have `README.md` open at the architecture diagram.

## The demo (5:00)

### 0:00 - The problem and the idea (30 s)
*Show README architecture diagram.*

> "Developers paste code and customer data into LLM tools. Proxy Armour is a gateway on the
> developer's machine: every request to an LLM API is scanned; secrets are swapped for random
> placeholders before they leave, and put back into the answer locally. Identifiers like Aadhaar
> never leave at all. Everything is logged as metadata only."

### 0:30 - Detection and tokenization in the Playground (60 s)
*Playground tab → **Load demo sample** → **Scan**.*

- Point at the highlights: email and phone (regex), DB URL and Stripe key (regex + entropy),
  `password="..."` found by the **AST detector** - it understands the code, not just patterns.
- Point at **Sent to the LLM**: `PA_DB_CONNECTION_STRING_...`, `PA_HARDCODED_SECRET_...` -
  quotes and code structure intact; the placeholders are random, not hashes.
- Point at the red banner: the PAN in the sample means this request would be **blocked**.

> "Nothing here is stored - the playground just runs the same detectors the proxy uses."

### 1:30 - A live request through the proxy (75 s)
*Live feed tab visible. Terminal A:*
```powershell
python test_client.py --ca certs\mitmproxy-ca-cert.pem --stream $prompt
```
- Terminal A shows the streamed answer with the **real** password and email back in the code.
- Terminal B (the "provider") shows what it actually received:
  `[MOCK-LLM provider view] received: '... DB_PASSWORD = "PA_HARDCODED_SECRET_1A2B3C4D" ...'`
- Live feed: a new **Tokenized** row, `2/2 restored` - it appeared without refreshing.

> "The LLM only ever saw placeholders. The answer was streamed back in 4-character pieces, so
> placeholders were split across events - the proxy reassembles and restores them on the fly."

### 2:45 - A blocked Aadhaar request (45 s)
```powershell
python test_client.py --ca certs\mitmproxy-ca-cert.pem "Update my KYC, my Aadhaar is 2345 6789 0124"
```
- Terminal: `403 ... "detected": ["AADHAAR"]` - the number is not echoed back.
- Live feed: a red **Blocked** row. Click **details** → the event page: types, detectors, timings -
  and no values anywhere.

> "It's not just a 12-digit pattern - the Verhoeff checksum is validated, so order numbers don't
> trigger it. And if the scanner were down, the proxy would block too: it fails closed."

### 3:30 - Dashboard and policies (30 s)
*Overview tab (refresh): requests by action, findings by type, restoration success 100%.*
Optionally on **Policies**: change `PHONE_IN` to *Block*, **Save** - "the proxy picks this up
within 10 seconds".

### 4:00 - Evaluation results (50 s)
*`eval/results/RESULTS.md`.*

- **Table D2 (secrets):** regex alone F1 ≈ 51 %; adding entropy and the AST detector ≈ 91 %;
  detect-secrets ≈ 76 % on the same synthetic test set.
- **Table R2:** an LLM that drops, re-cases, truncates, duplicates or forges placeholders - 100 %
  integrity, zero wrong restorations; leaked originals flagged.
- **Table L1, 1 client:** tens of milliseconds added for 1-10 KiB prompts; under heavy load the
  single-process scanner is the bottleneck and the proxy fails closed rather than leaking.

> "All results come from synthetic data; the corpus is regenerated from a seed and nothing was
> tuned on the test split. Limitations are listed in the README and RESULTS.md."

### 4:50 - Close (10 s)
> "Detection, reversible tokenization with streaming restoration, metadata-only auditing, and an
> evaluation - all reproducible with one command."

## If something goes wrong

| Problem | Fallback |
|---|---|
| Docker won't start | Manual mode from README (`python -m app.main`, `python -m mock_llm`, `python run_proxy.py` with `demo.enabled: true`) and `test_client.py` without `--ca` |
| `test_client` SSL error | Wrong CA: Docker uses `certs\mitmproxy-ca-cert.pem`, manual mode `~\.mitmproxy\` |
| Live feed doesn't update | Refresh the page; the feed falls back to polling without Redis. Events page always works |
| Dashboard login fails | `python scripts/stack.py seed --password "..."` again |
| Anything else | `python scripts/stack.py demo` - 12 scenarios, PASS/FAIL per provider format |

## Likely questions (short answers)

- **Why not just block everything sensitive?** Developers need the LLM's help with that code;
  tokenization keeps the request useful while the value stays local.
- **What if the LLM changes a placeholder?** Only exact issued placeholders are restored; a changed
  one stays visible and is counted as *missing* - never a wrong restoration (Table R2).
- **Where is the token map stored?** Only in the proxy's memory, per request, with a TTL; deleted
  after the response. Never logged or persisted (`tests/test_privacy.py` checks every sink).
- **Why can the proxy read HTTPS?** The developer installs its CA - the same trust model as
  corporate TLS inspection; the CA is per machine and its key stays local.
- **What's not covered?** AST is Python-only, pinned clients, web chat UIs, non-JSON uploads -
  see README "Known limitations".

# Proxy Armour - evaluation results

_Generated 2026-11-19 16:57 UTC by `python -m eval.run_all`. Tables are paste-ready; raw numbers are in the CSV files next to this document._

## Environment

| Item | Value |
| --- | --- |
| CPU | AMD Ryzen 5 4600H with Radeon Graphics |
| Logical cores | 12 |
| RAM | 7.4 GiB |
| OS | Windows 11 (10.0.26300) |
| Python | 3.13.7 |
| mitmproxy | 12.2.3 |
| FastAPI | 0.142.2 |
| uvicorn | 0.54.0 |
| httpx | 0.28.1 |
| detect-secrets | 1.5.0 |
| Git commit | 43035cf-dirty |

## Method

**Data.** Synthetic only. `eval/generate.py` (seed `20261119`) builds 610 samples in
10 categories - Python snippets with secrets in assignments, dicts, keyword
arguments, comments and f-strings; JSON configs; `.env` text; prose with PII; prose with keys;
and hard negatives (UUIDs, git SHAs and SHA-256 digests in context, random IDs, numbers shaped
like Aadhaar/phone/card numbers that fail Verhoeff/Luhn, look-alike code). Each sample carries
ground-truth character spans `{{start, end, type}}` covering exactly the sensitive value.
A stratified, seeded 70/30 dev/test split is drawn
before any detector runs; all detector thresholds are the committed defaults and **nothing was
tuned on either split**. The corpus is regenerated, not committed (it contains realistic fake keys).

**Detection metrics.** A prediction matches a gold span when they overlap by at least 50% of
the longer span. Before scoring, a prediction lying mostly inside a longer prediction is merged
into it (e.g. entropy hits on the parts of a JWT already caught by regex); the proxy redacts the
union anyway. Overall precision/recall/F1 are label-agnostic (the value is protected whatever it
is called); per-type recall is attributed to the gold type. FPR = share of hard-negative samples
with at least one alarm; FNR = 1 − recall.
detect-secrets 1.5.0 is run like `detect-secrets scan` (`SecretsCollection.scan_file`, default
plugins and filters, file extension matching the sample type). It is line-based and its reported
`secret_value` is often a fragment (e.g. `ghp` for a GitHub token, only the header of a PEM key),
so it is scored at **line level**: a gold span counts as caught if detect-secrets reported a line
the span lies on, and a report is a false positive only if its line holds no gold span. This is
more lenient than the span rule applied to configs (a)-(c), i.e. it favours the baseline.
(`scan_line` was not used: its ad-hoc mode reports every word regardless of entropy limits.)
It does not target PII, hence Table D2.

**Restoration.** Each test sample is wrapped in a code fence and sent as an OpenAI chat request
through the proxy's real hooks in-process (scanner app, tokenizer, JSON and SSE restorers);
SSE replies are fed in random 1-64-byte chunks. The honest upstream is `mock_llm` (echoes the
code). A mangling upstream damages placeholders; integrity is checked against an oracle
(only exact issued placeholders restored).

**Latency.** Real processes on one machine: mock LLM, scanner (uvicorn, 1 worker), mitmproxy +
addon, and mitmproxy without the addon as a TLS-interception baseline. Non-streaming requests,
500 measured per cell after 20 warm-ups; percentiles are nearest-rank. Audit events (posted in
the background) were off. The Docker stack was stopped during measurement.

### Detection accuracy (test split: 183 samples, 207 labelled spans, 25 hard negatives)

**Table D1 - all types** (configs a-c: span-level, overlap ≥ 50% of the longer span; (d): line-level, see Method)

| Configuration | TP | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (a) regex | 112 | 0 | 95 | 100.0% | 54.1% | 70.2% | 0.0% | 45.9% |
| (b) regex+entropy | 137 | 0 | 70 | 100.0% | 66.2% | 79.7% | 0.0% | 33.8% |
| (c) regex+entropy+AST | 183 | 0 | 24 | 100.0% | 88.4% | 93.8% | 0.0% | 11.6% |
| (d) detect-secrets | 89 | 2 | 118 | 97.8% | 43.0% | 59.7% | 8.0% | 57.0% |

**Table D2 - secrets only** (PII types excluded from gold and predictions; detect-secrets does not target PII)

| Configuration | TP | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (a) regex | 49 | 0 | 95 | 100.0% | 34.0% | 50.8% | 0.0% | 66.0% |
| (b) regex+entropy | 74 | 0 | 70 | 100.0% | 51.4% | 67.9% | 0.0% | 48.6% |
| (c) regex+entropy+AST | 120 | 0 | 24 | 100.0% | 83.3% | 90.9% | 0.0% | 16.7% |
| (d) detect-secrets | 89 | 2 | 55 | 97.8% | 61.8% | 75.7% | 3.6% | 38.2% |

**Table D3 - recall by ground-truth type** († support < 5: indicative only)

| Type | n | (a) regex | (b) regex+entropy | (c) regex+entropy+AST | (d) detect-secrets |
| --- | ---: | ---: | ---: | ---: | ---: |
| `HARDCODED_SECRET` | 94 | 0% | 26% | 74% | 54% |
| `EMAIL` | 18 | 100% | 100% | 100% | 0% |
| `AADHAAR` | 13 | 100% | 100% | 100% | 0% |
| `CREDIT_CARD` | 12 | 100% | 100% | 100% | 0% |
| `PAN` | 12 | 100% | 100% | 100% | 0% |
| `PHONE_IN` | 8 | 100% | 100% | 100% | 0% |
| `SLACK_TOKEN` | 8 | 100% | 100% | 100% | 100% |
| `AWS_KEY` | 7 | 100% | 100% | 100% | 100% |
| `GITHUB_TOKEN` | 7 | 100% | 100% | 100% | 100% |
| `ANTHROPIC_KEY` | 6 | 100% | 100% | 100% | 17% |
| `STRIPE_KEY` | 6 | 83% | 100% | 100% | 67% |
| `DB_CONNECTION_STRING` | 5 | 100% | 100% | 100% | 80% |
| `PRIVATE_KEY` † | 4 | 100% | 100% | 100% | 100% |
| `GOOGLE_API_KEY` † | 3 | 100% | 100% | 100% | 0% |
| `JWT` † | 3 | 100% | 100% | 100% | 100% |
| `OPENAI_KEY` † | 1 | 100% | 100% | 100% | 0% |

**Table D4 - recall (and false positives) by sample category**

| Category | (a) regex | (b) regex+entropy | (c) regex+entropy+AST | (d) detect-secrets |
| --- | ---: | ---: | ---: | ---: |
| `env_text` | 38% (0 FP) | 68% (0 FP) | 68% (0 FP) | 53% (0 FP) |
| `hard_negative` | — (0 FP) | — (0 FP) | — (0 FP) | — (2 FP) |
| `json_config` | 58% (0 FP) | 65% (0 FP) | 100% (0 FP) | 50% (0 FP) |
| `prose_keys` | 90% (0 FP) | 100% (0 FP) | 100% (0 FP) | 70% (0 FP) |
| `prose_pii` | 100% (0 FP) | 100% (0 FP) | 100% (0 FP) | 0% (0 FP) |
| `py_assign` | 8% (0 FP) | 29% (0 FP) | 100% (0 FP) | 54% (0 FP) |
| `py_comment` | 11% (0 FP) | 11% (0 FP) | 11% (0 FP) | 11% (0 FP) |
| `py_dict` | 13% (0 FP) | 33% (0 FP) | 100% (0 FP) | 93% (0 FP) |
| `py_fstring` | 33% (0 FP) | 44% (0 FP) | 44% (0 FP) | 44% (0 FP) |
| `py_kwargs` | 20% (0 FP) | 33% (0 FP) | 100% (0 FP) | 80% (0 FP) |

**Table D5 - false positives by predicted label**

| Configuration | FP | Labels |
| --- | ---: | --- |
| (a) regex | 0 | — |
| (b) regex+entropy | 0 | — |
| (c) regex+entropy+AST | 0 | — |
| (d) detect-secrets | 2 | `DS:Secret Keyword` 2 |

<details><summary>Dev split (sanity check only - nothing was tuned on either split)</summary>

| Configuration | TP | FP | FN | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| (a) regex | 283 | 2 | 204 | 99.3% | 58.1% | 73.3% | 0.0% | 41.9% |
| (b) regex+entropy | 339 | 0 | 148 | 100.0% | 69.6% | 82.1% | 0.0% | 30.4% |
| (c) regex+entropy+AST | 440 | 0 | 47 | 100.0% | 90.3% | 94.9% | 0.0% | 9.7% |
| (d) detect-secrets | 206 | 23 | 281 | 90.0% | 42.3% | 57.5% | 23.7% | 57.7% |

</details>

### Restoration (test split, through the mock LLM, real proxy hooks in-process)

**Table R1 - honest LLM** (restoration = distinct issued placeholders restored; survival =
issued placeholders present in the LLM reply before restoration; fidelity = client answer
byte-identical to the mock's answer to the *unprotected* prompt; leak alarms on honest
traffic are false alarms; syntax = restored Python code that parses / tokenized Python samples)

| Mode | Requests | Blocked | Tokenized | Allowed | Placeholders | Restored | Survival | Fidelity | Leak alarms | Syntax OK |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| JSON | 183 | 26 | 115 | 42 | 133 | 100.0% | 100.0% | 100.0% | 0 | 59/59 |
| SSE stream | 183 | 26 | 115 | 42 | 133 | 100.0% | 100.0% | 100.0% | 0 | 59/59 |

**Table R2 - integrity under a mangling LLM** (integrity = client answer equals the oracle:
only exact issued placeholders restored, damaged ones left visibly unrestored; counters =
missing/unknown/leak reported exactly as expected; wrong restorations = an original value
placed where no issued placeholder was)

| Mangling | What the LLM did | Mode | Flows | Integrity | Counters correct | Wrong restorations |
| --- | --- | :---: | ---: | ---: | ---: | ---: |
| `drop` | one placeholder removed | JSON | 115 | 100.0% | 100.0% | 0 |
| `drop` | one placeholder removed | SSE | 115 | 100.0% | 100.0% | 0 |
| `alter_case` | one placeholder lower-cased | JSON | 115 | 100.0% | 100.0% | 0 |
| `alter_case` | one placeholder lower-cased | SSE | 115 | 100.0% | 100.0% | 0 |
| `truncate` | last hex digit cut | JSON | 115 | 100.0% | 100.0% | 0 |
| `truncate` | last hex digit cut | SSE | 115 | 100.0% | 100.0% | 0 |
| `split` | space inserted inside | JSON | 115 | 100.0% | 100.0% | 0 |
| `split` | space inserted inside | SSE | 115 | 100.0% | 100.0% | 0 |
| `duplicate` | one placeholder repeated | JSON | 115 | 100.0% | 100.0% | 0 |
| `duplicate` | one placeholder repeated | SSE | 115 | 100.0% | 100.0% | 0 |
| `forge` | never-issued PA_ string added | JSON | 115 | 100.0% | 100.0% | 0 |
| `forge` | never-issued PA_ string added | SSE | 115 | 100.0% | 100.0% | 0 |
| `leak` | an original value returned | JSON | 115 | 100.0% | 100.0% | 0 |
| `leak` | an original value returned | SSE | 115 | 100.0% | 100.0% | 0 |

Leak check: in 1 of 115 leak flows the returned value had never been tokenized (a detector miss - it was already sent in plaintext); the leak check covers tokenized originals only, so no alarm is expected there and none was raised. Every leak of a tokenized value was flagged.

### Latency (500 measured requests per cell after 20 warm-up; non-streaming OpenAI chat; payload = Python code with 3 secrets)

**Table L1 - latency added by Proxy Armour (ms)**. Direct = client → mock LLM; Armour = client →
mitmproxy + Proxy Armour → mock LLM. Added = Armour − direct (mean / median / p95 of each
distribution). "vs plain mitmproxy" = Armour − mitmproxy without the addon (median), i.e. the
cost of scanning/tokenizing/restoring on top of TLS interception. Fail-closed = share of requests
the proxy blocked with 503 because the scanner did not answer within `scanner_timeout` (5 s) - the
designed overload behaviour (never forward unscanned). Other errors = any other non-200 on the
three paths (e.g. 502 when an upstream connection drops under overload); the mock LLM uses a 75 s
keep-alive like typical provider load balancers. Latency columns cover successful requests
("n/a" when fewer than 30 succeeded). Added values are differences between the two distributions'
statistics, not per-request deltas - so with many clients, where the direct path's own tail is wide,
added p95 can be smaller than added median.

| Payload | Clients | Direct median | Armour median | Added mean | Added median | Added p95 | vs plain mitmproxy | Armour req/s | Fail-closed | Other errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 1 | 4.5 | 42.3 | **39.3** | **37.8** | **69.2** | 30.0 | 21 | 0.0% | 0 |
| 1 KiB | 10 | 32.8 | 284.4 | **267.7** | **251.6** | **455.7** | 237.7 | 31 | 0.0% | 0 |
| 1 KiB | 50 | 350.6 | 1570.2 | **1106.3** | **1219.5** | **1802.8** | 1050.3 | 28 | 0.0% | 0 |
| 10 KiB | 1 | 3.6 | 73.1 | **79.6** | **69.5** | **131.9** | 65.8 | 12 | 0.0% | 0 |
| 10 KiB | 10 | 24.1 | 575.3 | **602.8** | **551.2** | **875.1** | 530.9 | 15 | 0.0% | 0 |
| 10 KiB | 50 | 336.1 | 4635.2 | **4252.9** | **4299.2** | **6160.0** | 4119.0 | 10 | 0.0% | 0 |
| 50 KiB | 1 | 4.7 | 299.8 | **315.0** | **295.1** | **459.7** | 290.6 | 3 | 0.0% | 0 |
| 50 KiB | 10 | 26.0 | 2615.1 | **2698.3** | **2589.1** | **3513.8** | 2569.4 | 3 | 0.0% | 0 |
| 50 KiB | 50 | 363.0 | n/a (0 ok) | n/a (0 ok) | n/a (0 ok) | n/a (0 ok) | n/a (0 ok) | 0 | 100.0% | 0 |

**Table L2 - per-stage timing inside the proxy, median ms (1 client)**. detect and verify include the
HTTP round trip to the scanner service; the in-process row is the detectors alone on the same text.

| Payload | parse | detect | of which in-process detection compute | tokenize | verify | restore |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 0.09 | 14.01 | 11.66 | 0.23 | 13.79 | 1.13 |
| 10 KiB | 0.09 | 29.59 | 36.81 | 0.27 | 29.35 | 4.65 |
| 50 KiB | 0.19 | 125.97 | 118.28 | 0.66 | 126.42 | 26.28 |

## Threats to validity

- **Synthetic data.** Formats follow the providers' published shapes but are generated; real
  prompts are messier. Hard negatives cover the listed classes, which the detectors were designed
  for - on real code the entropy detector's false-positive rate was ~0.5% on long identifiers
  (measured during development), and hex hashes *without* a context word are flagged.
- **Small per-type support** for some formats (marked †); overall figures are the robust ones.
- **The mock LLM echoes code verbatim**, so restoration figures are an upper bound for models
  that paraphrase; Table R2 shows what happens when placeholders are damaged.
- **Latency** is single-machine, Windows, loopback networking, one scanner worker; under load the
  scanner's CPU-bound detection (one process, GIL) is the throughput limit - more workers or
  replicas scale it. Figures are for non-streaming responses.
- **Run-to-run variance on a laptop is large.** An earlier run of the same benchmark on the same
  machine (commit `43035cf`, `eval/results/latency.csv` there) measured 21.6 ms added median for
  1 KiB / 1 client versus 37.8 ms here, and 2.1 s versus 4.3 s at 10 KiB / 50 clients; in this run
  the in-process detection time at 10 KiB even exceeded the in-proxy detect stage, a sign of CPU
  frequency changes during measurement. Treat absolute latencies as indicative (≈ ±2×); the
  conclusions - tens of ms at low load, the scanner as bottleneck, fail-closed at the extreme -
  held in every run.

"""Assemble eval/results/RESULTS.md from the per-benchmark fragments + environment.

    python -m eval.report          (run_detection / run_restoration / run_latency first)
    python -m eval.run_all         everything, then this
"""
import json
from datetime import datetime, timezone

from eval.common import RESULTS, environment, md_table
from eval.generate import MAKERS, SEED, TEST_FRACTION, load

METHOD = f"""
## Method

**Data.** Synthetic only. `eval/generate.py` (seed `{SEED}`) builds {{n_samples}} samples in
{len(MAKERS)} categories - Python snippets with secrets in assignments, dicts, keyword
arguments, comments and f-strings; JSON configs; `.env` text; prose with PII; prose with keys;
and hard negatives (UUIDs, git SHAs and SHA-256 digests in context, random IDs, numbers shaped
like Aadhaar/phone/card numbers that fail Verhoeff/Luhn, look-alike code). Each sample carries
ground-truth character spans `{{{{start, end, type}}}}` covering exactly the sensitive value.
A stratified, seeded {int((1 - TEST_FRACTION) * 100)}/{int(TEST_FRACTION * 100)} dev/test split is drawn
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
"""

LIMITATIONS = """
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
"""


def main():
    env = environment()
    samples = load()
    parts = [
        "# Proxy Armour - evaluation results",
        f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `python -m eval.run_all`. "
        "Tables are paste-ready; raw numbers are in the CSV files next to this document._",
        "## Environment",
        md_table(["Item", "Value"], [[k, v] for k, v in env.items()], align="ll"),
        METHOD.replace("{n_samples}", str(len(samples))),
    ]
    for name in ("detection.md", "restoration.md", "latency.md"):
        path = RESULTS / name
        parts.append(path.read_text(encoding="utf-8") if path.exists() else f"_{name}: not run_")
    parts.append(LIMITATIONS)
    (RESULTS / "RESULTS.md").write_text("\n\n".join(p.strip() for p in parts) + "\n", encoding="utf-8")
    (RESULTS / "environment.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    print(f"wrote {RESULTS / 'RESULTS.md'}")


if __name__ == "__main__":
    main()

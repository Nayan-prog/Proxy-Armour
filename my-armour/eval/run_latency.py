"""Latency overhead of Proxy Armour, with real processes and sockets.

    python -m eval.run_latency [--requests 500] [--sizes 1,10,50] [--concurrency 1,10,50]

Paths (each request: OpenAI chat completion, non-streaming, payload = Python code
with 3 secrets so detection, tokenization, verification and restoration all run):
  direct        client -> mock LLM (plain HTTP)
  plain-mitm    client -> mitmproxy without the addon (TLS interception + forwarding only;
                map_remote to the mock) -> mock LLM
  armour        client -> mitmproxy + Proxy Armour (scan, tokenize, verify, restore) -> mock LLM
added = armour - direct (everything the deployment adds); armour - plain-mitm isolates
the addon from the TLS-intercepting proxy every inspection approach needs.

Services run on dedicated ports (scanner 18000, armour 18080, plain 18081, mock 19000)
with access logs off; audit events are off (no EVENTS_SHARED_SECRET) - they are posted
in the background and not on the request path. 20 warm-up requests per run are discarded.
Per-stage times come from the addon's ARMOUR_TIMING_LOG (durations only).
"""
import argparse
import asyncio
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from app.detectors.engine import DETECTORS, scan_text
from eval.common import md_table, summary, write_csv, write_fragment

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
CA = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
PORTS = {"scanner": 18000, "armour": 18080, "plain": 18081, "mock": 19000}
URL = "https://api.openai.com/v1/chat/completions"
WARMUP = 20
OVERLAY = """
scanner: {host: 127.0.0.1, port: %(scanner)d}
proxy: {host: 127.0.0.1, port: %(armour)d}
demo: {enabled: true, upstream_host: 127.0.0.1, upstream_port: %(mock)d}
"""


def payload(kib: int) -> str:
    """~kib KiB prompt: a fenced Python module with 3 secrets (password, email, AWS key)."""
    head = ('Please review this module:\n```python\nimport logging\n\n'
            'DB_PASSWORD = "Summer2024!"\nADMIN_EMAIL = "rahul@acme.com"\n'
            'AWS_ACCESS_KEY_ID = "AKIA' + "IOSFODNN7EXAMPLE" + '"\n\n')
    lines, i = [head], 0
    while sum(map(len, lines)) < kib * 1024 - 40:
        lines.append(f"def handler_{i}(event, context):\n    total = sum(x * {i % 7 + 1} for x in event['items'])\n"
                     f"    logging.info('processed %d items', len(event['items']))\n    return {{'status': 200, 'total': total}}\n\n")
        i += 1
    return "".join(lines) + "```\n"


def wait_port(port: int, timeout: float = 60) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return
        except OSError:
            time.sleep(0.3)
    raise SystemExit(f"port {port} did not open")


def start_services(workdir: Path, timing_log: Path) -> list[subprocess.Popen]:
    overlay = workdir / "overlay.yaml"
    overlay.write_text(OVERLAY % PORTS, encoding="utf-8")
    env = {k: v for k, v in os.environ.items()
           if k not in ("EVENTS_SHARED_SECRET", "DATABASE_URL", "REDIS_URL")}
    env.update(ARMOUR_CONFIG_OVERLAY=str(overlay), ARMOUR_TIMING_LOG=str(timing_log), PYTHONUNBUFFERED="1")
    log = lambda name: open(workdir / f"{name}.log", "w")   # noqa: E731
    mitm_common = ["--set", "connection_strategy=lazy", "--set", "flow_detail=0", "-q"]
    procs = [
        subprocess.Popen([PY, "-m", "uvicorn", "mock_llm.app:app", "--host", "127.0.0.1", "--port", str(PORTS["mock"]),
                          "--no-access-log", "--log-level", "warning", "--timeout-keep-alive", "75"],
                         cwd=ROOT, env=env, stdout=log("mock"), stderr=subprocess.STDOUT),
        subprocess.Popen([PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORTS["scanner"]),
                          "--no-access-log", "--log-level", "warning"], cwd=ROOT, env=env, stdout=log("scanner"), stderr=subprocess.STDOUT),
        subprocess.Popen([PY, "run_proxy.py", *mitm_common], cwd=ROOT, env=env, stdout=log("armour"), stderr=subprocess.STDOUT),
        subprocess.Popen([PY, "-c", "import sys; from mitmproxy.tools.main import mitmdump; mitmdump(sys.argv[1:])",
                          "--listen-host", "127.0.0.1", "--listen-port", str(PORTS["plain"]), *mitm_common,
                          "--map-remote", rf"|https://api\.openai\.com|http://127.0.0.1:{PORTS['mock']}"],
                         cwd=ROOT, env=env, stdout=log("plain"), stderr=subprocess.STDOUT),
    ]
    try:
        for port in PORTS.values():
            wait_port(port)
    except BaseException:
        stop_services(procs)               # don't leave half the stack running
        raise
    return procs


def stop_services(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(10)
        except subprocess.TimeoutExpired:
            p.kill()


async def run_load(path: str, body: bytes, n: int, concurrency: int) -> tuple[list[float], dict]:
    ctx = ssl.create_default_context(cafile=str(CA))
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    if path == "direct":
        client = httpx.AsyncClient(limits=limits, timeout=120)
        url = f"http://127.0.0.1:{PORTS['mock']}/v1/chat/completions"
    else:
        port = PORTS["armour"] if path == "armour" else PORTS["plain"]
        client = httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx, limits=limits, timeout=120)
        url = URL
    headers = {"content-type": "application/json", "authorization": "Bearer sk-not-a-real-key"}
    latencies: list[float] = []
    failures = {"fail_closed": 0, "other": 0}
    queue = asyncio.Queue()
    for i in range(WARMUP + n):
        queue.put_nowait(i)

    async def worker():
        while True:
            try:
                i = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            start = time.perf_counter()
            r = await client.post(url, content=body, headers=headers)
            elapsed = (time.perf_counter() - start) * 1000
            if r.status_code != 200:
                # 503 from the proxy = scanner too slow/unavailable -> request blocked
                # (fail closed, by design). Other non-200s (e.g. 502 when an upstream
                # connection drops under overload) are counted as errors. Neither is timed.
                if path == "armour" and r.status_code == 503 and "Scanner unavailable" in r.text:
                    failures["fail_closed"] += i >= WARMUP
                else:
                    failures["other"] += i >= WARMUP
                continue
            if path == "armour" and "rahul@acme.com" not in r.text:
                raise SystemExit("armour: response was not restored")
            if i >= WARMUP:
                latencies.append(elapsed)

    async with client:
        await asyncio.gather(*(worker() for _ in range(concurrency)))
    return latencies, failures


def read_stages(timing_log: Path) -> list[dict]:
    if not timing_log.exists():
        return []
    rows = [json.loads(line) for line in timing_log.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows[WARMUP:]


def load_rows() -> tuple[list[dict], list[dict]]:
    import csv
    from eval.common import RESULTS

    def typed(row):
        return {k: (v if k in ("path", "stage") else float(v) if "." in v or v == "nan" else int(v))
                for k, v in row.items()}
    with open(RESULTS / "latency.csv", encoding="utf-8") as f:
        rows = [typed(r) for r in csv.DictReader(f)]
    with open(RESULTS / "latency_stages.csv", encoding="utf-8") as f:
        stages = [typed(r) for r in csv.DictReader(f)]
    return rows, stages


def detection_compute_ms(text: str, repeat: int = 30) -> float:
    times = []
    for _ in range(repeat):
        start = time.perf_counter()
        scan_text(text, DETECTORS)
        times.append((time.perf_counter() - start) * 1000)
    return summary(times)["median"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=500)
    ap.add_argument("--sizes", default="1,10,50")
    ap.add_argument("--concurrency", default="1,10,50")
    ap.add_argument("--render-only", action="store_true", help="rebuild the tables from the saved CSVs")
    args = ap.parse_args()
    sizes = [int(x) for x in args.sizes.split(",")]
    levels = [int(x) for x in args.concurrency.split(",")]

    if args.render_only:
        render(*load_rows(), args.requests, sizes, levels)
        return
    workdir = Path(tempfile.mkdtemp(prefix="armour-latency-"))
    timing_log = workdir / "timing.jsonl"
    procs = start_services(workdir, timing_log)
    rows, stage_rows = [], []
    try:
        for kib in sizes:
            text = payload(kib)
            body = json.dumps({"model": "gpt-4o-mini", "messages": [{"role": "user", "content": text}]}).encode()
            compute = detection_compute_ms(text)
            for c in levels:
                for path in ("direct", "plain-mitm", "armour"):
                    timing_log.unlink(missing_ok=True)
                    started = time.time()
                    lat, failed = asyncio.run(run_load(path, body, args.requests, c))
                    nan = float("nan")
                    s = summary(lat) if lat else {"n": 0, "mean": nan, "median": nan, "p95": nan}
                    rows.append({"payload_kib": kib, "body_bytes": len(body), "concurrency": c, "path": path,
                                 **{k: s[k] for k in ("n", "mean", "median", "p95")},
                                 "fail_closed": failed["fail_closed"], "other_errors": failed["other"],
                                 "fail_closed_rate": failed["fail_closed"] / args.requests,
                                 "throughput_rps": len(lat) / (time.time() - started)})
                    print(f"{kib:>3} KiB  c={c:<3} {path:<11} mean {s['mean']:8.1f}  median {s['median']:8.1f}  "
                          f"p95 {s['p95']:8.1f} ms  fail-closed {failed['fail_closed']}/{args.requests}  "
                          f"other errors {failed['other']}", flush=True)
                    if path == "armour":
                        stages = read_stages(timing_log)
                        for name in ("parse_ms", "detect_ms", "tokenize_ms", "verify_ms", "restore_ms"):
                            values = [st[name] for st in stages if name in st]
                            if values:
                                sm = summary(values)
                                stage_rows.append({"payload_kib": kib, "concurrency": c, "stage": name[:-3],
                                                   "mean": sm["mean"], "median": sm["median"], "p95": sm["p95"]})
                        if c == levels[0]:
                            stage_rows.append({"payload_kib": kib, "concurrency": c, "stage": "detect (in-process compute)",
                                               "mean": compute, "median": compute, "p95": compute})
    finally:
        stop_services(procs)

    write_csv("latency.csv", rows)
    write_csv("latency_stages.csv", stage_rows)
    render(rows, stage_rows, args.requests, sizes, levels)


MIN_SUCCESSFUL = 30   # fewer successful requests than this: latency statistics are not reported

def render(rows, stage_rows, requests, sizes, levels):
    """Markdown tables from the measured rows (also used by --render-only from the CSVs)."""

    def get(kib, c, path, key):
        return next(r[key] for r in rows if r["payload_kib"] == kib and r["concurrency"] == c and r["path"] == path)

    def errors(kib, c):
        # other non-200 responses on any path (e.g. 502 upstream connection dropped)
        n = sum(int(get(kib, c, p, "other_errors")) for p in ("direct", "plain-mitm", "armour"))
        return str(n)

    t1 = []
    for kib in sizes:
        for c in levels:
            d = {k: get(kib, c, "direct", k) for k in ("mean", "median", "p95")}
            m = {k: get(kib, c, "plain-mitm", k) for k in ("mean", "median", "p95")}
            a = {k: get(kib, c, "armour", k) for k in ("mean", "median", "p95")}
            ok = get(kib, c, "armour", "n")
            if ok < MIN_SUCCESSFUL:      # (almost) everything failed closed: no latency statistics
                na = f"n/a ({ok} ok)"
                t1.append([f"{kib} KiB", c, f"{d['median']:.1f}", na, na, na, na, na,
                           f"{get(kib, c, 'armour', 'throughput_rps'):.0f}",
                           f"{get(kib, c, 'armour', 'fail_closed_rate') * 100:.1f}%",
                       errors(kib, c)])
                continue
            t1.append([f"{kib} KiB", c, f"{d['median']:.1f}", f"{a['median']:.1f}",
                       f"**{a['mean'] - d['mean']:.1f}**", f"**{a['median'] - d['median']:.1f}**",
                       f"**{a['p95'] - d['p95']:.1f}**", f"{a['median'] - m['median']:.1f}",
                       f"{get(kib, c, 'armour', 'throughput_rps'):.0f}",
                       f"{get(kib, c, 'armour', 'fail_closed_rate') * 100:.1f}%",
                       errors(kib, c)])
    stage_names = ["parse", "detect", "of which in-process detection compute" , "tokenize", "verify", "restore"]
    t2 = []
    for kib in sizes:
        c = levels[0]
        def stage(name):
            key = "detect (in-process compute)" if name.startswith("of which") else name
            r = next((x for x in stage_rows if x["payload_kib"] == kib and x["concurrency"] == c and x["stage"] == key), None)
            return f"{r['median']:.2f}" if r else "—"
        t2.append([f"{kib} KiB", *[stage(n) for n in stage_names]])

    md = f"""
### Latency ({requests} measured requests per cell after {WARMUP} warm-up; non-streaming OpenAI chat; payload = Python code with 3 secrets)

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

{md_table(["Payload", "Clients", "Direct median", "Armour median", "Added mean", "Added median", "Added p95",
           "vs plain mitmproxy", "Armour req/s", "Fail-closed", "Other errors"], t1)}

**Table L2 - per-stage timing inside the proxy, median ms (1 client)**. detect and verify include the
HTTP round trip to the scanner service; the in-process row is the detectors alone on the same text.

{md_table(["Payload", *stage_names], t2)}
"""
    write_fragment("latency.md", md)
    print(md)


if __name__ == "__main__":
    main()

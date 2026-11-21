"""Evaluation harness (eval/) and operator scripts (scripts/).

Every test redirects eval output to tmp_path, so the published eval/results are
never touched, and Docker is never invoked.
"""
import asyncio
import csv
import importlib.util
import json
import subprocess
import sys

import httpx
import pytest

import eval.common as common
from app.detectors.checksums import luhn_valid, verhoeff_valid
from armour_config import ROOT
from eval import generate, mangling_mock


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def results_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "RESULTS", tmp_path / "results")
    return tmp_path / "results"


@pytest.fixture(scope="module")
def corpus():
    return generate.generate()


def subset(corpus, per_category=3):
    out, seen = [], {}
    for s in corpus:
        if seen.get(s["category"], 0) < per_category:
            seen[s["category"]] = seen.get(s["category"], 0) + 1
            out.append(s)
    return out


# ------------------------------------------------------------------ generate

def test_corpus_is_reproducible_and_sized(corpus):
    assert generate.generate() == corpus
    assert len(corpus) == sum(count for _, _, count in generate.MAKERS)
    assert generate.generate(seed=1) != corpus


def test_spans_mark_exactly_the_value(corpus):
    for s in corpus:
        for span in s["spans"]:
            value = s["text"][span["start"]:span["end"]]
            assert value and value == value.strip() and value[0] not in "\"'" and value[-1] not in "\"'"
    assert all(not s["spans"] for s in corpus if s["category"] == "hard_negative")
    assert all(s["spans"] for s in corpus if s["category"] != "hard_negative")


def test_split_is_stratified_70_30(corpus):
    for category, _, count in generate.MAKERS:
        test = sum(1 for s in corpus if s["category"] == category and s["split"] == "test")
        assert test == round(count * generate.TEST_FRACTION)


def test_labelled_identifiers_are_valid_and_lookalikes_are_not():
    v = generate.Values(__import__("random").Random(3))
    for _ in range(50):
        assert verhoeff_valid(v.aadhaar().replace(" ", "").replace("-", ""))
        assert luhn_valid(v.card().replace(" ", "").replace("-", ""))
        assert not verhoeff_valid(v.aadhaar_lookalike())
        assert not luhn_valid(v.card_lookalike())


def test_write_and_load(tmp_path, monkeypatch):
    monkeypatch.setattr(generate, "OUT", tmp_path / "corpus.jsonl")
    assert not (tmp_path / "corpus.jsonl").exists()
    test = generate.load("test")                     # generates on demand
    assert test and all(s["split"] == "test" for s in test)
    assert len(generate.load()) == len(generate.generate())


# ------------------------------------------------------------------ common

def test_overlap_and_nesting_rules():
    assert common.overlap_ok((0, 10), (0, 10))
    assert common.overlap_ok((0, 10), (2, 10))           # 8 of 10
    assert not common.overlap_ok((0, 10), (0, 30))       # 10 of the longer 30
    assert not common.overlap_ok((0, 4), (4, 8))         # touching
    assert common.nested((5, 8), (0, 30)) and not common.nested((0, 30), (5, 8))


def test_merge_predictions_keeps_the_outer_span():
    preds = [{"start": 0, "end": 40, "type": "JWT"}, {"start": 0, "end": 12, "type": "HIGH_ENTROPY_STRING"},
             {"start": 50, "end": 60, "type": "EMAIL"}]
    assert [p["type"] for p in common.merge_predictions(preds)] == ["JWT", "EMAIL"]


def test_counts_and_metrics():
    c = common.Counts()
    c.add_sample([{"start": 0, "end": 10, "type": "A"}, {"start": 20, "end": 30, "type": "B"}],
                 [{"start": 0, "end": 10, "type": "A"}, {"start": 40, "end": 45, "type": "X"}])
    c.add_sample([], [])
    c.add_sample([], [{"start": 0, "end": 3, "type": "X"}])
    m = c.metrics()
    assert (m["tp"], m["fp"], m["fn"]) == (1, 2, 1)
    assert m["precision"] == pytest.approx(1 / 3) and m["recall"] == 0.5 and m["fpr"] == 0.5
    assert c.tp_by_type == {"A": 1} and c.fn_by_type == {"B": 1} and c.fp_by_label == {"X": 2}


def test_line_level_matching():
    c = common.Counts()
    c.add_sample([{"start": 5, "end": 15, "type": "A"}], [{"start": 0, "end": 40, "type": "DS:x"}], line_level=True)
    assert c.metrics()["tp"] == 1


def test_percentile_summary_and_outputs(results_dir):
    values = list(range(1, 101))
    assert common.percentile(values, 95) == 95 and common.percentile(values, 50) == 50
    assert common.summary([1.0, 2.0, 3.0]) == {"mean": 2.0, "median": 2.0, "p95": 3.0, "n": 3}
    path = common.write_csv("x.csv", [{"a": 1, "b": 0.123456}])
    assert path.read_text(encoding="utf-8").splitlines() == ["a,b", "1,0.1235"]
    assert common.md_table(["h", "n"], [["x", 1]]).splitlines()[1] == "| --- | ---: |"
    assert common.write_fragment("f.md", "  hi  ").read_text(encoding="utf-8") == "hi\n"
    assert common.pct(0.1234) == "12.3%"
    env = common.environment()
    assert {"CPU", "RAM", "Python", "mitmproxy"} <= env.keys()


# ------------------------------------------------------------------ mangling mock

PH = "PA_EMAIL_0123ABCD"


@pytest.mark.parametrize("op,expected", [
    ("none", f"x {PH} y"),
    ("drop", "x  y"),
    ("alter_case", f"x {PH.lower()} y"),
    ("truncate", f"x {PH[:-1]} y"),
    ("duplicate", f"x {PH} y\nAs noted above: {PH}\n"),
    ("forge", f"x {PH} y\nAlso check {mangling_mock.FORGED}.\n"),
    ("leak", f"x {PH} y\nFor reference: secret\n"),
])
def test_mangle_operations(op, expected):
    assert mangling_mock.mangle(f"x {PH} y", op, seed=0, leak_value="secret") == expected


def test_mangle_split_breaks_the_placeholder():
    out = mangling_mock.mangle(f"x {PH} y", "split", seed=0)
    assert PH not in out and PH.replace(" ", "") in out.replace(" ", "")


# ------------------------------------------------------------------ benchmark pipelines (small)

def test_run_detection_pipeline(results_dir, monkeypatch, corpus):
    from eval import run_detection
    small = subset(corpus)
    monkeypatch.setattr(run_detection, "load", lambda split=None: [s for s in small if split in (None, s["split"])])
    run_detection.main()
    rows = list(csv.DictReader(open(results_dir / "detection_overall.csv", encoding="utf-8")))
    assert {r["config"] for r in rows} == set(run_detection.ORDER)
    assert "Table D1" in (results_dir / "detection.md").read_text(encoding="utf-8")


def test_run_restoration_pipeline(results_dir, monkeypatch, corpus):
    from eval import run_restoration
    from proxy import armour_addon
    small = [s for s in subset(corpus, 1)]
    monkeypatch.setattr(run_restoration, "load", lambda split=None: small)
    monkeypatch.setattr(run_restoration, "OPS", ["drop", "leak"])
    monkeypatch.setattr(armour_addon, "scanner", armour_addon.scanner)     # restored after the test
    monkeypatch.setattr(armour_addon, "VAULT", armour_addon.VAULT)
    run_restoration.main()
    honest = list(csv.DictReader(open(results_dir / "restoration_honest.csv", encoding="utf-8")))
    assert {r["mode"] for r in honest} == {"JSON", "SSE stream"}
    assert all(r["fidelity"] == str(int(r["requests"]) - int(r["blocked"])) for r in honest)
    mangled = list(csv.DictReader(open(results_dir / "restoration_mangling.csv", encoding="utf-8")))
    assert all(r["integrity_ok"] == r["flows"] and r["wrong_restorations"] == "0" for r in mangled)


def test_latency_helpers_and_render(results_dir, tmp_path, monkeypatch):
    from eval import run_latency
    for kib in (1, 10):
        assert abs(len(run_latency.payload(kib)) - kib * 1024) < 300
    assert run_latency.detection_compute_ms("password = 'hunter22'", repeat=2) >= 0
    log = tmp_path / "t.jsonl"
    log.write_text("\n".join(json.dumps({"parse_ms": i}) for i in range(25)), encoding="utf-8")
    assert len(run_latency.read_stages(log)) == 25 - run_latency.WARMUP
    assert run_latency.read_stages(tmp_path / "missing.jsonl") == []
    with pytest.raises(SystemExit):
        run_latency.wait_port(1, timeout=0.5)

    rows = []
    for path, median in (("direct", 3.0), ("plain-mitm", 7.0), ("armour", 25.0)):
        rows.append({"payload_kib": 1, "body_bytes": 1100, "concurrency": 1, "path": path, "n": 500,
                     "mean": median + 1, "median": median, "p95": median * 2, "fail_closed": 0, "other_errors": 0,
                     "fail_closed_rate": 0.0, "throughput_rps": 40.0})
    rows.append({**rows[2], "concurrency": 50, "n": 3, "fail_closed": 497, "fail_closed_rate": 0.994})
    rows += [{**r, "concurrency": 50} for r in rows[:2]]
    stages = [{"payload_kib": 1, "concurrency": 1, "stage": "detect", "mean": 8.0, "median": 7.5, "p95": 9.0}]
    common.write_csv("latency.csv", rows)
    common.write_csv("latency_stages.csv", stages)
    loaded_rows, loaded_stages = run_latency.load_rows()
    run_latency.render(loaded_rows, loaded_stages, 500, [1], [1, 50])
    md = (results_dir / "latency.md").read_text(encoding="utf-8")
    assert "**22.0**" in md and "n/a (3 ok)" in md and "99.4%" in md and "7.50" in md


def test_report_assembles_results(results_dir, monkeypatch, corpus):
    from eval import report
    monkeypatch.setattr(report, "load", lambda split=None: corpus)
    results_dir.mkdir(parents=True)
    (results_dir / "detection.md").write_text("### Detection\nTABLE", encoding="utf-8")
    report.main()
    text = (results_dir / "RESULTS.md").read_text(encoding="utf-8")
    assert "## Environment" in text and "### Detection" in text and "restoration.md: not run" in text
    assert "## Threats to validity" in text and str(len(corpus)) in text
    assert json.loads((results_dir / "environment.json").read_text(encoding="utf-8"))["Python"]


def test_run_all_runs_everything_in_order(monkeypatch):
    from eval import run_all
    calls = []
    for mod, name in ((run_all.generate, "write"), (run_all.run_detection, "main"),
                      (run_all.run_restoration, "main"), (run_all.report, "main")):
        monkeypatch.setattr(mod, name, lambda n=f"{mod.__name__}.{name}": calls.append(n))
    monkeypatch.setattr(run_all.subprocess, "run", lambda cmd, check: calls.append(" ".join(cmd[1:])))
    monkeypatch.setattr(sys, "argv", ["run_all", "--quick"])
    run_all.main()
    assert calls[:3] == ["eval.generate.write", "eval.run_detection.main", "eval.run_restoration.main"]
    assert calls[3].startswith("-m eval.run_latency --requests 30") and calls[4] == "eval.report.main"


# ------------------------------------------------------------------ scripts/stack.py

@pytest.fixture
def stack(tmp_path, monkeypatch):
    module = load_script("stack")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "ENV_FILE", tmp_path / ".env.docker")
    calls = []

    def fake_run(cmd, cwd, text, input=None, stdout=None):
        calls.append({"cmd": cmd, "input": input})
        out = "$2b$12$" + "x" * 53 if "hash" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, stdout=out)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    module.calls = calls
    return module


def test_env_file_is_generated_once_with_random_secrets(stack):
    stack.ensure_env()
    env = stack.read_env()
    assert len(env["POSTGRES_PASSWORD"]) == 32 and len(env["JWT_SECRET"]) >= 48
    assert env["DATABASE_URL"].endswith("@postgres:5432/proxy_armour") and env["ADMIN_PASSWORD_HASH"] == ""
    before = stack.ENV_FILE.read_text(encoding="utf-8")
    stack.ensure_env()
    assert stack.ENV_FILE.read_text(encoding="utf-8") == before          # never overwritten


def test_set_env_single_quotes_bcrypt_hashes(stack):
    stack.ensure_env()
    stack.set_env("ADMIN_PASSWORD_HASH", "$2b$12$abc")
    assert "ADMIN_PASSWORD_HASH='$2b$12$abc'" in stack.ENV_FILE.read_text(encoding="utf-8")
    assert stack.read_env()["ADMIN_PASSWORD_HASH"] == "$2b$12$abc"
    stack.set_env("NEW_KEY", "v")
    assert stack.read_env()["NEW_KEY"] == "v"


def test_seed_sends_the_password_on_stdin_only(stack, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["stack", "seed", "--password", "a-long-demo-password", "--reset-policies"])
    stack.main()
    hash_call = next(c for c in stack.calls if "hash" in c["cmd"])
    assert hash_call["input"] == "a-long-demo-password\n"
    assert all("a-long-demo-password" not in " ".join(c["cmd"]) for c in stack.calls)
    assert any(c["cmd"][-1] == "--reset" for c in stack.calls)
    assert stack.read_env()["ADMIN_PASSWORD_HASH"].startswith("$2b$12$")
    assert "a-long-demo-password" not in capsys.readouterr().out          # chosen password not echoed


@pytest.mark.parametrize("argv,expected", [
    (["up"], ["up", "-d", "--build", "--wait"]),
    (["down", "--volumes"], ["down", "--volumes"]),
    (["logs", "proxy"], ["logs", "-f", "--tail", "100", "proxy"]),
    (["ps"], ["ps"]),
    (["test", "tests/x.py", "-k", "x"], ["exec", "-T", "-e", "ARMOUR_CONFIG_OVERLAY=", "scanner", "python", "-m", "pytest",
                           "-q", "-p", "no:cacheprovider", "tests/x.py", "-k", "x"]),
    (["demo"], ["exec", "-T", "proxy", "python", "scripts/demo.py", "--proxy", "http://127.0.0.1:8080",
                "--ca", "/certs/mitmproxy-ca-cert.pem"]),
])
def test_stack_commands(stack, monkeypatch, argv, expected):
    monkeypatch.setattr(sys, "argv", ["stack", *argv])
    stack.main()
    assert stack.calls[-1]["cmd"] == ["docker", "compose", *expected]


def test_compose_failure_exits(stack, monkeypatch):
    monkeypatch.setattr(stack.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 3))
    with pytest.raises(SystemExit):
        stack.compose("ps")


# ------------------------------------------------------------------ scripts/demo.py

def demo_handler(demo):
    def handler(request):
        body = json.loads(request.content)
        text = json.dumps(body)
        if demo.AADHAAR in text:
            return httpx.Response(403, json={"error": {"detected": ["AADHAAR"]}})
        if "capital of France" in text:
            return httpx.Response(200, json={"choices": [{"message": {"content": "Paris"}}]})
        reply = " ".join(demo.ORIGINALS)
        if body.get("stream"):
            sse = "".join(f'data: {json.dumps({"choices": [{"delta": {"content": c}}]})}\n\n' for c in reply)
            return httpx.Response(200, text=sse + "data: [DONE]\n\n", headers={"content-type": "text/event-stream"})
        if body.get("stream") is not None and "anthropic" in str(request.url) and False:
            pass
        return httpx.Response(200, json={"choices": [{"message": {"content": reply}}]})
    return handler


def test_demo_passes_against_a_correct_proxy(monkeypatch, capsys, tmp_path):
    demo = load_script("demo")
    real_client = httpx.Client
    monkeypatch.setattr(demo.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(demo_handler(demo))))
    monkeypatch.setattr(demo.ssl, "create_default_context", lambda cafile: None)
    monkeypatch.setattr(sys, "argv", ["demo", "--ca", str(tmp_path / "ca.pem")])
    assert demo.main() == 0
    out = capsys.readouterr().out
    assert f"{len(demo.SCENARIOS)}/{len(demo.SCENARIOS)} scenarios passed" in out


def test_demo_fails_when_placeholders_are_not_restored(monkeypatch, capsys, tmp_path):
    demo = load_script("demo")
    real_client = httpx.Client
    leaky = lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "PA_EMAIL_0123ABCD"}}]})
    monkeypatch.setattr(demo.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(leaky)))
    monkeypatch.setattr(demo.ssl, "create_default_context", lambda cafile: None)
    monkeypatch.setattr(sys, "argv", ["demo", "--ca", str(tmp_path / "ca.pem")])
    assert demo.main() == 1
    assert "FAIL" in capsys.readouterr().out

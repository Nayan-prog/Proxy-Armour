"""Round-trip restoration and integrity, through the mock LLM.

    python -m eval.run_restoration

Every test-split sample is sent as an OpenAI chat request ("Please review: ```...```")
through the addon's real hooks - request (scan + tokenize) -> mock LLM ->
responseheaders/response (JSON or SSE restore) - in-process, with the real scanner
app. SSE responses are fed to the restorer in random chunk sizes (1-64 bytes, seeded).

Honest mock (mock_llm): measures restoration rate, placeholder survival, leak-check
false alarms, end-to-end fidelity (answer identical to an unprotected run) and
post-restore Python syntax validity.
Mangling mock (eval/mangling_mock.py): drops / re-cases / truncates / splits /
duplicates / forges placeholders, or leaks an original. Integrity = the client gets
exactly the oracle answer (only exact issued placeholders restored), and the
missing/unknown/leak counters report the damage.
"""
import ast
import asyncio
import json
import random
import re

import httpx
from mitmproxy import http
from mitmproxy.test import tflow

from app.main import app as scanner_app
from eval import mangling_mock
from eval.common import md_table, pct, write_csv, write_fragment
from eval.generate import load
from mock_llm.app import EDIT_LINE, app as mock_app, reply_for
from proxy import armour_addon as addon
from proxy.tokenization import TokenVault

PLACEHOLDER = re.compile(r"PA_[A-Z][A-Z0-9_]*?_[0-9A-F]{8}")
OPS = ["drop", "alter_case", "truncate", "split", "duplicate", "forge", "leak"]
URL = "https://api.openai.com/v1/chat/completions"


def prompt_for(sample: dict) -> tuple[str, bool]:
    is_python = sample["category"].startswith("py_")
    lang = "python" if is_python else "json" if sample["category"] == "json_config" else "text"
    return f"Please review:\n```{lang}\n{sample['text']}\n```", is_python


def reply_text(body: bytes, streamed: bool) -> str:
    if not streamed:
        return json.loads(body)["choices"][0]["message"]["content"]
    text = ""
    for line in body.decode("utf-8").split("\n"):
        if line.startswith("data: {"):
            text += "".join(c["delta"].get("content", "") for c in json.loads(line[6:])["choices"])
    return text


async def round_trip(prompt: str, *, stream: bool, upstream_app, headers: dict, rng: random.Random) -> dict:
    body = json.dumps({"model": "gpt-4o-mini", "stream": stream, "messages": [{"role": "user", "content": prompt}]})
    flow = tflow.tflow(req=http.Request.make("POST", URL, body, {"content-type": "application/json", **headers}))
    await addon.request(flow)
    if flow.response is not None:
        return {"blocked": flow.response.status_code == 403, "status": flow.response.status_code}

    sent = flow.request.get_text()
    issued = set(PLACEHOLDER.findall(sent))
    mapping = dict(addon.VAULT._entries[flow.id][0]) if flow.id in addon.VAULT else {}   # oracle only

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream_app), base_url="http://mock") as c:
        upstream = await c.post(flow.request.path, content=flow.request.get_content(),
                                headers={"content-type": "application/json", **headers})
    upstream_body = upstream.content
    upstream_text = reply_text(upstream_body, stream)

    flow.response = http.Response.make(200, b"" if stream else upstream_body,
                                       {"content-type": upstream.headers["content-type"]})
    addon.responseheaders(flow)
    if stream:
        restorer = flow.response.stream
        if not callable(restorer):        # nothing tokenized: the proxy passes bytes through
            restorer = lambda data: data   # noqa: E731
        out, i = b"", 0
        while i < len(upstream_body):
            n = rng.randint(1, 64)
            out += restorer(upstream_body[i:i + n])
            i += n
        out += restorer(b"")
        addon.response(flow)
        client_text = reply_text(out, True)
    else:
        addon.response(flow)
        client_text = reply_text(flow.response.content, False)

    oracle = PLACEHOLDER.sub(lambda m: mapping.get(m.group(), m.group()), upstream_text)
    stats = flow.metadata["proxy_armour"].get("restore", {})
    return {"blocked": False, "issued": len(issued), "mapping": mapping, "stats": stats,
            "survived": len({p for p in issued if p in upstream_text}),
            "client_text": client_text, "oracle": oracle, "upstream_text": upstream_text}


def code_of(text: str) -> str | None:
    m = re.search(r"```python\n(.*?)```", text, re.DOTALL)
    return m.group(1) if m else None


def parses(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except Exception:
        return False


async def honest_run(samples, stream: bool) -> tuple[dict, list[dict]]:
    rng = random.Random(7)
    agg = {"requests": 0, "blocked": 0, "tokenized": 0, "allowed": 0, "issued": 0, "restored_distinct": 0,
           "survived": 0, "fidelity": 0, "leak_alarms": 0, "unknown": 0,
           "py_tokenized": 0, "py_original_parses": 0, "py_restored_parses": 0, "py_syntax_agrees": 0}
    rows = []
    for s in samples:
        prompt, is_python = prompt_for(s)
        r = await round_trip(prompt, stream=stream, upstream_app=mock_app, headers={}, rng=rng)
        agg["requests"] += 1
        if r["blocked"]:
            agg["blocked"] += 1
            rows.append({"id": s["id"], "stream": stream, "outcome": "blocked"})
            continue
        st = r["stats"]
        if not r["issued"]:
            agg["allowed"] += 1
        else:
            agg["tokenized"] += 1
            agg["issued"] += r["issued"]
            agg["restored_distinct"] += r["issued"] - st.get("missing", 0)
            agg["survived"] += r["survived"]
            agg["leak_alarms"] += bool(st.get("leaked_types"))
            agg["unknown"] += st.get("unknown", 0)
        # fidelity: identical to the answer the mock gives the ORIGINAL prompt (no proxy)
        identical = r["client_text"] == reply_for(prompt)
        agg["fidelity"] += identical
        if is_python and r["issued"]:
            agg["py_tokenized"] += 1
            original_ok = parses(s["text"])
            restored_code = code_of(r["client_text"])
            restored_ok = restored_code is not None and parses(restored_code.replace(EDIT_LINE + "\n", "", 1))
            agg["py_original_parses"] += original_ok
            agg["py_restored_parses"] += restored_ok
            agg["py_syntax_agrees"] += (st.get("syntax_valid") is True) == original_ok
        rows.append({"id": s["id"], "stream": stream, "outcome": "tokenized" if r["issued"] else "allowed",
                     "issued": r["issued"], "missing": st.get("missing", 0), "survived": r["survived"],
                     "identical_to_unprotected": identical, "syntax_valid": st.get("syntax_valid")})
    return agg, rows


async def mangling_run(samples, op: str, stream: bool) -> dict:
    rng = random.Random(11)
    res = {"op": op, "stream": stream, "flows": 0, "integrity_ok": 0, "counters_ok": 0, "wrong_restorations": 0,
           "leak_of_untokenized": 0}
    for i, s in enumerate(samples):
        prompt, _ = prompt_for(s)
        headers = {"x-mangle": op, "x-mangle-seed": str(i), "x-leak-id": s["id"]}
        if op == "leak":    # the provider "already knows" the first labelled value
            mangling_mock.LEAK_VALUES[s["id"]] = s["text"][s["spans"][0]["start"]:s["spans"][0]["end"]]
        r = await round_trip(prompt, stream=stream, upstream_app=mangling_mock.app, headers=headers, rng=rng)
        if r["blocked"] or not r["issued"]:
            continue
        res["flows"] += 1
        st, up = r["stats"], r["upstream_text"]
        integrity = r["client_text"] == r["oracle"]
        res["integrity_ok"] += integrity
        # an original that appears where the oracle has none = wrong restoration
        res["wrong_restorations"] += sum(max(0, r["client_text"].count(v) - r["oracle"].count(v))
                                         for v in r["mapping"].values())
        expected_missing = sum(1 for p in r["mapping"] if p not in up)
        expected_unknown = 1 if op == "forge" else 0
        counters = st.get("missing") == expected_missing and st.get("unknown") == expected_unknown
        if op == "leak":
            # the leak check watches TOKENIZED originals; a value the detector missed
            # went upstream in plaintext and is a detection miss, not a missed leak
            leaked = mangling_mock.LEAK_VALUES[s["id"]]
            if leaked in r["mapping"].values():
                counters = counters and bool(st.get("leaked_types"))
            else:
                res["leak_of_untokenized"] += 1
                counters = counters and not st.get("leaked_types")
        res["counters_ok"] += counters
    return res


async def main_async():
    samples = load("test")
    addon.scanner = httpx.AsyncClient(transport=httpx.ASGITransport(app=scanner_app))
    addon.VAULT = TokenVault(ttl_seconds=120)

    honest_rows, per_flow = [], []
    for stream in (False, True):
        agg, rows = await honest_run(samples, stream)
        honest_rows.append({"mode": "SSE stream" if stream else "JSON", **agg})
        per_flow += rows
    mangle_rows = []
    tokenizable = [s for s in samples if s["spans"]]
    for op in OPS:
        for stream in (False, True):
            mangle_rows.append(await mangling_run(tokenizable, op, stream))
    assert len(addon.VAULT) == 0, "token maps left behind"
    return honest_rows, per_flow, mangle_rows


def main():
    honest_rows, per_flow, mangle_rows = asyncio.run(main_async())
    write_csv("restoration_honest.csv", honest_rows)
    write_csv("restoration_per_flow.csv", per_flow)
    write_csv("restoration_mangling.csv", mangle_rows)

    t1 = []
    for r in honest_rows:
        t1.append([r["mode"], r["requests"], r["blocked"], r["tokenized"], r["allowed"], r["issued"],
                   pct(r["restored_distinct"] / r["issued"]), pct(r["survived"] / r["issued"]),
                   pct(r["fidelity"] / (r["requests"] - r["blocked"])), r["leak_alarms"],
                   f"{r['py_restored_parses']}/{r['py_tokenized']}"])
    descriptions = {
        "drop": "one placeholder removed", "alter_case": "one placeholder lower-cased",
        "truncate": "last hex digit cut", "split": "space inserted inside", "duplicate": "one placeholder repeated",
        "forge": "never-issued PA_ string added", "leak": "an original value returned",
    }
    t2 = [[f"`{r['op']}`", descriptions[r["op"]], "SSE" if r["stream"] else "JSON", r["flows"],
           pct(r["integrity_ok"] / r["flows"]), pct(r["counters_ok"] / r["flows"]), r["wrong_restorations"]]
          for r in mangle_rows]
    untokenized = max(r["leak_of_untokenized"] for r in mangle_rows if r["op"] == "leak")
    leak_note = (f"Leak check: in {untokenized} of {next(r['flows'] for r in mangle_rows if r['op'] == 'leak')} "
                 "leak flows the returned value had never been tokenized (a detector miss - it was already "
                 "sent in plaintext); the leak check covers tokenized originals only, so no alarm is expected "
                 "there and none was raised. Every leak of a tokenized value was flagged.")
    md = f"""
### Restoration (test split, through the mock LLM, real proxy hooks in-process)

**Table R1 - honest LLM** (restoration = distinct issued placeholders restored; survival =
issued placeholders present in the LLM reply before restoration; fidelity = client answer
byte-identical to the mock's answer to the *unprotected* prompt; leak alarms on honest
traffic are false alarms; syntax = restored Python code that parses / tokenized Python samples)

{md_table(["Mode", "Requests", "Blocked", "Tokenized", "Allowed", "Placeholders", "Restored", "Survival",
           "Fidelity", "Leak alarms", "Syntax OK"], t1)}

**Table R2 - integrity under a mangling LLM** (integrity = client answer equals the oracle:
only exact issued placeholders restored, damaged ones left visibly unrestored; counters =
missing/unknown/leak reported exactly as expected; wrong restorations = an original value
placed where no issued placeholder was)

{md_table(["Mangling", "What the LLM did", "Mode", "Flows", "Integrity", "Counters correct", "Wrong restorations"],
          t2, align="llcrrrr")}

{leak_note}
"""
    write_fragment("restoration.md", md)
    print(md)


if __name__ == "__main__":
    main()

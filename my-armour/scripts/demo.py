"""Send sample secrets through Proxy Armour in every provider format and check the result.

    python scripts/demo.py --proxy http://127.0.0.1:8080 --ca ~/.mitmproxy/mitmproxy-ca-cert.pem

Meant for demo mode (the proxy forwards to the mock LLM, which echoes the code
back). For each request it checks that the client got the ORIGINAL values back
(restored) and no PA_ placeholder leaked through; the Aadhaar request must be
blocked and the clean one allowed. Exit code 1 if any expectation fails.

Sample secrets are generated at run time - nothing secret-shaped is committed.
"""
import argparse
import json
import secrets
import ssl
import string
import sys

import httpx

PASSWORD = "demo-" + secrets.token_hex(6)
EMAIL = "rahul@acme.com"
GITHUB = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
ORIGINALS = (PASSWORD, EMAIL, GITHUB)
CODE = (f'Please review:\n```python\nDB_PASSWORD = "{PASSWORD}"\nADMIN_EMAIL = "{EMAIL}"\n'
        f'GITHUB_TOKEN = "{GITHUB}"\n```')
AADHAAR = "2345 6789 0124"   # fake, Verhoeff-valid


def chat(content, stream=False):
    return {"model": "gpt-4o-mini", "stream": stream, "messages": [{"role": "user", "content": content}]}


SCENARIOS = [
    # name, url, body, expectation
    ("OpenAI chat", "https://api.openai.com/v1/chat/completions", chat(CODE), "restored"),
    ("OpenAI chat (content parts)", "https://api.openai.com/v1/chat/completions",
     chat([{"type": "text", "text": CODE}]), "restored"),
    ("OpenAI chat (streaming)", "https://api.openai.com/v1/chat/completions", chat(CODE, stream=True), "restored"),
    ("OpenAI Responses API", "https://api.openai.com/v1/responses",
     {"model": "gpt-4o-mini", "input": [{"role": "user", "content": [{"type": "input_text", "text": CODE}]}]},
     "restored"),
    ("Anthropic messages", "https://api.anthropic.com/v1/messages",
     {"model": "claude-x", "max_tokens": 512, "system": f"The on-call admin is {EMAIL}.",
      "messages": [{"role": "user", "content": CODE}]}, "restored"),
    ("Anthropic (streaming)", "https://api.anthropic.com/v1/messages",
     {"model": "claude-x", "max_tokens": 512, "stream": True, "messages": [{"role": "user", "content": CODE}]},
     "restored"),
    ("Google Gemini", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=demo-key",
     {"contents": [{"role": "user", "parts": [{"text": CODE}]}]}, "restored"),
    ("Azure OpenAI", "https://contoso.openai.azure.com/openai/deployments/gpt4o/chat/completions?api-version=2024-10-21",
     chat(CODE), "restored"),
    ("Mistral", "https://api.mistral.ai/v1/chat/completions", chat(CODE), "restored"),
    ("Groq", "https://api.groq.com/openai/v1/chat/completions", chat(CODE), "restored"),
    ("Aadhaar (block policy)", "https://api.openai.com/v1/chat/completions",
     chat(f"My Aadhaar is {AADHAAR}, update my KYC"), "blocked"),
    ("Clean prompt", "https://api.openai.com/v1/chat/completions",
     chat("What is the capital of France?"), "allowed"),
]


def reply_text(response: httpx.Response) -> str:
    """All generated text in a JSON or SSE response, whatever the provider format."""
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        text = ""
        for line in response.text.splitlines():
            if not line.startswith("data: {"):
                continue
            event = json.loads(line[6:])
            if "choices" in event:
                text += "".join(c.get("delta", {}).get("content") or "" for c in event["choices"])
            elif event.get("type") == "content_block_delta":
                text += event["delta"].get("text", "")
        return text
    strings: list[str] = []
    stack = [response.json()]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str):
            strings.append(node)
    return "\n".join(strings)


def check(expect: str, response: httpx.Response) -> tuple[bool, str]:
    if expect == "blocked":
        ok = response.status_code == 403 and AADHAAR not in response.text
        return ok, f"HTTP {response.status_code}, detected {response.json()['error']['detected']}" \
            if response.status_code == 403 else f"HTTP {response.status_code} (expected 403)"
    if response.status_code != 200:
        return False, f"HTTP {response.status_code}: {response.text[:120]}"
    text = reply_text(response)
    if expect == "allowed":
        return "Paris" in text or "capital" in text, "answered unchanged"
    missing = [o for o in ORIGINALS if o not in text]
    leftover = "PA_" in text
    ok = not missing and not leftover
    detail = "3/3 originals restored, no placeholders" if ok else \
        f"missing originals: {len(missing)}, placeholders left: {leftover}"
    return ok, detail


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--proxy", default="http://127.0.0.1:8080")
    parser.add_argument("--ca", required=True, help="mitmproxy CA certificate (PEM) to trust")
    args = parser.parse_args()

    ctx = ssl.create_default_context(cafile=args.ca)
    failures = 0
    print(f"{'scenario':32} {'result':8} detail")
    print("-" * 90)
    with httpx.Client(proxy=args.proxy, verify=ctx, timeout=30) as client:
        for name, url, body, expect in SCENARIOS:
            try:
                response = client.post(url, json=body, headers={"Authorization": "Bearer sk-demo-not-a-key"})
                ok, detail = check(expect, response)
            except httpx.HTTPError as e:
                ok, detail = False, f"{type(e).__name__}: {e}"
            failures += not ok
            print(f"{name:32} {'PASS' if ok else 'FAIL':8} {detail}")
    print("-" * 90)
    print(f"{len(SCENARIOS) - failures}/{len(SCENARIOS)} scenarios passed"
          " - open the dashboard (http://localhost:3000) to see the events.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

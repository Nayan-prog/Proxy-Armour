"""Send one prompt to an LLM API through Proxy Armour and print what comes back.

    python test_client.py "your prompt"
    python test_client.py --stream "your prompt"
    python test_client.py --provider anthropic --stream "your prompt"

With demo.enabled: true in config.yaml (and python -m mock_llm running) the
proxy forwards to the local mock LLM, so no API key is needed.

Against the Docker stack:  python test_client.py --ca certs/mitmproxy-ca-cert.pem "..."
"""
import argparse
import json
import os
import ssl

import httpx

from armour_config import settings

PROXY_URL = f"http://{settings.proxy.host}:{settings.proxy.port}"

parser = argparse.ArgumentParser()
parser.add_argument("prompt", nargs="?", default="What is the capital of France?")
parser.add_argument("--stream", action="store_true", help="request an SSE stream")
parser.add_argument("--provider", choices=["openai", "anthropic"], default="openai")
parser.add_argument("--ca", default=os.environ.get("ARMOUR_CA_CERT", os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")),
                    help="mitmproxy CA to trust (Docker stack: certs/mitmproxy-ca-cert.pem)")
args = parser.parse_args()

if args.provider == "openai":
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": "Bearer sk-fake"}
    body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": args.prompt}]}
else:
    url = "https://api.anthropic.com/v1/messages"
    headers = {"x-api-key": "fake", "anthropic-version": "2023-06-01"}
    body = {"model": "claude-x", "max_tokens": 512,
            "messages": [{"role": "user", "content": args.prompt}]}
body["stream"] = args.stream


def delta_text(event: dict) -> str:
    if "choices" in event:                                    # OpenAI chunk
        return "".join(c.get("delta", {}).get("content") or "" for c in event["choices"])
    if event.get("type") == "content_block_delta":            # Anthropic delta
        return event["delta"].get("text", "")
    return ""


ctx = ssl.create_default_context(cafile=args.ca)
with httpx.Client(proxy=PROXY_URL, verify=ctx, timeout=30) as client:
    if not args.stream:
        r = client.post(url, headers=headers, json=body)
        print(r.status_code, r.text[:1000])
    else:
        with client.stream("POST", url, headers=headers, json=body) as r:
            print(r.status_code, r.headers.get("content-type"))
            if not r.headers.get("content-type", "").startswith("text/event-stream"):
                print(r.read().decode()[:1000])
            else:
                events, text = 0, ""
                for line in r.iter_lines():
                    if line.startswith("data: {"):
                        events += 1
                        text += delta_text(json.loads(line[6:]))
                print(f"[{events} SSE events reassembled]")
                print(text)

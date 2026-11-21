"""Start the Proxy Armour proxy (mitmdump + armour addon) using config.yaml.

    python run_proxy.py            # listens on proxy.host:proxy.port from config.yaml
    python run_proxy.py -v         # extra args are passed straight to mitmdump

Equivalent to:
    mitmdump -s proxy/armour_addon.py --listen-host 127.0.0.1 --listen-port 8080 --set flow_detail=0

Never run with flow_detail >= 2 on real traffic: mitmproxy then prints headers
(API keys) and request bodies (prompts) itself.
"""
import sys

from mitmproxy.tools.main import mitmdump

from armour_config import ROOT, settings

def build_args(user_args: list[str]) -> list[str]:
    args = ["-s", str(ROOT / "proxy" / "armour_addon.py"),
            "--listen-host", settings.proxy.host,
            "--listen-port", str(settings.proxy.port)]
    # no per-request lines from mitmproxy by default: level 1 prints URLs (Gemini puts
    # the API key in ?key=), 2+ headers and bodies. Our [ARMOUR] lines are the audit
    # trail. Only added if the user didn't set it - mitmproxy rejects duplicates.
    if not any(a.startswith("flow_detail=") for a in user_args):
        args += ["--set", "flow_detail=0"]
    return args + user_args


if __name__ == "__main__":
    mitmdump(build_args(sys.argv[1:]))

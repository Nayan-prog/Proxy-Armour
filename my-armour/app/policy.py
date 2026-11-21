"""Decide what happens to each finding and to the request as a whole.

Per finding: the policy for its type (allow | tokenize | block), falling back to
policy.default_action for unlisted types. The policy comes from the `policies`
table when a database is configured (seeded from config.yaml), else config.yaml.

Per request: the strictest finding wins - block > tokenize > allow. One AADHAAR
among ten EMAILs blocks the request; tokenizing the emails and sending the
Aadhaar would leak it.

This module has no database imports, so the proxy can use it too.
"""
from armour_config import PolicySettings, settings

STRICTNESS = {"allow": 0, "tokenize": 1, "block": 2}


def apply_policy(findings: list[dict], policy: PolicySettings = settings.policy) -> list[dict]:
    """Return the findings with "action" (and any policy severity override) applied."""
    return [{**f, "action": policy.action_for(f["type"]),
             "severity": policy.severities.get(f["type"], f.get("severity"))}
            for f in findings]


def request_action(findings: list[dict]) -> str:
    """block if any finding is block, else tokenize if any is tokenize, else allow."""
    return max((f["action"] for f in findings), key=STRICTNESS.__getitem__, default="allow")

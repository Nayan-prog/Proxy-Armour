import pytest
from pydantic import ValidationError

from armour_config import load_settings, settings

# The shipped config.yaml values. If these tests fail, runtime behaviour has
# changed - update them only when that change is intended.
EXPECTED_LLM_HOSTS = {
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "*.openai.azure.com",
    "api.mistral.ai",
    "api.groq.com",
}
SECRET_TYPES = {"AWS_KEY", "OPENAI_KEY", "ANTHROPIC_KEY", "GITHUB_TOKEN", "GOOGLE_API_KEY",
                "STRIPE_KEY", "SLACK_TOKEN", "JWT", "PRIVATE_KEY", "DB_CONNECTION_STRING",
                "HIGH_ENTROPY_STRING", "HARDCODED_SECRET"}


def test_config_matches_expected_values():
    assert settings.proxy.llm_hosts == EXPECTED_LLM_HOSTS
    assert settings.scanner.url == "http://127.0.0.1:8000/scan"
    assert settings.proxy.port == 8080
    assert settings.proxy.scanner_timeout == 5
    assert settings.proxy.unsupported_body.status == 415
    assert settings.policy.default_action == "block"
    assert {t for t, a in settings.policy.types.items() if a == "tokenize"} == SECRET_TYPES | {"EMAIL", "PHONE_IN"}
    assert {t for t, a in settings.policy.types.items() if a == "block"} == {"AADHAAR", "PAN", "CREDIT_CARD"}
    assert settings.tokenization.ttl_seconds == 120
    assert settings.demo.enabled is False


def test_scanner_and_proxy_use_the_config():
    from proxy.armour_addon import LLM_HOSTS, SCANNER_URL, UNSUPPORTED_BODY, VAULT

    assert VAULT.ttl == settings.tokenization.ttl_seconds
    assert LLM_HOSTS == EXPECTED_LLM_HOSTS
    assert SCANNER_URL == "http://127.0.0.1:8000/scan"
    assert UNSUPPORTED_BODY.status == 415


VALID = """
scanner: {host: 127.0.0.1, port: 8000}
proxy:
  host: 127.0.0.1
  port: 8080
  scanner_timeout: 5
  llm_hosts: [api.openai.com]
  unsupported_body: {status: 415, message: blocked}
policy:
  default_action: block
  types: {EMAIL: tokenize, AADHAAR: block}
detectors:
  regex: {enabled: true}
  entropy: {enabled: true, min_length: 20, base64_threshold: 4.0, hex_threshold: 3.0, min_digits: 2}
  ast: {enabled: true}
tokenization: {ttl_seconds: 120, cleanup_interval_seconds: 10}
demo: {enabled: false, upstream_host: 127.0.0.1, upstream_port: 9000}
admin: {cors_origins: ["http://localhost:3000"], jwt_expiry_hours: 8, login_max_failures: 5, login_window_seconds: 300}
events: {enabled: true, timeout_seconds: 2}
policy_sync: {poll_seconds: 10}
live: {poll_seconds: 2, heartbeat_seconds: 15}
"""


def write(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_file_loads(tmp_path):
    assert load_settings(write(tmp_path, VALID)).proxy.port == 8080


@pytest.mark.parametrize("broken", [
    VALID.replace("EMAIL: tokenize", "EMAIL: redcat"),    # unknown action
    VALID.replace("default_action: block", "default_action: allow"),  # unknown types would leak
    VALID.replace("port: 8080", "port: 99999"),          # port out of range
    VALID.replace("llm_hosts: [api.openai.com]", "llm_hosts: []"),  # nothing to inspect
    VALID + "typo_section: 1\n",                         # unknown key
    VALID.replace("status: 415", "status: 200"),         # "unsupported" body let through
    VALID.replace("[api.openai.com]", "['*openai*']"),   # ambiguous wildcard
    VALID.replace("[api.openai.com]", "['api.*.com']"),  # wildcard not leading
    VALID.replace("regex: {enabled: true}", "regex: {enabled: false}")
         .replace("entropy: {enabled: true", "entropy: {enabled: false")
         .replace("ast: {enabled: true}", "ast: {enabled: false}"),   # nothing would be scanned
    VALID.replace("hex_threshold: 3.0", "hex_threshold: 4.5"),       # above log2(16) - never fires
], ids=["unknown-action", "default-allow", "bad-port", "no-hosts", "unknown-key",
        "unsupported-status-200", "wildcard-middle", "wildcard-not-leading",
        "all-detectors-off", "impossible-hex-threshold"])
def test_invalid_config_is_rejected(tmp_path, broken):
    with pytest.raises(ValidationError):
        load_settings(write(tmp_path, broken))


def test_env_var_selects_config_file(tmp_path, monkeypatch):
    custom = VALID.replace("port: 8080", "port: 9090")
    monkeypatch.setenv("ARMOUR_CONFIG", str(write(tmp_path, custom)))
    assert load_settings().proxy.port == 9090


def test_detector_toggles_control_the_engine(tmp_path):
    from app.detectors.engine import build_detectors

    cfg = load_settings(write(tmp_path, VALID.replace("ast: {enabled: true}", "ast: {enabled: false}")))
    assert [d.name for d in build_detectors(cfg.detectors)] == ["regex", "entropy"]
    assert [d.name for d in build_detectors(settings.detectors)] == ["regex", "entropy", "ast"]


def test_lowercase_type_names_are_rejected(tmp_path):
    with pytest.raises(ValidationError):
        load_settings(write(tmp_path, VALID.replace("EMAIL: tokenize", "email: tokenize")))


def test_every_detector_type_has_an_explicit_policy():
    # a new detector type silently falling back to default_action is a design
    # decision that should be made explicitly in config.yaml
    from app.detectors.regex_detector import RULES
    from app.detectors.entropy_detector import EntropyDetector
    from app.detectors.ast_detector import AstDetector

    emitted = {r.type for r in RULES} | {EntropyDetector.finding_type, AstDetector.finding_type}
    assert emitted - settings.policy.types.keys() == set()


def test_overlay_deep_merges_only_the_given_keys(tmp_path, monkeypatch):
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("scanner: {host: scanner}\ndemo: {enabled: true, upstream_host: mock-llm}\n",
                       encoding="utf-8")
    monkeypatch.setenv("ARMOUR_CONFIG_OVERLAY", str(overlay))
    s = load_settings(write(tmp_path, VALID))
    assert (s.scanner.host, s.scanner.port) == ("scanner", 8000)          # port kept from base
    assert (s.demo.enabled, s.demo.upstream_host, s.demo.upstream_port) == (True, "mock-llm", 9000)
    assert s.proxy.port == 8080


def test_invalid_overlay_is_rejected(tmp_path, monkeypatch):
    overlay = tmp_path / "overlay.yaml"
    overlay.write_text("policy: {default_action: allow}\n", encoding="utf-8")
    monkeypatch.setenv("ARMOUR_CONFIG_OVERLAY", str(overlay))
    with pytest.raises(ValidationError):
        load_settings(write(tmp_path, VALID))


def test_docker_overlay_is_valid(monkeypatch):
    from armour_config import ROOT
    monkeypatch.setenv("ARMOUR_CONFIG_OVERLAY", str(ROOT / "docker" / "config.overlay.yaml"))
    s = load_settings()
    assert s.scanner.host == "scanner" and s.demo.upstream_host == "mock-llm"

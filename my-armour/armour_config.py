"""Load and validate config.yaml - the one place runtime settings come from.

Usage:
    from armour_config import settings
    settings.proxy.llm_hosts        # frozenset of hostnames
    settings.scanner.url            # "http://127.0.0.1:8000/scan"
    settings.policy.action_for("EMAIL")  # "tokenize"

The file is validated on import, so a typo stops the service at startup
instead of causing a wrong allow/block decision later (fail closed).
"""
import os
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = ROOT / "config.yaml"


Action = Literal["allow", "tokenize", "block"]
Severity = Literal["low", "medium", "high"]
TYPE_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


class _Section(BaseModel):
    # extra="forbid": an unknown or misspelled key is an error, not silently ignored
    # frozen=True: settings can't be changed by accident while running
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScannerSettings(_Section):
    host: str
    port: int = Field(ge=1, le=65535)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/scan"


class UnsupportedBodySettings(_Section):
    # 4xx/5xx only: a non-JSON body can't be scanned, so it must always be blocked
    status: int = Field(ge=400, le=599)
    message: str = Field(min_length=1)


class ProxySettings(_Section):
    host: str
    port: int = Field(ge=1, le=65535)
    scanner_timeout: float = Field(gt=0)
    llm_hosts: frozenset[str] = Field(min_length=1)
    unsupported_body: UnsupportedBodySettings

    @field_validator("llm_hosts")
    @classmethod
    def valid_host_patterns(cls, hosts: frozenset[str]) -> frozenset[str]:
        normalised = set()
        for h in hosts:
            h = h.strip().lower().rstrip(".")
            name = h[2:] if h.startswith("*.") else h
            # only a single leading "*." wildcard is allowed, e.g. "*.openai.azure.com"
            if not name or "*" in name or "." not in name:
                raise ValueError(f"invalid llm_hosts entry {h!r}: use 'api.example.com' "
                                 f"or '*.example.com'")
            normalised.add(h)
        return frozenset(normalised)


class PolicySettings(_Section):
    # unlisted types (typo, new detector) fall back to this - so it must not be
    # "allow", or an unknown finding would leave the machine (fail closed)
    default_action: Literal["tokenize", "block"]
    types: dict[str, Action]
    # optional per-type severity override (the policies table sets these);
    # types not listed keep the severity their detector assigned
    severities: dict[str, Severity] = Field(default_factory=dict)

    @field_validator("types", "severities")
    @classmethod
    def type_names_fit_placeholders(cls, types: dict) -> dict:
        # the name goes into PA_<TYPE>_<hex>, which restoration matches exactly
        for name in types:
            if not TYPE_NAME.fullmatch(name):
                raise ValueError(f"policy type {name!r} must be UPPER_SNAKE_CASE")
        return types

    def action_for(self, finding_type: str) -> str:
        return self.types.get(finding_type, self.default_action)


class TokenizationSettings(_Section):
    ttl_seconds: float = Field(gt=0)
    cleanup_interval_seconds: float = Field(gt=0)


class DemoSettings(_Section):
    enabled: bool
    upstream_host: str
    upstream_port: int = Field(ge=1, le=65535)


class ToggleSettings(_Section):
    enabled: bool


class EntropySettings(_Section):
    enabled: bool
    min_length: int = Field(ge=8)
    # max possible entropy: log2(64) = 6 for base64, log2(16) = 4 for hex
    base64_threshold: float = Field(gt=0, le=6)
    hex_threshold: float = Field(gt=0, le=4)
    min_digits: int = Field(ge=0)


class DetectorsSettings(_Section):
    regex: ToggleSettings
    entropy: EntropySettings
    ast: ToggleSettings

    @model_validator(mode="after")
    def at_least_one_enabled(self) -> "DetectorsSettings":
        # a scanner with no detectors would allow everything - fail closed
        if not (self.regex.enabled or self.entropy.enabled or self.ast.enabled):
            raise ValueError("at least one detector must be enabled")
        return self


class AdminSettings(_Section):
    # browser origins allowed to call /api (the dashboard)
    cors_origins: list[str]
    jwt_expiry_hours: float = Field(gt=0, le=24)
    # failed logins allowed per client IP within the window before 429
    login_max_failures: int = Field(ge=1)
    login_window_seconds: float = Field(gt=0)


class EventsSettings(_Section):
    # proxy -> POST /events after each flow (needs EVENTS_SHARED_SECRET in .env)
    enabled: bool
    timeout_seconds: float = Field(gt=0)


class PolicySyncSettings(_Section):
    # proxy polls GET /internal/policies this often
    poll_seconds: float = Field(gt=0)


class LiveSettings(_Section):
    # /api/live: DB polling interval when Redis is unavailable, SSE keep-alive
    poll_seconds: float = Field(gt=0)
    heartbeat_seconds: float = Field(gt=0)


class Settings(_Section):
    scanner: ScannerSettings
    proxy: ProxySettings
    policy: PolicySettings
    detectors: DetectorsSettings
    tokenization: TokenizationSettings
    demo: DemoSettings
    admin: AdminSettings
    events: EventsSettings
    policy_sync: PolicySyncSettings
    live: LiveSettings


def load_settings(path: str | Path | None = None) -> Settings:
    """Read a YAML config file and return validated Settings.

    Path priority: explicit argument > ARMOUR_CONFIG env var > ./config.yaml
    """
    path = Path(path or os.environ.get("ARMOUR_CONFIG") or DEFAULT_CONFIG_PATH)
    data = _read_yaml(path)
    # optional overlay: a small YAML with only the values that differ (e.g. the
    # Docker hostnames in docker/config.overlay.yaml), deep-merged on top
    overlay = os.environ.get("ARMOUR_CONFIG_OVERLAY")
    if overlay:
        data = deep_merge(data, _read_yaml(Path(overlay)))
    return Settings.model_validate(data)


def _read_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        # typ="safe" only builds plain dicts/lists/strings/numbers -
        # it can never construct Python objects or run code from the file
        return YAML(typ="safe").load(f) or {}


def deep_merge(base: dict, overlay: dict) -> dict:
    """Overlay wins; nested mappings merge key by key, everything else is replaced."""
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


settings = load_settings()


# ------------------------------------------------------------------ secrets (.env)

class EnvSettings(BaseSettings):
    """Secrets and connection strings - from environment variables or ROOT/.env.

    Every field is optional: a missing value disables the feature that needs it
    (no DATABASE_URL -> no audit log / admin data; no REDIS_URL -> no live
    counters; no JWT_SECRET or admin credentials -> admin API answers 503).
    SecretStr keeps values out of repr()/logs. See .env.example.
    """
    # env_ignore_empty: `ADMIN_PASSWORD_HASH=` (e.g. before `seed`) means "not set",
    # so the feature reports itself unconfigured instead of using an empty secret
    model_config = SettingsConfigDict(env_file=ROOT / ".env", env_file_encoding="utf-8",
                                      extra="ignore", frozen=True, env_ignore_empty=True)

    database_url: SecretStr | None = None
    redis_url: SecretStr | None = None
    admin_username: str | None = None
    admin_password_hash: SecretStr | None = None      # bcrypt hash, never the password
    jwt_secret: SecretStr | None = None
    events_shared_secret: SecretStr | None = None


# modules read armour_config.env at call time (not `from ... import env`), so
# tests can swap it with monkeypatch.setattr(armour_config, "env", EnvSettings(...))
env = EnvSettings()

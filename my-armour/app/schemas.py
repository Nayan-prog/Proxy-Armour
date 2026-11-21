"""API request/response models.

EventIn is the gatekeeper of the audit log: extra fields are rejected and every
string is pattern-restricted, so prompt text, original values or placeholders
cannot be stored even if a client tried.
"""
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints


def _utc(ts: datetime | None) -> datetime | None:
    # SQLite returns naive datetimes; everything is stored in UTC, so say so -
    # otherwise a browser would read the time in its own timezone
    if ts is None:
        return None
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


UtcDatetime = Annotated[datetime, AfterValidator(_utc)]

TypeName = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")]
Action = Literal["allow", "tokenize", "block"]
Risk = Literal["none", "low", "medium", "high"]
Severity = Literal["low", "medium", "high"]
Provider = Literal["openai", "anthropic", "google", "azure", "mistral", "groq", "other"]
DetectorName = Literal["regex", "entropy", "ast"]


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: UtcDatetime | None = None
    host: str = Field(pattern=r"^[a-z0-9.-]{1,253}$")
    provider: Provider
    # a path only - no query string (Gemini puts the API key in ?key=)
    endpoint: str = Field(pattern=r"^/[A-Za-z0-9/_.:\-]{0,511}$")
    action: Action
    risk: Risk | None = None
    finding_types: list[TypeName] = Field(default_factory=list, max_length=64)
    finding_count: int = Field(0, ge=0, le=1_000_000)
    detectors_used: list[DetectorName] = Field(default_factory=list, max_length=3)
    tokens_issued: int = Field(0, ge=0)
    tokens_restored: int = Field(0, ge=0)
    tokens_missing: int = Field(0, ge=0)
    tokens_unknown: int = Field(0, ge=0)
    leak_flag: bool = False
    syntax_valid: bool | None = None
    latency_ms_scan: float | None = Field(None, ge=0)
    latency_ms_total: float | None = Field(None, ge=0)
    status_code: int | None = Field(None, ge=100, le=599)


class EventOut(EventIn):
    model_config = ConfigDict(extra="forbid", from_attributes=True)
    id: int
    ts: UtcDatetime


class EventPage(BaseModel):
    items: list[EventOut]
    total: int
    page: int
    page_size: int


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_at: UtcDatetime


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    type: str
    action: Action
    severity: Severity
    updated_at: UtcDatetime | None
    updated_by: str


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: TypeName
    action: Action
    severity: Severity | None = None        # keep the current severity if omitted


class PolicyUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policies: list[PolicyUpdate] = Field(min_length=1, max_length=200)


class PlaygroundIn(BaseModel):
    text: str = Field(max_length=100_000)


class PlaygroundFinding(BaseModel):
    # offsets into the submitted text; the value itself is not echoed back
    type: str
    start: int
    end: int
    severity: Severity
    detector: DetectorName
    action: Action


class PlaygroundOut(BaseModel):
    risk: Risk
    action: Action
    findings: list[PlaygroundFinding]
    tokenized_preview: str
    placeholders: dict[str, str]            # placeholder -> TYPE (no original values)

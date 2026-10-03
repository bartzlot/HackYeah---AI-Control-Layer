"""AICL shared contracts (T-002). Interfaces between w1..w5: change only via a lead task.

Everything crossing a piece boundary is one of these types:
  Event    -> what a PEP (gateway, MCP proxy, SDK) hands to decide()
  Finding  -> what one control reports about an event
  Decision -> what decide() returns (final action + explain trace)
  Control  -> protocol each detector / governor implements
  AuditRecord -> one JSONL line per decision (privacy: no raw text, only spans + hashes)
"""
from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_EVENT = "aicl-event/1"
SCHEMA_CASE = "aicl-case/1"


class Action(IntEnum):
    """Lattice ALLOW < LOG < WARN < REDACT < BLOCK. The final action is the max over findings."""
    ALLOW = 0
    LOG = 1
    WARN = 2
    REDACT = 3
    BLOCK = 4

    @classmethod
    def parse(cls, value: "str | int | Action") -> "Action":
        if isinstance(value, str):
            return cls[value.upper()]
        return cls(value)


def lattice_max(actions) -> Action:
    return max(actions, default=Action.ALLOW)


class Stage(StrEnum):
    PROMPT = "prompt"          # user/system/tool messages going to a model
    RESPONSE = "response"      # model output coming back
    TOOL_ARGS = "tool_args"    # a tool call the model wants to make
    TOOL_RESULT = "tool_result"
    LIFECYCLE = "lifecycle"    # policy reload, kill switch


class DestKind(StrEnum):
    LOCAL = "local"            # local Ollama model
    EXTERNAL = "external"      # priced commercial model (cloud-sim)
    UNKNOWN = "unknown"        # anything else: strictest column of the matrix


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Part(_Model):
    """One text segment of an event; findings point into it by index and span."""
    role: str = "user"                       # system | user | assistant | tool
    text: str
    trusted: bool = True                     # False = retrieved doc / tool output (indirect injection surface)


class ToolCall(_Model):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    server: str | None = None                # MCP server id when known


class Usage(_Model):
    input_tokens: int = 0
    output_tokens: int = 0
    usd: float = 0.0
    source: Literal["reported", "estimated"] = "estimated"


class Event(_Model):
    stage: Stage = Stage.PROMPT
    channel: Literal["llm", "tool", "mcp", "memory"] = "llm"
    parts: list[Part] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    agent_id: str = "anonymous"
    session_id: str | None = None
    request_id: str | None = None
    model: str | None = None
    destination: DestKind = DestKind.UNKNOWN
    profile: str | None = None               # strict | balanced | permissive, None = agent default
    usage: Usage | None = None


class Span(_Model):
    part: int = 0
    start: int
    end: int
    type: str                                # e.g. AWS_KEY, PL_PESEL
    sha256_8: str | None = None              # never the value itself


class Finding(_Model):
    control_id: str                          # DLP-01, INJ-03, TOOL-01, BUD-01 ...
    rule_id: str
    category: str                            # secret | pii | injection | tool_abuse | resource | supply_chain
    action: Action
    reason_code: str = ""
    score: float | None = None
    threshold: float | None = None
    spans: list[Span] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)
    rule_source: Literal["builtin", "policy", "local", "feed"] = "builtin"


class Redaction(_Model):
    part: int
    start: int
    end: int
    replacement: str                         # [REDACTED_AWS_KEY], [PL_PESEL_1]


class Decision(_Model):
    action: Action = Action.ALLOW
    would_action: Action = Action.ALLOW      # differs from action when a control runs in shadow mode
    findings: list[Finding] = Field(default_factory=list)
    redactions: list[Redaction] = Field(default_factory=list)
    explain: list[str] = Field(default_factory=list)   # human-readable trace, one line per step
    policy_version: str = ""                 # sha256 of the canonical policy
    degraded: bool = False                   # a detector timed out / failed (fail mode applied)
    latency_us: dict[str, int] = Field(default_factory=dict)
    decision_id: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK


class Ctx(_Model):
    """Per-call context handed to controls next to the event."""
    profile: str = "balanced"
    mode: Literal["enforce", "shadow", "off"] = "enforce"
    params: dict[str, Any] = Field(default_factory=dict)   # thresholds etc. from policy.yaml for this control


@runtime_checkable
class Control(Protocol):
    """A detector or governor. Pure with respect to the event; may read its own state (budgets)."""
    control_id: str
    stages: tuple[Stage, ...]

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]: ...


# --- audit -----------------------------------------------------------------

AUDIT_EVENT_TYPES = (
    "REQUEST_ALLOWED", "PII_REDACTED", "SECRET_DETECTED", "INJECTION_BLOCKED", "TOOL_CALL_ALLOWED",
    "TOOL_CALL_BLOCKED", "BUDGET_EXCEEDED", "AGENT_LOOP_TERMINATED", "MODEL_DENIED", "POLICY_CHANGED",
)


class AuditRecord(_Model):
    schema_version: str = SCHEMA_EVENT
    ts: str                                  # ISO-8601 UTC
    event_id: str
    request_id: str | None = None
    event_type: str
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    decision: Action
    would_decision: Action | None = None
    stage: Stage
    channel: str = "llm"
    agent_id: str = "anonymous"
    session_id: str | None = None
    model: str | None = None
    destination: DestKind = DestKind.UNKNOWN
    tool: str | None = None
    findings: list[Finding] = Field(default_factory=list)   # spans carry positions + hash only
    redaction_count: int = 0
    policy_version: str = ""
    usage: Usage | None = None
    latency_us: dict[str, int] = Field(default_factory=dict)
    degraded: bool = False
    explain: list[str] = Field(default_factory=list)

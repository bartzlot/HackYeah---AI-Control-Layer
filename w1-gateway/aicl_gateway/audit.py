"""Audit sink: AuditRecord JSONL file + EventBus."""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone

from aicl_contracts import Action, AuditRecord, Decision, Event, Finding, Stage

from .bus import EventBus


def event_type(event: Event, d: Decision) -> str:
    cats = {f.category for f in d.findings if f.action >= Action.WARN}
    if d.action == Action.BLOCK:
        if event.stage == Stage.TOOL_ARGS:
            return "TOOL_CALL_BLOCKED"
        if "injection" in cats:
            return "INJECTION_BLOCKED"
        if "resource" in cats:
            return "BUDGET_EXCEEDED"
        return "SECRET_DETECTED" if "secret" in cats else "REQUEST_BLOCKED"
    if d.action == Action.REDACT:
        return "SECRET_DETECTED" if "secret" in cats else "PII_REDACTED"
    if event.stage == Stage.TOOL_ARGS:
        return "TOOL_CALL_ALLOWED"
    return "REQUEST_ALLOWED"


def severity(d: Decision) -> str:
    return {Action.BLOCK: "high", Action.REDACT: "medium", Action.WARN: "low"}.get(d.action, "info")


class Audit:
    def __init__(self, path: str | None, bus: EventBus):
        self.path, self.bus, self._lock = path, bus, threading.Lock()

    def emit(self, record: AuditRecord) -> AuditRecord:
        if self.path:
            line = record.model_dump_json() + "\n"
            with self._lock, open(self.path, "a", encoding="utf-8") as f:
                f.write(line)
        self.bus.publish(record.model_dump(mode="json"))
        return record

    def from_decision(self, event: Event, d: Decision, event_type_: str | None = None) -> AuditRecord:
        return self.emit(AuditRecord(
            ts=datetime.now(timezone.utc).isoformat(), event_id=d.decision_id or uuid.uuid4().hex,
            request_id=event.request_id, event_type=event_type_ or event_type(event, d), severity=severity(d),
            decision=d.action, would_decision=d.would_action, stage=event.stage, channel=event.channel,
            agent_id=event.agent_id, session_id=event.session_id, model=event.model, destination=event.destination,
            tool=event.tool_calls[0].name if event.tool_calls else None, findings=d.findings,
            redaction_count=len(d.redactions), policy_version=d.policy_version, usage=event.usage,
            latency_us=d.latency_us, degraded=d.degraded, explain=d.explain, protocol=event.protocol,
            upstream_host=event.upstream_host, client_ip=event.client_ip, credential_hash=event.credential_hash,
            user_agent=event.user_agent))

    def denied(self, event: Event, reason: str, event_type_: str = "MODEL_DENIED",
               findings: list[Finding] | None = None) -> AuditRecord:
        d = Decision(action=Action.BLOCK, would_action=Action.BLOCK, explain=[reason], findings=findings or [],
                     decision_id=uuid.uuid4().hex[:16])
        return self.from_decision(event, d, event_type_)

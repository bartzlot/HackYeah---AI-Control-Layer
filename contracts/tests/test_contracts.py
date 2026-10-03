import pytest
from pydantic import ValidationError

from aicl_contracts import (Action, AuditRecord, Control, Ctx, Decision, Event, Finding, Part, Span, Stage,
                            lattice_max)


def test_lattice_order_and_max():
    assert Action.ALLOW < Action.LOG < Action.WARN < Action.REDACT < Action.BLOCK
    assert lattice_max([Action.WARN, Action.BLOCK, Action.REDACT]) == Action.BLOCK
    assert lattice_max([]) == Action.ALLOW
    assert Action.parse("redact") == Action.REDACT


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        Event(parts=[Part(text="x")], bogus=1)


def test_decision_roundtrip_json():
    f = Finding(control_id="DLP-01", rule_id="AWS_KEY", category="secret", action=Action.REDACT,
                spans=[Span(start=0, end=20, type="AWS_KEY")])
    d = Decision(action=Action.REDACT, findings=[f], policy_version="sha256:x")
    assert Decision.model_validate_json(d.model_dump_json()) == d
    assert not d.blocked


def test_control_protocol_is_structural():
    class C:
        control_id = "X"
        stages = (Stage.PROMPT,)

        def evaluate(self, event, ctx):
            return []

    assert isinstance(C(), Control)
    assert C().evaluate(Event(), Ctx()) == []


def test_audit_record_carries_no_raw_text_field():
    assert "parts" not in AuditRecord.model_fields and "text" not in AuditRecord.model_fields

"""T-201 acceptance, one test per item of the TASKS.md line: ruamel + pydantic load, 1 s polling reload,
last-good on invalid, policy_version = sha256, control registry, action lattice, explain trace
(control, rule, span), span redaction ([REDACTED_AWS_KEY], [PL_PESEL_n])."""
import hashlib
import json
import time

import pytest

from aicl_contracts import Action, Event, Finding, Part, Stage
from aicl_core import Engine, PolicyError, apply_redactions, load_policy, registered
from aicl_core.engine import BUILTIN, REGISTRY, register
from aicl_core.util import span


def test_ruamel_yaml12_and_pydantic_validation(policy_dir):
    pol = load_policy(policy_dir)
    assert pol.doc.version == "aicl-policy/1" and set(pol.doc.profiles) == {"strict", "balanced", "permissive"}
    policy_dir.write_text(policy_dir.read_text(encoding="utf-8").replace("version: aicl-policy/1", "version: v9"),
                          encoding="utf-8")
    with pytest.raises(PolicyError, match="aicl-policy"):
        load_policy(policy_dir)


def test_policy_version_is_sha256_of_canonical_policy_and_rules(policy_dir):
    pol = load_policy(policy_dir)
    h = hashlib.sha256(json.dumps(pol.raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                  default=str).encode())
    for f in pol.files:
        if f.parent.name == "rules":
            h.update(f.read_bytes())
    assert pol.version == h.hexdigest()


def test_rule_file_edit_changes_version(policy_dir):
    v1 = load_policy(policy_dir).version
    rf = policy_dir.parent / "rules" / "historical.yaml"
    rf.write_text(rf.read_text(encoding="utf-8").replace("severity: medium", "severity: high", 1), encoding="utf-8")
    assert load_policy(policy_dir).version != v1


def test_engine_reload_one_second_and_last_good(policy_dir):
    eng = Engine(policy_dir, interval=1.0, start=True)
    try:
        ev = Event(parts=[Part(text="hello")], agent_id="analyst-agent", destination="local")
        v0 = eng.decide(ev).policy_version
        original = policy_dir.read_text(encoding="utf-8")
        policy_dir.write_text(original.replace("kill_switch: false", "kill_switch: true"), encoding="utf-8")
        t0 = time.monotonic()
        while eng.decide(ev).action != Action.BLOCK and time.monotonic() - t0 < 3.0:
            time.sleep(0.05)
        d = eng.decide(ev)
        assert d.action == Action.BLOCK and d.policy_version != v0 and time.monotonic() - t0 < 2.5
        good = d.policy_version
        policy_dir.write_text("defaults: [broken\n", encoding="utf-8")       # invalid edit
        t0 = time.monotonic()
        while eng.store.error is None and time.monotonic() - t0 < 3.0:
            time.sleep(0.05)
        d = eng.decide(ev)
        assert eng.store.error and d.policy_version == good and d.action == Action.BLOCK   # last good still enforced
        assert eng.status()["error"] == eng.store.error
    finally:
        eng.store.stop()


def test_registry_lists_controls_in_order_and_register_adds():
    ids = registered()
    assert ids[:2] == ["KILL-01", "ACCESS-01"] and {"KILL-01", "ACCESS-01"} <= BUILTIN

    class Probe:
        control_id, stages = "PROBE-99", (Stage.PROMPT,)

        def evaluate(self, event, ctx):
            return []
    try:
        register(Probe())
        assert registered()[-1] == "PROBE-99"
    finally:
        REGISTRY.pop("PROBE-99", None)


@pytest.mark.parametrize("acts, final", [
    ([], Action.ALLOW), ([Action.LOG], Action.LOG), ([Action.LOG, Action.WARN], Action.WARN),
    ([Action.WARN, Action.REDACT], Action.REDACT), ([Action.REDACT, Action.BLOCK, Action.LOG], Action.BLOCK),
])
def test_action_lattice_max(engine, acts, final):
    text = "My AWS key is AKIAIOSFODNN7EXAMPLE"

    class Many:
        control_id, stages = "DLP-01", (Stage.PROMPT,)

        def evaluate(self, event, ctx):
            return [Finding(control_id="DLP-01", rule_id=f"R{i}", category="t", action=a,
                            spans=[span(0, 14, 34, "AWS_KEY", "x")]) for i, a in enumerate(acts)]
    saved = dict(REGISTRY)
    REGISTRY.clear()
    REGISTRY["DLP-01"] = Many()
    try:
        d = engine.decide(Event(parts=[Part(text=text)], agent_id="analyst-agent", destination="local"))
    finally:
        REGISTRY.clear()
        REGISTRY.update(saved)
    assert d.action == final and d.would_action == final


def test_explain_trace_has_control_rule_span_and_redaction_placeholders(engine):
    text = "key AKIAIOSFODNN7EXAMPLE for PESEL 44051401458"
    e = Event(parts=[Part(text=text)], agent_id="analyst-agent", model="gpt-4o-mini", destination="external")
    pol = engine.policy.derive({"controls": {"DLP-05": {"mode": "off"}}})
    d = engine.decide(e, policy=pol)
    assert d.action == Action.REDACT
    assert apply_redactions([text], d.redactions)[0] == "key [REDACTED_AWS_KEY] for PESEL [PL_PESEL_1]"
    assert any(x.startswith("DLP-01 rule AWS_KEY: REDACT at part 0 [4:24] AWS_KEY") for x in d.explain)
    assert any(x.startswith("DLP-02 rule PL_PESEL: REDACT at part 0 [35:46] PL_PESEL") for x in d.explain)
    assert d.explain[-1].startswith("decision REDACT by DLP-0")

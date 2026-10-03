import pytest

from aicl_contracts import Action, Event, Finding, Part, Span, Stage, ToolCall
from aicl_core import apply_redactions
from aicl_core.engine import REGISTRY, resolve_destination
from aicl_core.util import span

TEXT = "My AWS key is AKIAIOSFODNN7EXAMPLE and PESEL 44051401458, again 44051401458."


class Fake:
    """Test control: returns canned findings; registered under a policy-known id for one test."""
    stages = (Stage.PROMPT, Stage.TOOL_ARGS)

    def __init__(self, cid, findings=None, boom=False):
        self.control_id, self._f, self._boom = cid, findings or [], boom

    def evaluate(self, event, ctx):
        if self._boom:
            raise RuntimeError("detector bug")
        return [f(event) if callable(f) else f for f in self._f]


@pytest.fixture
def swap():
    """Temporarily replace registered controls with fakes (by id)."""
    saved = dict(REGISTRY)

    def put(*fakes):
        REGISTRY.clear()
        for f in fakes:
            REGISTRY[f.control_id] = f

    yield put
    REGISTRY.clear()
    REGISTRY.update(saved)


def ev(text=TEXT, **kw):
    kw.setdefault("agent_id", "analyst-agent")
    return Event(parts=[Part(text=text)], **kw)


def secret(e):
    i = e.parts[0].text.index("AKIA")
    return Finding(control_id="DLP-01", rule_id="AWS_KEY", category="secret", action=Action.REDACT,
                   spans=[span(0, i, i + 20, "AWS_KEY", "AKIAIOSFODNN7EXAMPLE")], detail={"priority": 100})


def pesels(e):
    t = e.parts[0].text
    a = t.index("44051401458")
    b = t.index("44051401458", a + 1)
    return Finding(control_id="DLP-02", rule_id="PL_PESEL", category="pii", action=Action.REDACT,
                   spans=[span(0, a, a + 11, "PL_PESEL", "44051401458"), span(0, b, b + 11, "PL_PESEL", "44051401458")],
                   detail={"placeholder": "numbered"})


def test_lattice_redaction_and_explain(engine, swap):
    warn = Finding(control_id="INJ-03", rule_id="HIST-010", category="injection", action=Action.WARN)
    swap(Fake("DLP-01", [secret]), Fake("DLP-02", [pesels]), Fake("INJ-03", [warn]))
    e = ev()
    d = engine.decide(e)
    assert d.action == Action.REDACT and d.would_action == Action.REDACT
    out = apply_redactions([e.parts[0].text], d.redactions)[0]
    assert out == "My AWS key is [REDACTED_AWS_KEY] and PESEL [PL_PESEL_1], again [PL_PESEL_1]."
    assert d.policy_version == engine.policy.version and d.decision_id
    assert d.explain[0].startswith("policy ") and d.explain[-1] == "decision REDACT by DLP-01/AWS_KEY"
    assert any("DLP-01 rule AWS_KEY: REDACT at part 0 [14:34] AWS_KEY" in x for x in d.explain)
    assert {"DLP-01", "DLP-02", "INJ-03", "total"} <= set(d.latency_us)


def test_block_wins_and_has_no_redactions(engine, swap):
    block = Finding(control_id="INJ-03", rule_id="HIST-003", category="code_exec", action=Action.BLOCK)
    swap(Fake("DLP-01", [secret]), Fake("INJ-03", [block]))
    d = engine.decide(ev())
    assert d.action == Action.BLOCK and d.redactions == [] and d.blocked
    assert "HIST-003" in d.explain[-2] and d.explain[-1] == "decision BLOCK by INJ-03/HIST-003"


def test_shadow_mode_sets_only_would_action(engine, swap):
    swap(Fake("DLP-01", [secret]))
    pol = engine.policy.derive({"controls": {"DLP-01": {"mode": "shadow"}}})
    d = engine.decide(ev(), policy=pol)
    assert d.action == Action.ALLOW and d.would_action == Action.REDACT and d.redactions == []
    assert "shadow" in d.explain[-2] and "would be REDACT" in d.explain[-1]


def test_off_and_removed_controls_do_not_run(engine, swap):
    swap(Fake("DLP-01", [secret]))
    assert engine.decide(ev(), policy=engine.policy.derive({"controls": {"DLP-01": {"mode": "off"}}})).action == 0
    assert engine.decide(ev(), policy=engine.policy.derive({"controls": {"DLP-01": None}})).action == 0


def test_overlapping_spans_higher_priority_wins(engine, swap):
    def wide(e):
        return Finding(control_id="DLP-02", rule_id="X", category="pii", action=Action.REDACT,
                       spans=[span(0, 10, 40, "WIDE", "x")])
    swap(Fake("DLP-01", [secret]), Fake("DLP-02", [wide]))
    d = engine.decide(ev())   # union of both spans, placeholder of the higher-priority one
    assert [(r.start, r.end, r.replacement) for r in d.redactions] == [(10, 40, "[REDACTED_AWS_KEY]")]


def test_bad_redact_offsets_block(engine, swap):
    def bad(e):
        return Finding(control_id="DLP-02", rule_id="X", category="pii", action=Action.REDACT,
                       spans=[Span(part=0, start=5, end=10_000, type="X")])
    swap(Fake("DLP-01", [secret]), Fake("DLP-02", [bad]))
    d = engine.decide(ev())
    assert d.action == Action.BLOCK and d.would_action >= d.action


def test_engine_error_fails_closed(engine, swap):
    swap(Fake("DLP-01", ["not a finding"]))
    d = engine.decide(ev())
    assert d.action == Action.BLOCK and d.degraded and "engine error" in d.explain[0]


def test_fail_typo_is_closed(engine, swap):
    swap(Fake("DLP-01", boom=True))
    pol = engine.policy.derive({"controls": {"DLP-01": {"fail": "open"}}})
    assert engine.decide(ev(), policy=pol).action == Action.ALLOW
    raw = engine.policy.raw["controls"]["DLP-01"]
    assert engine.policy.fail_for("DLP-01") == "closed" and "fail" not in raw


def test_builtin_controls_survive_block_removal(engine):
    pol = engine.policy.derive({"controls": {"ACCESS-01": None}})
    assert engine.decide(ev(agent_id="intruder"), policy=pol).action == Action.BLOCK
    pol = engine.policy.derive({"controls": {"ACCESS-01": {"mode": "off"}}})
    assert engine.decide(ev(agent_id="intruder"), policy=pol).action != Action.BLOCK


def test_request_profile_can_only_tighten(engine):
    pol = engine.policy
    assert pol.profile_for("analyst-agent", "strict") == "strict"
    assert pol.profile_for("analyst-agent", "permissive") == "balanced"
    assert pol.profile_for("mailer-agent", None) == "strict"


def test_redact_in_tool_arguments_becomes_block(engine, swap):
    def in_args(e):
        return Finding(control_id="DLP-01", rule_id="AWS_KEY", category="secret", action=Action.REDACT,
                       spans=[Span(part=-1, start=0, end=20, type="AWS_KEY")])
    swap(Fake("DLP-01", [in_args]))
    e = Event(stage=Stage.TOOL_ARGS, agent_id="analyst-agent",
              tool_calls=[ToolCall(name="web.fetch", arguments={"url": "AKIAIOSFODNN7EXAMPLE"})])
    d = engine.decide(e)
    assert d.action == Action.BLOCK and "cannot redact" in d.findings[0].reason_code


def test_control_error_fails_closed_or_degrades(engine, swap):
    swap(Fake("DLP-01", boom=True), Fake("INJ-04", boom=True))
    d = engine.decide(ev())                      # DLP-01 inherits defaults.fail: closed
    assert d.action == Action.BLOCK and d.findings[0].rule_id == "CONTROL_ERROR"
    pol = engine.policy.derive({"controls": {"DLP-01": {"fail": "degrade"}}})
    d = engine.decide(ev(), policy=pol)          # INJ-04 has fail: degrade
    assert d.action == Action.ALLOW and d.degraded


def test_destination_resolved_from_model_tag_never_weaker(engine):
    pol = engine.policy
    assert resolve_destination(pol, Event(model="qwen3.5:2b-q4_K_M", destination="local")).value == "local"
    assert resolve_destination(pol, Event(model="gpt-4o-mini", destination="local")).value == "external"
    assert resolve_destination(pol, Event(model="gpt-oss:120b-cloud", destination="local")).value == "unknown"
    assert resolve_destination(pol, Event(model="mystery", destination="local")).value == "unknown"
    assert resolve_destination(pol, Event(model="qwen3.5:2b-q4_K_M", destination="external")).value == "external"


def test_status_reports_posture(engine):
    st = engine.status()
    assert st["policy_version"] == engine.policy.version and st["error"] is None
    assert 0 < st["posture_pct"] <= 100 and any(r["control_id"] == "KILL-01" for r in st["controls"])


def test_module_level_decide_uses_repo_policy():
    from aicl_core import decide
    d = decide(Event(parts=[Part(text="hello")], agent_id="support-bot", model="qwen3.5:2b-q4_K_M"))
    assert d.action == Action.ALLOW and len(d.policy_version) == 64

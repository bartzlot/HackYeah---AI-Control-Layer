"""Runs every <piece>/cases/*.yaml through decide(), plus the mutation proof: each negative case
must FAIL when its own control is switched off (so the suite really catches that control)."""
import pytest

from aicl_core.cases import build_event, case_policy, check, collect_cases

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

CASES = collect_cases(REPO)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_case(engine, case):
    pol = case_policy(engine.policy, case)
    event = build_event(case)
    d = engine.decide(event, policy=pol)
    errs = check(case, event, d)
    assert not errs, f"{case.file.name} {case.id}: {errs}\n" + "\n".join(d.explain)


@pytest.mark.parametrize("case", [c for c in CASES if c.kind == "negative"], ids=lambda c: c.name)
def test_negative_case_fails_with_control_off(engine, case):
    pol = case_policy(engine.policy, case, {"controls": {case.control: {"mode": "off"}}})
    event = build_event(case)
    d = engine.decide(event, policy=pol)
    assert check(case, event, d), f"{case.name} still passes with {case.control} off: the case does not test it"

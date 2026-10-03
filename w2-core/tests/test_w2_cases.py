"""Runs every <piece>/cases/*.yaml whose control is enforced inside decide(), plus the mutation proof:
each negative case must FAIL when its own control is switched off (so the suite really catches it).

Controls enforced by the gateway itself (budgets and the loop guard, BUD-01) cannot be decided by
decide(): their cases are driven through the gateway over ASGI with the scripted cloud-sim upstream
(w1-gateway/tests/test_cases.py, unified by the T-204 runner). A case for a control that neither
side knows fails here, so a typo in `control:` never silently skips a case."""
from pathlib import Path

import pytest

from aicl_core import registered
from aicl_core.cases import build_event, case_policy, check, collect_cases

from w2_gateway_driver import GATEWAY_CONTROLS, runs_on_decide, runs_on_gateway

GATEWAY_ONLY_KEYS = {"http_status", "upstream_called", "retry_after", "upstream_body_contains",
                     "upstream_body_not_contains", "judge_called", "degraded"}

REPO = Path(__file__).resolve().parents[2]

ALL = collect_cases(REPO)
DECIDE = set(registered())
CASES = [c for c in ALL if runs_on_decide(c, DECIDE)]


def test_every_case_has_a_known_driver():
    unknown = sorted({c.name for c in ALL if c.control not in DECIDE | GATEWAY_CONTROLS
                      and c.runner not in ("gateway", "judge-fake")})
    assert not unknown, f"cases for controls neither decide() nor the gateway enforce: {unknown}"
    nowhere = sorted(c.name for c in ALL if not runs_on_decide(c, DECIDE) and not runs_on_gateway(c, DECIDE))
    assert not nowhere, f"cases no driver runs: {nowhere}"


def test_decide_only_cases_carry_no_gateway_only_expectations():
    """check() cannot see HTTP status, upstream traffic or judge calls: a case only decide() runs must not
    promise them, or they would pass unchecked."""
    lost = sorted(f"{c.name}: {sorted(set(c.expect) & GATEWAY_ONLY_KEYS)}" for c in CASES
                  if not runs_on_gateway(c, DECIDE) and set(c.expect) & GATEWAY_ONLY_KEYS)
    assert not lost, f"gateway-only expectations on decide-only cases: {lost}"


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

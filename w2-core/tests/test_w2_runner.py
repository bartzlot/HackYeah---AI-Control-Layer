"""T-204 unified runner: every */cases/*.yaml of every piece, driven through decide() (test_w2_cases.py)
AND through the real gateway (ASGI + scripted cloud-sim) here, plus the meta-tests:
  - every control enabled in policy.yaml has at least one positive and one negative case;
  - budgets (BUD-01) and every historical exploit category have a blocking case;
  - every negative gateway case stops matching when its control is switched off.
`make test` runs this with the rest of the suite and writes reports/junit.xml."""
from pathlib import Path

import pytest

from aicl_core import load_policy, registered
from aicl_core.cases import case_policy, collect_cases, coverage_gaps, enabled_controls

from w2_gateway_driver import GATEWAY_CONTROLS, check_gateway, gateway_path, run_gateway_case, runs_on_gateway

REPO = Path(__file__).resolve().parents[2]
ALL = collect_cases(REPO)
GW = [c for c in ALL if runs_on_gateway(c, set(registered()))]
# controls whose owner task has not landed cases yet: reported as xfail, never silently skipped
PENDING = {"INJ-04": "w1 moving tests/cases_pending/INJ-04.yaml into cases/ (runner: judge-fake is driven since T-205)"}


def test_gateway_only_cases_are_routable():
    """A case of a gateway-enforced control that the gateway driver cannot run would run nowhere."""
    lost = [c.name for c in ALL if (c.control in GATEWAY_CONTROLS or c.runner in ("gateway", "judge-fake"))
            and not gateway_path(c)]
    assert not lost, f"gateway-control cases the gateway driver cannot run: {lost}"


@pytest.mark.parametrize("case", GW, ids=lambda c: c.name)
async def test_case_through_gateway(engine, case):
    pol = case_policy(engine.policy, case)
    got = await run_gateway_case(case, pol, engine.decide)
    bad = check_gateway(case, got)
    assert not bad, f"{case.file.name} {case.id}: {bad}\nstatus {got['status']} events {got['events']}\n{got['payload']}"


@pytest.mark.parametrize("case", [c for c in GW if c.kind == "negative"], ids=lambda c: c.name)
async def test_gateway_negative_fails_with_control_off(engine, case):
    pol = case_policy(engine.policy, case, {"controls": {case.control: {"mode": "off"}}})
    got = await run_gateway_case(case, pol, engine.decide, control_off=True)
    assert check_gateway(case, got), f"{case.name} still passes through the gateway with {case.control} off"


@pytest.mark.parametrize("cid", enabled_controls(load_policy(REPO / "policy" / "policy.yaml")))
def test_meta_each_control_has_positive_and_negative_case(cid):
    gaps = coverage_gaps(ALL, [cid])
    if cid in PENDING and gaps:
        pytest.xfail(f"{cid}: cases owed by {PENDING[cid]}")
    assert not gaps, f"{cid} needs an allowed and a blocked/redacted case, missing {gaps[cid]}"


def test_meta_budget_and_exploit_cases_exist(engine):
    bud = [c for c in ALL if c.control == "BUD-01" and c.kind == "negative"]
    assert any(c.expect.get("http_status") == 429 for c in bud), "budget exhaustion case (429) missing"
    assert any("AGENT_LOOP_TERMINATED" in (c.expect.get("events") or []) for c in bud), "loop guard case missing"
    by_cat = {r.id: r.category for r in engine.policy.rules}
    # every category of the historical-exploit rule set (HIST-*) needs a blocking case
    exploit_categories = sorted({r.category for r in engine.policy.rules if r.id.startswith("HIST-")})
    assert {"code_exec", "unsafe_deserialization", "model_supply_chain"} <= set(exploit_categories)
    covered = {by_cat.get(r) for c in ALL if c.kind == "negative" for r in c.expect.get("rule_ids") or []}
    missing = [cat for cat in exploit_categories if cat not in covered]
    assert not missing, f"no blocking case for historical exploit categories {missing}"


def test_meta_case_ids_unique_per_control():
    seen = {}
    for c in ALL:
        assert (c.control, c.id) not in seen, f"duplicate case id {c.name} in {c.file} and {seen[(c.control, c.id)]}"
        seen[(c.control, c.id)] = c.file

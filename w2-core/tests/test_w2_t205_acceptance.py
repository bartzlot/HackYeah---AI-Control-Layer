"""T-205 acceptance: the shared runner drives case files marked `runner: gateway` / `runner: judge-fake`
(w1 BUD-01, INJ-04) through the real gateway, so w1 can move INJ-04.yaml from tests/cases_pending/ into
cases/. Uses w1's pending file read-only; when w1 has moved it, the same file is found under cases/."""
import shutil
from pathlib import Path

import pytest

from aicl_contracts import SCHEMA_CASE
from aicl_core import registered
from aicl_core.cases import RUNNERS, case_policy, collect_cases, coverage_gaps, load_case_file
from aicl_core.engine import REGISTRY

from w2_gateway_driver import (check_gateway, run_gateway_case, runs_on_decide, runs_on_gateway, with_judge_answer,
                               without_judge_keys)

REPO = Path(__file__).resolve().parents[2]
_CANDIDATES = [REPO / "w1-gateway" / "cases" / "INJ-04.yaml", REPO / "w1-gateway" / "tests" / "cases_pending" / "INJ-04.yaml"]
INJ04 = next((p for p in _CANDIDATES if p.is_file()), None)
needs_file = pytest.mark.skipif(INJ04 is None, reason="w1 INJ-04 case file not present")
JUDGE_CASES = load_case_file(INJ04) if INJ04 else []


def _write(tmp_path, body):
    f = tmp_path / "X.yaml"
    f.write_text(f"schema: {SCHEMA_CASE}\ncontrol: X\n" + body, encoding="utf-8")
    return f


def test_runner_field_file_level_and_per_case_override(tmp_path):
    f = _write(tmp_path, "runner: gateway\ncases:\n- {id: a, kind: positive}\n- {id: b, kind: negative, runner: decide}\n")
    a, b = load_case_file(f)
    assert (a.runner, b.runner) == ("gateway", "decide")
    assert load_case_file(_write(tmp_path, "cases:\n- {id: a, kind: positive}\n"))[0].runner == "auto"
    assert set(RUNNERS) == {"auto", "decide", "gateway", "judge-fake"}


def test_unknown_runner_rejected(tmp_path):
    with pytest.raises(ValueError, match="runner must be one of"):
        load_case_file(_write(tmp_path, "runner: magic\ncases:\n- {id: a, kind: positive}\n"))


@needs_file
def test_judge_fake_cases_route_to_gateway_only():
    decide = set(registered())
    assert JUDGE_CASES and all(c.runner == "judge-fake" for c in JUDGE_CASES)
    assert all(runs_on_gateway(c, decide) and not runs_on_decide(c, decide) for c in JUDGE_CASES)


@needs_file
@pytest.mark.parametrize("case", JUDGE_CASES, ids=lambda c: c.name)
async def test_judge_fake_case_passes_through_gateway(engine, case):
    got = await run_gateway_case(case, case_policy(engine.policy, case), engine.decide)
    bad = check_gateway(case, got)
    assert not bad, f"{case.name}: {bad} status {got['status']} events {got['events']}"
    assert "INJ-04" not in REGISTRY                    # the fake judge never leaks into later decisions


@needs_file
@pytest.mark.parametrize("case", [c for c in JUDGE_CASES if c.kind == "negative"], ids=lambda c: c.name)
async def test_judge_fake_negative_fails_with_judge_off(engine, case):
    pol = case_policy(engine.policy, case, {"controls": {case.control: {"mode": "off"}}})
    got = await run_gateway_case(case, pol, engine.decide, control_off=True)
    assert check_gateway(without_judge_keys(case), got), f"{case.name} verdict still matches with the judge off"


@needs_file
@pytest.mark.parametrize("case", [c for c in JUDGE_CASES if c.kind == "negative" and c.setup.get("judge") == "malicious"],
                         ids=lambda c: c.name)
async def test_malicious_verdict_is_what_blocks(engine, case):
    benign = with_judge_answer(case, "benign")
    got = await run_gateway_case(benign, case_policy(engine.policy, benign), engine.decide)
    assert check_gateway(without_judge_keys(case), got), f"{case.name} still blocked with a benign judge"


def test_unknown_expect_key_fails_in_decide_runner(engine):
    from aicl_core.cases import build_event, check
    case = next(c for c in collect_cases(REPO) if c.name == "DLP-02:T10")
    typo = type(case)(**{**case.__dict__, "expect": {**case.expect, "decison": "BLOCK"}})
    ev = build_event(typo)
    assert any("unknown expect keys" in x for x in check(typo, ev, engine.decide(ev)))


@needs_file
def test_moving_the_file_into_cases_closes_the_inj04_gap(tmp_path):
    shutil.copytree(REPO / "w2-core" / "cases", tmp_path / "w2-core" / "cases")
    (tmp_path / "w1-gateway" / "cases").mkdir(parents=True)
    shutil.copy(INJ04, tmp_path / "w1-gateway" / "cases" / "INJ-04.yaml")
    cases = collect_cases(tmp_path)
    assert not coverage_gaps(cases, ["INJ-04"])
    decide = set(registered())
    assert all(runs_on_decide(c, decide) or runs_on_gateway(c, decide) for c in cases)


@needs_file
def test_judge_expectations_are_checked_not_ignored():
    case = next(c for c in JUDGE_CASES if c.expect.get("judge_called") is True)
    got = {"status": 200, "decision": case.expect.get("decision"), "events": list(case.expect.get("events") or []),
           "rule_ids": [], "controls": [], "upstream_called": True, "upstream_body": "", "content": "", "tool_calls": [],
           "retry_after": None, "judge_called": False, "degraded": False}
    assert any("judge_called" in b for b in check_gateway(case, got))


async def test_auto_and_decide_runners_unchanged(engine):
    """A runner: decide case never reaches the gateway; auto cases of decide controls still run on both."""
    cases = collect_cases(REPO)
    decide = set(registered())
    dlp = next(c for c in cases if c.name == "DLP-02:T09")
    assert runs_on_decide(dlp, decide) and runs_on_gateway(dlp, decide)
    bud = [c for c in cases if c.control == "BUD-01"]
    assert bud and all(runs_on_gateway(c, decide) and not runs_on_decide(c, decide) for c in bud)


@needs_file
async def test_judge_cleanup_runs_even_when_gateway_setup_fails(engine, monkeypatch):
    import aicl_gateway

    def boom(*a, **kw):
        raise RuntimeError("create_app failed")
    monkeypatch.setattr(aicl_gateway, "create_app", boom)
    case = JUDGE_CASES[0]
    with pytest.raises(RuntimeError, match="create_app failed"):
        await run_gateway_case(case, case_policy(engine.policy, case), engine.decide)
    assert "INJ-04" not in REGISTRY


@needs_file
def test_decide_only_keys_flagged_on_gateway_only_runners():
    case = JUDGE_CASES[0]
    case = type(case)(**{**case.__dict__, "expect": {**case.expect, "would_decision": "BLOCK"}})
    got = {"status": 200, "decision": case.expect.get("decision"), "events": [], "rule_ids": [], "controls": [],
           "upstream_called": True, "upstream_body": "", "content": "", "tool_calls": [], "retry_after": None,
           "judge_called": bool(case.expect.get("judge_called")), "degraded": bool(case.expect.get("degraded"))}
    assert any("cannot be checked by runner judge-fake" in b for b in check_gateway(case, got))

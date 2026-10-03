"""Local runner for w1-gateway/cases/*.yaml (gateway-level controls owned by w1, e.g. BUD-01).

Until the shared w2 runner (T-204) lands, check.sh drives the cases here: ASGI gateway + scripted
cloud-sim upstreams, stub decide (ALLOW) so only the gateway's own controls act. The meta test runs
every negative case again with the control off and requires it to stop matching (the case catches
something).
"""
from pathlib import Path

import json

import httpx
import pytest
import yaml

from aicl_gateway import create_app
from cloud_sim import Script, create_app as sim_app

CASES_DIR = Path(__file__).resolve().parents[1] / "cases"
# case files the shared w2 runner cannot drive yet (T-205): kept out of */cases/ so main stays green
PENDING_DIR = Path(__file__).resolve().parent / "cases_pending"
AGENT, KEY = "case-agent", "k-case"
POLICY_AGENT = "analyst-agent"          # policy.yaml agent allowed on gpt-4o-mini
LOCAL = "qwen3.5:2b-q4_K_M"


def load_cases():
    out = []
    for f in sorted([*CASES_DIR.glob("*.yaml"), *PENDING_DIR.glob("*.yaml")]):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert doc["schema"] == "aicl-case/1", f
        for c in doc["cases"]:
            out.append((doc["control"], {**c, "_runner": doc.get("runner", "gateway")}))
    return out


CASES = load_cases()


JUDGE_REPLIES = {"benign": ("benign", "none"), "suspicious": ("suspicious", "low"), "malicious": ("malicious", "high")}


def judge_decide(case: dict, control_off: bool):
    """runner judge-fake: w2 engine over policy.yaml with the INJ-04 judge (fake Ollama) registered after
    INJ-03; control off = judge not registered. Returns (decide, judge calls list, cleanup)."""
    from aicl_core import engine as eng
    from aicl_gateway.judge import install
    e = eng.Engine(Path(__file__).resolve().parents[2] / "policy" / "policy.yaml")
    calls = []
    if control_off:
        return e.decide, calls, lambda: None
    word = (case.get("setup") or {}).get("judge", "benign")

    def fake(body, timeout):
        calls.append(body)
        if word == "timeout":
            raise TimeoutError("fake judge timeout")
        verdict, level = JUDGE_REPLIES[word]
        return {"message": {"content": json.dumps({"prompt_injection": level, "data_exfiltration": "none",
                                                   "jailbreak": "none", "tool_abuse": "none", "verdict": verdict})}}

    install(eng.register, "http://unused", chat_fn=fake)
    return e.decide, calls, lambda: eng.REGISTRY.pop("INJ-04", None)


async def run_case(case: dict, control_off: bool = False) -> dict:
    if case.get("_runner") == "judge-fake":
        decide, calls, cleanup = judge_decide(case, control_off)
        try:
            got = await run_gateway_case(case, control_off, decide)
        finally:
            cleanup()
        got["judge_called"] = bool(calls)
        return got
    return await run_gateway_case(case, control_off, None)


async def run_gateway_case(case: dict, control_off: bool, decide) -> dict:
    setup, inp = case.get("setup") or {}, case["input"]
    repeat = int(setup.get("repeat", 1))
    steps = [{"tool_calls": setup["tool_calls"]} for _ in range(repeat)] if setup.get("tool_calls") else None
    ext, loc = sim_app(Script(steps)), sim_app(Script(steps), {LOCAL: {"in": 0, "out": 0}})
    agent = POLICY_AGENT if decide is not None else AGENT   # the real policy denies unknown agents
    cfg = {"agents": {KEY: {"agent_id": agent, "profile": case.get("profile")}},
           "budgets": {} if control_off or "budget" not in setup else {agent: setup["budget"]},
           "loop_limits": {"repeat_identical": 10_000 if control_off else 4}}
    ups = {"external": httpx.AsyncClient(transport=httpx.ASGITransport(app=ext), base_url="http://ext"),
           "local": httpx.AsyncClient(transport=httpx.ASGITransport(app=loc), base_url="http://loc")}
    app = create_app(decide, cfg, ups)
    if setup.get("spent") and not control_off:
        app.state.ledger.record(agent, int(setup["spent"].get("tokens", 0)), float(setup["spent"].get("usd", 0.0)))
    records = []
    app.state.bus.listeners.append(records.append)
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw")
    headers = {"authorization": f"Bearer {KEY}"}
    if setup.get("session"):
        headers["x-session-id"] = setup["session"]
    body = {"model": setup.get("destination", "gpt-4o-mini"), **inp}
    for _ in range(repeat):
        calls_before = len(ext.state.calls) + len(loc.state.calls)
        n0 = len(records)
        r = await c.post("/v1/chat/completions", headers=headers, json=body)
    return {"status": r.status_code, "decision": r.headers.get("x-aicl-decision"),
            "retry_after": r.headers.get("retry-after"),
            "events": [x["event_type"] for x in records[n0:]],
            "degraded": any(x.get("degraded") for x in records[n0:]),
            "upstream_called": len(ext.state.calls) + len(loc.state.calls) > calls_before}


def matches(case: dict, got: dict) -> list[str]:
    exp, bad = case["expect"], []
    if "decision" in exp and got["decision"] != exp["decision"]:
        bad.append(f"decision {got['decision']} != {exp['decision']}")
    if "http_status" in exp and got["status"] != exp["http_status"]:
        bad.append(f"status {got['status']} != {exp['http_status']}")
    for ev in exp.get("events", []):
        if ev not in got["events"]:
            bad.append(f"event {ev} not in {got['events']}")
    if "upstream_called" in exp and got["upstream_called"] != exp["upstream_called"]:
        bad.append(f"upstream_called {got['upstream_called']} != {exp['upstream_called']}")
    for k in ("judge_called", "degraded"):
        if k in exp and got.get(k) != exp[k]:
            bad.append(f"{k} {got.get(k)} != {exp[k]}")
    if exp.get("retry_after") and not (got["retry_after"] or "").isdigit():
        bad.append("missing Retry-After")
    return bad


@pytest.mark.parametrize("control,case", CASES, ids=[c["id"] for _, c in CASES])
async def test_case(control, case):
    got = await run_case(case)
    assert not matches(case, got), (case["id"], got)


@pytest.mark.parametrize("control,case", [x for x in CASES if x[1]["kind"] == "negative"],
                         ids=[c["id"] for _, c in CASES if c["kind"] == "negative"])
async def test_negative_case_fails_with_control_off(control, case):
    got = await run_case(case, control_off=True)
    assert matches(case, got), f"{case['id']} still matches with {control} off: the case proves nothing"


def test_every_control_has_allowed_and_blocked_case():
    kinds: dict[str, set] = {}
    for control, c in CASES:
        kinds.setdefault(control, set()).add(c["kind"])
    assert kinds and all(k == {"positive", "negative"} for k in kinds.values()), kinds

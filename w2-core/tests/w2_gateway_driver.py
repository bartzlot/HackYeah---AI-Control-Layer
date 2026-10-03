"""Drive one aicl-case/1 case through the REAL gateway in-process: ASGI transport, scripted cloud-sim
upstreams (external + local), the real decide() bound to the case's policy, audit records off the bus.

Paths: `llm` (messages -> request stage, upstream echo or scripted reply), `output` (input.response is the
scripted upstream reply -> response stage), `tool` / `mcp` with input.tool_calls (scripted upstream tool
calls -> tool_args stage). Cases that need a destination the gateway never routes (destination_class)
or a tool_result part are decide()-only.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

from aicl_contracts import Action, Event
from aicl_core.cases import DEFAULT_AGENT, Case, expand
from aicl_core.policy import Policy

LOCAL, EXTERNAL = "qwen3.5:2b-q4_K_M", "gpt-4o-mini"
KEY = "k-case"
GATEWAY_EVENT_CONTROLS = {"BUD-01"}


def gateway_path(case: Case) -> bool:
    s, inp = case.setup, case.input
    if s.get("destination_class") or "tool_result" in inp:
        return False
    if any(t.get("server") for t in inp.get("tool_calls") or []):
        return False            # MCP server identity does not exist on the OpenAI chat path
    return "messages" in inp or "response" in inp or "tool_calls" in inp


def _body(case: Case) -> dict:
    inp = case.input
    if "messages" in inp:
        msgs = [{**m, "content": expand(str(m.get("content", "")))} for m in inp["messages"]]
        msgs = [{k: v for k, v in m.items() if k != "trusted"} for m in msgs]
    else:
        msgs = [{"role": "user", "content": "continue"}]
    extra = {k: v for k, v in inp.items() if k not in ("messages", "response", "tool_calls", "tool_result")}
    return {"model": case.setup.get("destination", LOCAL), "messages": msgs, **extra}


def _steps(case: Case, repeat: int) -> list[dict] | None:
    inp, s = case.input, case.setup
    if "response" in inp:
        return [{"reply": expand(str(inp["response"]))} for _ in range(repeat)]
    calls = inp.get("tool_calls") or s.get("tool_calls")
    if calls:
        return [{"tool_calls": [{"name": t["name"], "arguments": t.get("arguments") or {}} for t in calls]}
                for _ in range(repeat)]
    return None


async def run_gateway_case(case: Case, policy: Policy, decide, *, control_off: bool = False) -> dict[str, Any]:
    from aicl_gateway import create_app
    from cloud_sim import Script, create_app as sim_app

    s = case.setup
    repeat = int(s.get("repeat", 1))
    steps = _steps(case, repeat)
    ext, loc = sim_app(Script(steps)), sim_app(Script(steps), {LOCAL: {"in": 0, "out": 0}})
    agent = s.get("agent", DEFAULT_AGENT)
    # models: None = the gateway routes any known tag and leaves the allowlist to decide() (ACCESS-01),
    # so the mutation test can see ACCESS-01 switched off
    cfg: dict[str, Any] = {"agents": {KEY: {"agent_id": agent, "models": None, "profile": case.profile}},
                           "audit_path": None, "budget_db": ":memory:"}   # never a shared file from the env
    gated = case.control == "BUD-01"
    cfg["budgets"] = {agent: s["budget"]} if gated and "budget" in s and not control_off else {}
    cfg["loop_limits"] = {"repeat_identical": 10_000 if (gated and control_off) else
                          int((policy.raw.get("loop_limits") or {}).get("repeat_identical", 4))}
    ups = {"external": httpx.AsyncClient(transport=httpx.ASGITransport(app=ext), base_url="http://ext"),
           "local": httpx.AsyncClient(transport=httpx.ASGITransport(app=loc), base_url="http://loc")}

    def bound(event: Event):
        return decide(event, policy=policy)

    app = create_app(bound, cfg, ups)
    if gated and s.get("spent") and not control_off:
        app.state.ledger.record(agent, int(s["spent"].get("tokens", 0)), float(s["spent"].get("usd", 0.0)))
    records: list[dict] = []
    app.state.bus.listeners.append(records.append)
    headers = {"authorization": f"Bearer {KEY}"}
    if s.get("session"):
        headers["x-session-id"] = s["session"]
    body = _body(case)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
            for _ in range(repeat):
                n_ext, n_loc, n_rec = len(ext.state.calls), len(loc.state.calls), len(records)
                r = await c.post("/v1/chat/completions", headers=headers, json=body)
    finally:
        for u in ups.values():
            await u.aclose()
    sent = ext.state.calls[n_ext:] + loc.state.calls[n_loc:]          # upstream bodies of the LAST request
    try:
        payload = r.json()
    except ValueError:
        payload = {}
    msg = ((payload.get("choices") or [{}])[0].get("message") or {}) if isinstance(payload, dict) else {}
    return {"status": r.status_code, "decision": r.headers.get("x-aicl-decision"),
            "retry_after": r.headers.get("retry-after"), "events": [x.get("event_type") for x in records[n_rec:]],
            "rule_ids": sorted({f.get("rule_id") for x in records[n_rec:] for f in x.get("findings") or []}),
            "upstream_called": bool(sent), "upstream_body": json.dumps(sent, ensure_ascii=False),
            "content": msg.get("content") or "", "tool_calls": msg.get("tool_calls") or [], "payload": payload}


def check_gateway(case: Case, got: dict) -> list[str]:
    e, bad = case.expect, []
    if "decision" in e:
        want = Action.parse(e["decision"])
        have = got["decision"]
        # LOG / WARN pass through like ALLOW at the HTTP level; the header carries the lattice verdict
        if have != want.name:
            bad.append(f"X-AICL-Decision {have} != {want.name}")
    if "http_status" in e and got["status"] != e["http_status"]:
        bad.append(f"status {got['status']} != {e['http_status']}")
    if case.control in GATEWAY_EVENT_CONTROLS:    # decide() controls name events per finding, the audit per record
        for ev in e.get("events") or []:
            if ev not in got["events"]:
                bad.append(f"event {ev} not in {got['events']}")
    for rid in e.get("rule_ids") or []:
        if rid not in got["rule_ids"]:
            bad.append(f"rule {rid} not in audited findings {got['rule_ids']}")
    if "upstream_called" in e and got["upstream_called"] != e["upstream_called"]:
        bad.append(f"upstream_called {got['upstream_called']} != {e['upstream_called']}")
    if e.get("retry_after") and not (got["retry_after"] or "").isdigit():
        bad.append("missing Retry-After")
    for k, where in (("upstream_body_contains", "upstream_body"), ("upstream_body_not_contains", "upstream_body")):
        for needle in ([e[k]] if isinstance(e.get(k), str) else e.get(k) or []):
            present = needle in got[where]
            if present != (k == "upstream_body_contains"):
                bad.append(f"{k} {needle!r}")
    return bad

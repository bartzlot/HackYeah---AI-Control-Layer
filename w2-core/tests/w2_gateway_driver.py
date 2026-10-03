"""Drive one aicl-case/1 case through the REAL gateway in-process: ASGI transport, scripted cloud-sim
upstreams (external + local), the real decide() bound to the case's policy, audit records off the bus.

Routing (gateway_path): `llm` (messages -> request stage, upstream echo or scripted reply), `output`
(input.response is the scripted upstream reply -> response stage), `tool` with input.tool_calls (scripted
upstream tool calls -> tool_args stage). decide()-only: `mcp` / `memory` paths (no MCP-proxy driver yet),
destination_class (a destination the gateway never routes), tool_result parts, MCP server identity, and
messages whose explicit `trusted` differs from what the gateway derives from the role.

Every expect key is either checked here or listed in DECIDE_ONLY_KEYS; an unknown key fails the case.
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
GATEWAY_CONTROLS = {"BUD-01"}          # enforced in the gateway itself (budget ledger, loop guard), not decide()
# per-finding detail the HTTP / audit surface does not carry (checked by the decide() runner only);
# `events` of decide() controls are finding-level names (DESTINATION_BLOCKED ...), the audit names records
DECIDE_ONLY_KEYS = {"would_decision", "events"}
GATEWAY_KEYS = {"decision", "http_status", "events", "rule_ids", "controls", "findings", "upstream_called",
                "retry_after", "upstream_body_contains", "upstream_body_not_contains", "redacted_contains",
                "redacted_not_contains"}


def gateway_path(case: Case) -> bool:
    s, inp = case.setup, case.input
    if case.path not in ("llm", "output", "tool"):
        return False
    if s.get("destination_class") or "tool_result" in inp:
        return False
    if any(t.get("server") for t in inp.get("tool_calls") or []):
        return False
    for m in inp.get("messages") or []:
        if "trusted" in m and bool(m["trusted"]) != (m.get("role", "user") != "tool"):
            return False
    return "messages" in inp or "response" in inp or "tool_calls" in inp


def _body(case: Case) -> dict:
    inp = case.input
    if "messages" in inp:
        msgs = [{k: v for k, v in m.items() if k != "trusted"} for m in inp["messages"]]
        msgs = [{**m, "content": expand(str(m.get("content", "")))} for m in msgs]
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
    gated = case.control in GATEWAY_CONTROLS
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
        app.state.ledger.close()          # ASGITransport runs no lifespan: release per-case resources here
        app.state.bus.close()
    sent = ext.state.calls[n_ext:] + loc.state.calls[n_loc:]          # upstream bodies of the LAST request
    try:
        payload = r.json()
    except ValueError:
        payload = {}
    msg = ((payload.get("choices") or [{}])[0].get("message") or {}) if isinstance(payload, dict) else {}
    findings = [f for x in records[n_rec:] for f in x.get("findings") or []]
    return {"status": r.status_code, "decision": r.headers.get("x-aicl-decision"),
            "retry_after": r.headers.get("retry-after"), "events": [x.get("event_type") for x in records[n_rec:]],
            "rule_ids": sorted({f.get("rule_id") for f in findings}),
            "controls": sorted({f.get("control_id") for f in findings}),
            "upstream_called": bool(sent), "upstream_body": json.dumps(sent, ensure_ascii=False),
            "content": msg.get("content") or "", "tool_calls": msg.get("tool_calls") or [], "payload": payload}


def _as_list(x) -> list:
    return [] if x is None else (x if isinstance(x, list) else [x])


def check_gateway(case: Case, got: dict) -> list[str]:
    """Failed expectations of `case` against one gateway run (empty = pass)."""
    e, bad = case.expect, []
    unknown = set(e) - GATEWAY_KEYS - DECIDE_ONLY_KEYS
    if unknown:
        bad.append(f"unknown expect keys {sorted(unknown)} (check them or list them as decide-only)")
    if "decision" in e:
        want = Action.parse(e["decision"]).name
        if got["decision"] != want:
            bad.append(f"X-AICL-Decision {got['decision']} != {want}")
    if "http_status" in e and got["status"] != e["http_status"]:
        bad.append(f"status {got['status']} != {e['http_status']}")
    if case.control in GATEWAY_CONTROLS:
        for ev in _as_list(e.get("events")):
            if ev not in got["events"]:
                bad.append(f"event {ev} not in {got['events']}")
    for rid in _as_list(e.get("rule_ids")):
        if rid not in got["rule_ids"]:
            bad.append(f"rule {rid} not in audited findings {got['rule_ids']}")
    for cid in _as_list(e.get("controls")):
        if cid not in got["controls"]:
            bad.append(f"control {cid} not in audited findings {got['controls']}")
    if e.get("findings") == [] and got["rule_ids"]:
        bad.append(f"expected no findings, audit has {got['rule_ids']}")
    if "upstream_called" in e and got["upstream_called"] != e["upstream_called"]:
        bad.append(f"upstream_called {got['upstream_called']} != {e['upstream_called']}")
    if e.get("retry_after") and not (got["retry_after"] or "").isdigit():
        bad.append("missing Retry-After")
    for needle in _as_list(e.get("upstream_body_contains")):
        if needle not in got["upstream_body"]:
            bad.append(f"upstream body lacks {needle!r}")
    for needle in _as_list(e.get("upstream_body_not_contains")):
        if needle in got["upstream_body"]:
            bad.append(f"upstream body still has {needle!r}")
    # redaction proof: what the client gets back (output path) or what left for the model (request path)
    where = "content" if case.path == "output" else "upstream_body"
    if (e.get("redacted_contains") or e.get("redacted_not_contains")) and got["status"] == 200:
        for needle in _as_list(e.get("redacted_contains")):
            if needle not in got[where]:
                bad.append(f"{where} lacks redacted {needle!r}")
        for needle in _as_list(e.get("redacted_not_contains")):
            if needle in got[where]:
                bad.append(f"{where} still has {needle!r}")
    # tool path: a blocked proposal never reaches the client; an allowed one does
    if case.path == "tool" and "tool_calls" in case.input and got["status"] == 200:
        blocked = got["decision"] == "BLOCK"
        if blocked and (got["tool_calls"] or "was blocked" not in got["content"]):
            bad.append("BLOCK verdict but the tool call was still returned to the client")
        if not blocked and not got["tool_calls"]:
            bad.append("tool call allowed but missing from the response")
    if case.kind == "negative" and "decision" not in e and "http_status" not in e:
        if got["decision"] not in ("REDACT", "BLOCK"):
            bad.append("negative case was not blocked or redacted")
    return bad

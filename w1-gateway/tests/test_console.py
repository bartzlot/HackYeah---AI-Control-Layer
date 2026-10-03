import csv
import io
import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from aicl_gateway.console_api import FIXTURES, ConsoleStore, make_console_router, store_with_fixtures

ROOT = Path(__file__).resolve().parents[2]


def make():
    store = store_with_fixtures()
    app = FastAPI()
    app.include_router(make_console_router(store))
    return store, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://c")


def fixture_records():
    return [json.loads(x) for x in FIXTURES.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_fixtures_valid_audit_records():
    from aicl_contracts import AuditRecord
    recs = fixture_records()
    assert len(recs) >= 30
    for r in recs:
        AuditRecord.model_validate(r)


async def test_summary_matches_fixtures():
    store, c = make()
    recs = fixture_records()
    final = {}
    for r in recs:
        final[r["request_id"]] = max(final.get(r["request_id"], 0), r["decision"])
    s = (await c.get("/console/api/summary")).json()
    assert s["requests"] == len(final)
    assert s["blocked"] == sum(v == 4 for v in final.values()) > 0
    assert s["redacted"] == sum(v == 3 for v in final.values()) > 0
    assert s["requests"] == s["blocked"] + s["redacted"] + s["allowed"]
    assert s["cost_usd"] == pytest.approx(sum(r["usage"]["usd"] for r in recs), abs=1e-6)
    assert s["tokens"] == sum(r["usage"]["input_tokens"] + r["usage"]["output_tokens"] for r in recs)
    assert s["posture_pct"] == round(100 * s["controls_enforced"] / s["controls_total"], 1)
    assert 0 < s["budget_used_pct"] < 100


def test_final_decision_is_max_over_request_records():
    store = ConsoleStore()
    store.append({"request_id": "r1", "stage": "prompt", "decision": 0, "ts": "t"})
    store.append({"request_id": "r1", "stage": "tool_args", "decision": 4, "ts": "t"})
    store.append({"request_id": "r2", "stage": "prompt", "decision": 3, "ts": "t"})
    s = store.summary()
    assert (s["requests"], s["blocked"], s["redacted"], s["allowed"]) == (2, 1, 1, 0)


def load_policy():
    import yaml
    return yaml.safe_load((ROOT / "policy" / "policy.yaml").read_text(encoding="utf-8"))


POLICY = {   # fixed fixture in the shape of policy/policy.yaml (the shared file changes as pieces land)
    "defaults": {"profile": "balanced", "mode": "enforce"},
    "controls": {
        "DLP-01": {"mode": "enforce", "action": {"prompt": "REDACT", "tool_args": "BLOCK"}},
        "DLP-02": {"mode": "enforce"},
        "DLP-05": {"mode": "enforce"},
        "INJ-03": {"mode": "enforce"},
        "INJ-04": {"mode": {"strict": "enforce", "balanced": "enforce", "permissive": "shadow"}},
        "TOOL-01": {"mode": "enforce", "default": "BLOCK"},
        "BUD-01": {"fail": "closed"},                 # no mode -> defaults.mode
    },
    "budgets": {"org": {"usd": 5.0}},
}


def test_controls_and_budget_follow_policy():
    import copy
    pol = copy.deepcopy(POLICY)
    store = ConsoleStore(policy=lambda: pol)
    rows = {r["id"]: r for r in store.control_rows()}
    assert set(rows) == set(pol["controls"])
    assert rows["INJ-04"]["mode"] == "enforce" and rows["BUD-01"]["mode"] == "enforce"
    assert rows["DLP-01"]["action"] == "BLOCK/REDACT"     # per-stage action map
    assert rows["TOOL-01"]["action"] == "BLOCK"           # default deny
    assert store.budget_usd == 5.0
    assert store.summary()["posture_pct"] == 100.0
    pol["controls"]["DLP-05"]["mode"] = False             # bare `off` read by YAML 1.1
    pol["controls"]["INJ-03"]["mode"] = "shadow"
    del pol["controls"]["BUD-01"]                         # removed control stays in the denominator
    rows = {r["id"]: r for r in store.control_rows()}
    assert (rows["DLP-05"]["mode"], rows["INJ-03"]["mode"], rows["BUD-01"]["mode"]) == ("off", "shadow", "off")
    s = store.summary()
    assert (s["controls_total"], s["controls_enforced"], s["posture_pct"]) == (7, 4, round(400 / 7, 1))
    pol["defaults"]["profile"] = "permissive"
    assert {r["id"]: r for r in store.control_rows()}["INJ-04"]["mode"] == "shadow"


def test_real_policy_file_drives_the_console():
    pol = load_policy() or {}
    controls, org = pol.get("controls"), (pol.get("budgets") or {}).get("org") or {}
    if not isinstance(controls, dict) or "usd" not in org:
        pytest.skip("shared policy.yaml has no controls / budgets.org.usd right now")
    store = ConsoleStore(policy=pol)
    assert set(controls) <= {r["id"] for r in store.control_rows()}
    assert 0 <= store.summary()["posture_pct"] <= 100
    assert store.budget_usd == float(org["usd"])


async def test_events_controls_and_pages():
    _, c = make()
    ev = (await c.get("/console/api/events?limit=5")).json()["events"]
    assert len(ev) == 5 and ev[0]["ts"] >= ev[-1]["ts"]
    ctl = (await c.get("/console/api/controls")).json()["controls"]
    assert {x["id"]: x["hits"] for x in ctl}["DLP-02"] == 3
    html = await c.get("/console")
    assert html.status_code == 200 and "AI Control Layer" in html.text
    assert (await c.get("/console/static/app.js")).status_code == 200
    assert (await c.get("/console/static/fixtures.jsonl")).status_code == 404
    assert (await c.get("/console/static/..%2Fconsole_api.py")).status_code == 404


async def test_exports():
    _, c = make()
    j = await c.get("/console/api/export.jsonl")
    lines = [json.loads(x) for x in j.text.splitlines()]
    assert lines == fixture_records()
    r = await c.get("/console/api/export.csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == len(lines)
    assert "PL_PESEL" not in r.text and rows[0]["event_id"] == lines[0]["event_id"]
    assert {x["decision"] for x in rows} >= {"ALLOW", "REDACT", "BLOCK"}
    assert any(x["controls"] == "TOOL-01" and x["tool"] == "shell.exec" for x in rows)


async def test_sse_first_event_and_live_append():
    store, c = make()
    r = await c.get("/console/api/stream?replay=1&max_events=1")
    assert r.headers["content-type"].startswith("text/event-stream")
    data = [x for x in r.text.splitlines() if x.startswith("data: ")]
    assert json.loads(data[0][6:])["event_id"] == fixture_records()[-1]["event_id"]


async def test_store_subscribe_and_append():
    store = ConsoleStore()
    q = store.subscribe()
    store.append({"event_id": "x", "stage": "prompt", "decision": "ALLOW", "ts": "2026-01-01T00:00:00Z"})
    assert (await q.get())["event_id"] == "x"
    assert store.summary()["requests"] == 1
    store.unsubscribe(q)


async def test_events_filter_by_request_id():
    _, c = make()
    ev = (await c.get("/console/api/events?request_id=req-0014")).json()["events"]
    assert [e["request_id"] for e in ev] == ["req-0014"]


async def test_gateway_feeds_console_end_to_end():
    """A real gateway request shows up in the console: tiles, explain lookup by request id, SSE, export."""
    from aicl_contracts import Action, Decision, Finding, Redaction, Stage
    from aicl_gateway import create_app
    from cloud_sim import Script, create_app as sim_app

    def decide(ev):
        if ev.stage == Stage.PROMPT and "AKIA" in ev.parts[0].text:
            i = ev.parts[0].text.index("AKIA")
            return Decision(action=Action.REDACT, explain=["DLP-01 AWS key -> REDACT"],
                            findings=[Finding(control_id="DLP-01", rule_id="aws_access_key", category="secret",
                                              action=Action.REDACT)],
                            redactions=[Redaction(part=0, start=i, end=i + 20, replacement="[REDACTED_AWS_KEY]")])
        return Decision()

    ext = httpx.AsyncClient(transport=httpx.ASGITransport(app=sim_app(Script())), base_url="http://ext")
    app = create_app(decide, {"agents": {"k-demo": {"agent_id": "demo"}},
                              "console": {"demo_key": "k-demo", "policy": lambda: POLICY}}, {"external": ext})
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://g")
    r = await c.post("/v1/chat/completions", headers={"authorization": "Bearer k-demo"},
                     json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]})
    assert r.status_code == 200 and r.headers["x-aicl-decision"] == "REDACT"
    rid = r.headers["x-aicl-request-id"]
    s = (await c.get("/console/api/summary")).json()
    assert (s["requests"], s["redacted"], s["blocked"]) == (1, 1, 0) and s["cost_usd"] > 0
    assert s["budget_usd"] == 5.0 and s["posture_pct"] == 100.0
    ev = (await c.get(f"/console/api/events?request_id={rid}")).json()["events"]
    assert [e["stage"] for e in ev] == ["response", "prompt"]
    assert ev[1]["findings"][0]["control_id"] == "DLP-01" and "DLP-01 AWS key -> REDACT" in ev[1]["explain"]
    assert "AKIAIOSFODNN7EXAMPLE" not in (await c.get("/console/api/export.jsonl")).text
    assert "AKIAIOSFODNN7EXAMPLE" not in (await c.get("/console/api/export.csv")).text
    sse = await c.get("/console/api/stream?replay=2&max_events=2")
    assert [json.loads(x[6:])["request_id"] for x in sse.text.splitlines() if x.startswith("data: ")] == [rid, rid]
    pg = (await c.get("/console/api/playground")).json()          # ASGITransport client = 127.0.0.1
    assert pg["api_key"] == "k-demo" and "gpt-4o-mini" in pg["models"]["external"]
    far = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("203.0.113.7", 5000)), base_url="http://g")
    for path in ("/console/api/playground", "/console/api/export.jsonl", "/console/api/events", "/console"):
        assert (await far.get(path)).status_code == 403                       # host-only by default
    assert (await c.get("/console/api/playground", headers={"x-forwarded-for": "203.0.113.7"})).status_code == 403
    d = await c.post("/v1/chat/completions", headers={"authorization": "Bearer k-demo"},
                     json={"model": "unknown-model", "messages": [{"role": "user", "content": "hi"}]})
    assert d.status_code == 403 and d.headers["x-aicl-decision"] == "BLOCK"
    assert "x-aicl-decision" not in (await c.post("/v1/chat/completions", json={})).headers
    ctl = {x["id"]: x["hits"] for x in (await c.get("/console/api/controls")).json()["controls"]}
    assert ctl["DLP-01"] == 1


async def test_console_remote_mode_and_upstream_failure_header():
    from aicl_gateway import create_app

    def down(request):
        raise httpx.ConnectError("down")

    ext = httpx.AsyncClient(transport=httpx.MockTransport(down), base_url="http://ext")
    app = create_app(None, {"agents": {"k": {"agent_id": "a"}}, "console": {"remote": True, "demo_key": "k"}},
                     {"external": ext})
    far = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("203.0.113.7", 5000)), base_url="http://g")
    assert (await far.get("/console/api/playground")).json()["api_key"] == "k"
    r = await far.post("/v1/chat/completions", headers={"authorization": "Bearer k"},
                       json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 502 and "x-aicl-decision" not in r.headers and r.headers["x-aicl-request-id"]


def test_csv_formula_injection_guard():
    from aicl_gateway.console_api import _csv_row
    row = _csv_row({"model": "=HYPERLINK(\"http://x\")", "tool": "@SUM(1)", "agent_id": "ok"})
    assert row[10].startswith("'=") and row[12].startswith("'@") and row[9] == "ok"

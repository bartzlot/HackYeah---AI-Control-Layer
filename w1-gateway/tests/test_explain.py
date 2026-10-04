"""T-119 console explain drawer: per-request decide() timeline (identity -> model + budget -> DLP -> INJ-03 ->
INJ-04 judge -> TOOL-01 -> final action on the lattice), per-stage latency (same numbers as the Server-Timing
entries), spans as hashes / redaction tokens only. In-process only: no sockets, no Ollama.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from fastapi import FastAPI

from aicl_gateway.console_api import make_console_router, store_with_fixtures
from aicl_gateway.explain import LATTICE, add_latency, stage_timing, timeline
from aicl_gateway.mock_providers import AWS_EXAMPLE

from test_passthrough import cc_body, post, rig  # noqa: F401 - rig is a pytest fixture

CONSOLE = Path(__file__).resolve().parents[1] / "aicl_gateway" / "console"
STAGE_IDS = ["identity", "model_budget", "dlp", "inj03", "inj04", "tool"]


def span(t, s, e, h, part=0):
    return {"part": part, "start": s, "end": e, "type": t, "sha256_8": h}


def request_records() -> list[dict]:
    """One request: prompt (secret + PII redacted), response (judge WARN), tool_args (TOOL-01 BLOCK)."""
    base = {"request_id": "req-x", "agent_id": "demo-dev", "client_ip": "10.77.0.10", "credential_hash": "ab12cd34",
            "user_agent": "claude-cli/2.1.289", "model": "claude-sonnet-5-5", "destination": "external",
            "protocol": "anthropic_messages", "upstream_host": "api.anthropic.com", "policy_version": "f" * 64}
    return [
        {**base, "event_id": "e3", "ts": "2026-10-04T08:00:03Z", "stage": "tool_args", "decision": 4,
         "would_decision": 4, "event_type": "TOOL_CALL_BLOCKED",
         "latency_us": {"KILL-01": 2, "ACCESS-01": 3, "TOOL-01": 400, "total": 450},
         "findings": [{"control_id": "TOOL-01", "rule_id": "tool.shell.pipe_to_shell", "category": "tool_abuse",
                       "action": 4, "reason_code": "curl | sh", "spans": [], "detail": {}}]},
        {**base, "event_id": "e1", "ts": "2026-10-04T08:00:01Z", "stage": "prompt", "decision": 3,
         "would_decision": 3, "event_type": "SECRET_DETECTED",
         "latency_us": {"KILL-01": 5, "ACCESS-01": 7, "DLP-01": 300, "DLP-02": 120, "DLP-05": 30,
                        "INJ-03": 90, "total": 600},
         "findings": [
             {"control_id": "DLP-01", "rule_id": "secret.aws_access_key", "category": "secret", "action": 3,
              "spans": [span("AWS_KEY", 10, 30, "deadbeef")], "detail": {}},
             {"control_id": "DLP-02", "rule_id": "pii.pl_pesel", "category": "pii", "action": 3,
              "spans": [span("PL_PESEL", 40, 51, "cafebabe")], "detail": {"placeholder": "numbered"}}]},
        {**base, "event_id": "e2", "ts": "2026-10-04T08:00:02Z", "stage": "response", "decision": 2,
         "would_decision": 2, "event_type": "REQUEST_ALLOWED", "degraded": False,
         "latency_us": {"INJ-04": 2500, "total": 2600},
         "findings": [{"control_id": "INJ-04", "rule_id": "judge.suspicious", "category": "injection", "action": 2,
                       "score": 0.61, "threshold": 0.85, "spans": [],
                       "detail": {"model": "qwen3.5:2b-q4_K_M", "cached": True, "eval_ms": 812}}]},
    ]


def test_timeline_orders_the_pipeline_and_ends_on_the_lattice():
    t = timeline(request_records())
    assert [s["id"] for s in t["stages"]] == STAGE_IDS                    # "other" omitted when unused
    assert t["records"] == 3 and t["record_stages"] == ["prompt", "response", "tool_args"]
    st = {s["id"]: s for s in t["stages"]}
    assert st["identity"]["ran"] == ["KILL-01", "ACCESS-01"] and st["identity"]["latency_ms"] == 0.017
    mb = st["model_budget"]       # BUD-01 / allowlist run in the gateway ledger, outside decide(): a note, no latency
    assert mb["ran"] == [] and mb["action"] == "ALLOW" and "budget ledger" in mb["note"]
    assert st["dlp"]["action"] == "REDACT" and st["dlp"]["latency_ms"] == 0.45
    assert st["inj03"]["action"] == "ALLOW" and st["inj03"]["findings"] == []
    assert st["inj04"]["action"] == "WARN"
    assert st["inj04"]["findings"][0]["judge"] == {"model": "qwen3.5:2b-q4_K_M", "verdict": "suspicious",
                                                  "cached": True, "eval_ms": 812, "degraded": False}
    assert st["tool"]["action"] == "BLOCK" and st["tool"]["findings"][0]["record_stage"] == "tool_args"
    f = t["final"]
    assert f["action"] == "BLOCK" and f["lattice"] == LATTICE == ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"]
    assert f["by"] == {"control_id": "TOOL-01", "rule_id": "tool.shell.pipe_to_shell", "stage": "tool"}
    assert t["latency_ms"]["decide_total"] == 3.65
    assert t["identity"]["principal"] == "demo-dev" and t["model"]["upstream_host"] == "api.anthropic.com"
    assert t["server_timing"] == ("identity;dur=0.02, dlp;dur=0.45, inj03;dur=0.09, inj04;dur=2.50, tool;dur=0.40, "
                                  "decide;dur=3.65")


def test_spans_are_hashes_and_redaction_tokens_only():
    t = timeline(request_records())
    dlp = next(s for s in t["stages"] if s["id"] == "dlp")
    spans = [s for f in dlp["findings"] for s in f["spans"]]
    assert [s["token"] for s in spans] == ["[REDACTED_AWS_KEY]", "[PL_PESEL_1]"]
    assert all(set(s) == {"part", "start", "end", "type", "sha256_8", "token"} for s in spans)
    blocked = timeline([{**request_records()[1], "findings": [{**request_records()[1]["findings"][0], "action": 4}]}])
    s = next(x for x in blocked["stages"] if x["id"] == "dlp")["findings"][0]["spans"][0]
    assert s["token"] is None and s["sha256_8"] == "deadbeef"          # BLOCK replaces nothing: hash only


def test_shadow_findings_never_set_the_stage_action_or_the_final_cause():
    """permissive profile runs INJ-04 in shadow: shown with its would-be action, the request stays ALLOW."""
    rec = {"event_id": "s", "request_id": "r", "ts": "t", "stage": "prompt", "decision": 0, "would_decision": 4,
           "event_type": "REQUEST_ALLOWED", "latency_us": {"INJ-04": 900, "total": 950},
           "explain": ["policy x", "INJ-04 rule judge.malicious: BLOCK - local judge (shadow: not enforced)",
                       "decision ALLOW (would be BLOCK without shadow mode)"],
           "findings": [{"control_id": "INJ-04", "rule_id": "judge.malicious", "category": "injection", "action": 4,
                         "spans": [span("TEXT", 0, 9, "0badf00d")], "detail": {"model": "m"}}]}
    t = timeline([rec])
    inj = next(s for s in t["stages"] if s["id"] == "inj04")
    assert inj["action"] == "ALLOW" and inj["findings"][0]["shadow"] is True
    assert inj["findings"][0]["spans"][0]["token"] is None
    assert t["final"]["action"] == "ALLOW" and t["final"]["would"] == "BLOCK" and t["final"]["by"] is None


def test_tokens_follow_the_engine_numbering_and_merging():
    """Two PESELs: numbered in reading order across findings, the same value keeps its number."""
    pesel = {"control_id": "DLP-02", "rule_id": "pii.pl_pesel", "category": "pii", "action": 3,
             "detail": {"placeholder": "numbered"}}
    rec = {"event_id": "p", "request_id": "r", "ts": "t", "stage": "prompt", "decision": 3, "event_type": "PII_REDACTED",
           "findings": [{**pesel, "spans": [span("PL_PESEL", 50, 61, "bbbb")]},
                        {**pesel, "spans": [span("PL_PESEL", 5, 16, "aaaa"), span("PL_PESEL", 80, 91, "bbbb")]}]}
    dlp = next(s for s in timeline([rec])["stages"] if s["id"] == "dlp")
    toks = [s["token"] for f in dlp["findings"] for s in f["spans"]]
    assert toks == ["[PL_PESEL_2]", "[PL_PESEL_1]", "[PL_PESEL_2]"]


def test_stage_not_run_unknown_control_and_denied_records():
    t = timeline([{"event_id": "d", "request_id": "r", "ts": "t", "stage": "prompt", "decision": 4,
                   "event_type": "MODEL_DENIED", "findings": [], "explain": ["model gpt-x not allowed"],
                   "latency_us": {"NET-99": 4}}])
    st = {s["id"]: s for s in t["stages"]}
    assert st["dlp"]["ran"] == [] and st["dlp"]["findings"] == []
    assert st["other"]["ran"] == ["NET-99"]
    mb = st["model_budget"]
    assert mb["action"] == "BLOCK" and mb["findings"][0]["rule_id"] == "MODEL_DENIED"
    assert mb["findings"][0]["reason_code"] == "model gpt-x not allowed"
    assert t["final"]["action"] == "BLOCK" and t["final"]["by"]["stage"] == "model_budget"
    assert timeline([]) == {"records": 0, "stages": [], "final": None}


def test_stage_timing_is_server_timing_syntax_in_pipeline_order():
    acc: dict[str, int] = {}
    add_latency(acc, {"TOOL-01": 7, "DLP-02": 20, "KILL-01": 10, "DLP-01": 300, "total": 999, "X-1": 7})
    add_latency(acc, None)
    assert stage_timing(acc) == "identity;dur=0.01, dlp;dur=0.32, tool;dur=0.01, other;dur=0.01"
    assert stage_timing({}) == ""


async def test_console_explain_route_groups_the_request_and_404s_unknown_ids():
    app = FastAPI()
    app.include_router(make_console_router(store_with_fixtures()))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://c") as c:
        t = (await c.get("/console/api/explain/evt-0007")).json()
        assert (await c.get("/console/api/explain/nope")).status_code == 404
    assert t["event_id"] == "evt-0007" and t["request_id"] == "req-0007"
    dlp = next(s for s in t["stages"] if s["id"] == "dlp")
    assert dlp["findings"][0]["rule_id"] == "secret.aws_access_key" and t["final"]["action"] == "BLOCK"


async def test_live_request_timeline_and_server_timing_without_raw_text(rig):  # noqa: F811
    """Real policy + engine + passthrough: the redacted secret shows as its token and hash, never as text."""
    app, c, _, _ = rig()
    r = await post(c, cc_body(f"deploy with key {AWS_EXAMPLE} please"))
    assert r.status_code == 200
    timing = r.headers["server-timing"]
    assert timing.startswith("aicl;dur=") and "identity;dur=" in timing and "dlp;dur=" in timing
    assert timing.index("dlp;dur=") < timing.index("upstream;dur=") < timing.index("total;dur=")
    rec = next(x for x in reversed(app.state.bus.recent(500))
               if x["stage"] == "prompt" and any(f["control_id"] == "DLP-01" for f in x["findings"]))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:18080") as con:
        resp = await con.get(f"/console/api/explain/{rec['event_id']}")
    assert resp.status_code == 200
    t = resp.json()
    assert AWS_EXAMPLE not in json.dumps(t)
    dlp = next(s for s in t["stages"] if s["id"] == "dlp")
    f = next(x for x in dlp["findings"] if x["control_id"] == "DLP-01")
    assert f["spans"] and all(s["sha256_8"] for s in f["spans"])
    if f["action"] == "REDACT":
        assert f["spans"][0]["token"].startswith("[")
    assert dlp["latency_ms"] > 0 and "DLP-01" in dlp["ran"]
    assert [s["id"] for s in t["stages"]][:3] == ["identity", "model_budget", "dlp"]


def test_drawer_renders_the_timeline_and_links_rules_to_the_policy_page():
    js = (CONSOLE / "app.js").read_text(encoding="utf-8")
    assert 'API + "/explain/" + encodeURIComponent(r.event_id)' in js
    assert 'class="rulelink"' in js and "pendingRule = { rule: a.dataset.rule" in js and "markPolicy();" in js
    assert "Stage timing, whole request: " in js and "shadow, not enforced" in js
    css = (CONSOLE / "style.css").read_text(encoding="utf-8")
    assert ".tl-step.a-BLOCK .tl-dot" in css and "mark.hit" in css

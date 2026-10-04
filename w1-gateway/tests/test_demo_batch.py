"""T-123 demo batch, offline: the preset prompts through the policy-driven gateway (real policy.yaml, w2 engine) with
a fake Ollama (zero-priced cloud-sim), the scripted cloud-sim and a fake judge; the results table says which control
caught each prompt, with which rule, on which detection layer."""
import asyncio
import importlib.util
import json
from pathlib import Path

import httpx
import pytest
import yaml

from aicl_gateway import demo_batch as db
from aicl_gateway.demo_agent import LOCAL
from aicl_gateway.main import create_app_from_env
from aicl_gateway.names import Catalog, enrich, layer_of, record_layer
from cloud_sim import create_app as sim_app
from cloud_sim.app import load_script

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "policy" / "policy.yaml"
KEY = "aicl_demo_0123456789abcdef"
LOCALHOST = ("127.0.0.1", 5000)


def judge_reply(verdict="malicious", level="high"):
    def chat(body, timeout):
        chat.calls.append(body)
        return {"message": {"content": json.dumps({"prompt_injection": level, "data_exfiltration": "none",
                                                   "jailbreak": "none", "tool_abuse": "none", "verdict": verdict})}}
    chat.calls = []
    return chat


@pytest.fixture
def rig(tmp_path):
    from aicl_core import engine as eng

    def make(judge=None, env_extra=None):
        ollama = sim_app(load_script(None), {LOCAL: {"in": 0.0, "out": 0.0}})
        cloud = sim_app(load_script("demo"))
        env = {"AICL_POLICY": str(POLICY), "AICL_KEY_DEMO": KEY, "AICL_DATA_DIR": str(tmp_path / "data"),
               "AICL_AUDIT_PATH": str(tmp_path / "data" / "audit.jsonl"), "AICL_BUDGET_DB": str(tmp_path / "data" / "budget.db"),
               "AICL_UPSTREAM_KEY_EXTERNAL": "sk-cloudsim-demo", **(env_extra or {})}
        ups = {"local": httpx.AsyncClient(transport=httpx.ASGITransport(app=ollama), base_url="http://ollama"),
               "external": httpx.AsyncClient(transport=httpx.ASGITransport(app=cloud), base_url="http://cloud")}
        app = create_app_from_env(env, upstreams=ups, judge_chat=judge or judge_reply(), reload_interval=0.0, start_reload=False)
        return app, ollama, cloud

    yield make
    eng.REGISTRY.pop("INJ-04", None)


async def run(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
        return await db.run_batch(c, KEY, lambda rid: app.state.console.list(100, rid), catalog=app.state.console.catalog())


def bodies(sim) -> str:
    return json.dumps(sim.state.calls, ensure_ascii=False)


# what each preset must show: (outcome, control, rule, layer)
EXPECTED = {
    "B1": ("allowed", None, None, None),
    "B2": ("redacted", "DLP-01", "AWS_KEY", "deterministic"),
    "B3": ("redacted", "DLP-02", "PL_PESEL", "deterministic"),
    "B4": ("blocked", "DLP-05", "matrix.confidential.external", "deterministic"),
    "B5": ("blocked", "INJ-03", "INJ-IND-001", "deterministic"),
    "B6": ("blocked", "INJ-03", "INJ-PE-002", "deterministic"),
    "B7": ("blocked", "TOOL-01", "tool.not_allowed", "deterministic"),
    "B8": ("blocked", "TOOL-01", "CODE-AG-002", "deterministic"),
    "B9": ("blocked", "INJ-04", "judge.malicious", "ai"),
    "B10": ("blocked", "ACCESS-01", "MODEL_DENIED", "deterministic"),
    "B11": ("blocked", "BUD-01", "loop.repeat_identical", "deterministic"),
}


async def test_every_preset_is_caught_by_its_control_and_layer(rig):
    app, _, _ = rig()
    res = await run(app)
    got = {r["id"]: (r["outcome"], r["control"], r["rule"], r["layer"]) for r in res["rows"]}
    assert got == EXPECTED
    assert all(r["ok"] for r in res["rows"])
    assert {p.control for p in db.PRESETS} - {"-"} >= {"DLP-01", "DLP-02", "DLP-05", "INJ-03", "INJ-04", "TOOL-01", "ACCESS-01", "BUD-01"}


async def test_secrets_never_reach_an_upstream_unredacted(rig):
    app, ollama, cloud = rig()
    await run(app)
    seen = bodies(ollama) + bodies(cloud)
    for p in db.PRESETS:
        if p.leak:
            assert p.leak not in seen, p.id
    assert "[REDACTED_AWS_KEY]" in bodies(ollama) and "[PL_PESEL_1]" in bodies(cloud)


async def test_the_judge_runs_only_for_the_gray_band_prompt(rig):
    judge = judge_reply()
    app, _, _ = rig(judge=judge)
    res = await run(app)
    assert len(judge.calls) == 1                        # clean traffic and every deterministic catch never reach the model
    b9 = next(r for r in res["rows"] if r["id"] == "B9")
    assert b9["judge"]["model"] == LOCAL and b9["judge"]["verdict"] == "malicious" and b9["judge"]["confidence"] == 0.9
    assert b9["judge_ms"] is not None
    assert all(r["judge"] is None and r["judge_ms"] is None for r in res["rows"] if r["id"] != "B9")


async def test_a_cached_judge_verdict_costs_no_judge_time(rig):
    judge = judge_reply()
    app, _, _ = rig(judge=judge)
    first, second = await run(app), await run(app)
    b9 = [next(r for r in res["rows"] if r["id"] == "B9") for res in (first, second)]
    assert len(judge.calls) == 1                                  # the second batch is answered from the verdict cache
    assert b9[0]["judge"]["cached"] is False and b9[1]["judge"]["cached"] is True
    assert b9[1]["judge_ms"] == 0.0 and b9[1]["outcome"] == "blocked" and b9[1]["layer"] == "ai"


async def test_a_judge_timeout_is_a_degraded_warn_not_a_failure(rig):
    def dead(body, timeout):
        raise TimeoutError("fake judge timeout")
    app, _, _ = rig(judge=dead)
    res = await run(app)
    b9 = next(r for r in res["rows"] if r["id"] == "B9")
    assert b9["outcome"] == "warned" and b9["ok"] and b9["layer"] == "ai"
    assert b9["judge"]["degraded"] is True and b9["rule"] == "judge.unavailable"


async def test_summary_has_percentiles_throughput_and_layer_split(rig):
    app, _, _ = rig()
    res = await run(app)
    s = res["summary"]
    assert s["prompts"] == len(db.PRESETS) == 11 and s["passed"] == 11
    assert s["requests"] == 10 + 4          # ten single calls and the burst: the loop guard trips on the 4th identical call
    assert 0 < s["decide_ms"]["p50"] <= s["decide_ms"]["p95"]
    assert s["throughput_rps"] > 0 and s["wall_s"] > 0
    assert s["by_layer"] == {"deterministic": 9, "ai": 1}
    assert s["by_outcome"] == {"allowed": 1, "warned": 0, "redacted": 2, "blocked": 8, "error": 0}
    assert s["judge_ms"]["count"] == 1


async def test_rows_carry_display_names_and_the_terminal_table_lists_them(rig):
    app, _, _ = rig()
    res = await run(app)
    b2 = next(r for r in res["rows"] if r["id"] == "B2")
    assert b2["control_name"] == "Secret leak (API keys, tokens)" and b2["rule_name"] == "AWS access key"
    assert b2["layer_label"] == "DETERMINISTIC"
    text = db.render(res)
    assert "DLP-01 / AWS_KEY" in text and "AI" in text and "11/11 as expected" in text and "req/s" in text


def test_outcome_split_and_percentiles():
    assert db.outcome_of(200, "ALLOW") == "allowed" and db.outcome_of(200, "WARN") == "warned"
    assert db.outcome_of(200, "REDACT") == "redacted" and db.outcome_of(403, None) == "blocked"
    assert db.outcome_of(502, None) == "error" and db.outcome_of(200, "BLOCK") == "blocked"
    assert db.pct([], 0.5) == 0.0 and db.pct([1, 2, 3, 4, 100], 0.5) == 3 and db.pct([1, 2, 3, 4, 100], 0.95) == 100


async def test_an_unreachable_gateway_is_an_error_row_not_a_crash():
    def refuse(request):
        raise httpx.ConnectError("down")
    async with httpx.AsyncClient(transport=httpx.MockTransport(refuse), base_url="http://gw") as c:
        res = await db.run_batch(c, KEY, lambda rid: [], presets=db.PRESETS[:2])
    assert [r["outcome"] for r in res["rows"]] == ["error", "error"] and not any(r["ok"] for r in res["rows"])
    assert res["summary"]["passed"] == 0


# ---- console endpoints ------------------------------------------------------------------------------

async def test_console_runs_the_batch_and_lists_presets_and_names(rig):
    app, _, _ = rig()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=LOCALHOST), base_url="http://gw") as c:
        presets = (await c.get("/console/api/demo/presets")).json()["presets"]
        assert [p["id"] for p in presets] == [p.id for p in db.PRESETS]
        res = (await c.post("/console/api/demo/batch")).json()
        assert res["summary"]["passed"] == 11 and {r["id"]: r["control"] for r in res["rows"]}["B8"] == "TOOL-01"
        # the batch is audited like any traffic: the live feed shows who caught it
        ev = (await c.get("/console/api/events?limit=500")).json()["events"]
        assert {e["detection_layer"] for e in ev if e.get("detection_layer")} == {"deterministic", "ai"}
        s = (await c.get("/console/api/summary")).json()
        assert s["by_layer"]["ai"] == 1 and s["by_layer"]["deterministic"] >= 9
        assert s["top_rules"] and all(t["rule_name"] and t["layer"] in ("deterministic", "ai") for t in s["top_rules"])


async def test_console_refuses_a_second_concurrent_batch(rig):
    app, _, _ = rig()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=LOCALHOST), base_url="http://gw") as c:
        r1, r2 = await asyncio.gather(c.post("/console/api/demo/batch"), c.post("/console/api/demo/batch"))
    assert sorted([r1.status_code, r2.status_code]) == [200, 409]


async def test_console_batch_without_a_demo_key_says_so(tmp_path):
    from aicl_gateway import create_app
    app = create_app(config={"audit_path": None, "console": {"demo_key": None}})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=LOCALHOST), base_url="http://gw") as c:
        r = await c.post("/console/api/demo/batch")
    assert r.status_code == 409 and "demo key" in r.json()["detail"]


async def test_the_batch_and_the_catalog_are_host_only(rig):
    app, _, _ = rig()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("203.0.113.9", 5000)), base_url="http://gw") as c:
        assert (await c.post("/console/api/demo/batch")).status_code == 403
        assert (await c.get("/console/api/catalog")).status_code == 403


# ---- names + detection layer --------------------------------------------------------------------------

def test_every_control_in_policy_yaml_has_a_display_name_description_and_layer():
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    cat = Catalog()
    ids = set(policy["controls"])
    assert {"DLP-01", "DLP-02", "DLP-05", "INJ-03", "INJ-04", "TOOL-01", "BUD-01", "ACCESS-01", "KILL-01"} <= ids
    for cid in ids:
        c = cat.control(cid)
        assert c["name"] and c["description"] and c["name"] != cid, cid
        assert c["layer"] == ("ai" if cid == "INJ-04" else "deterministic")
    assert cat.control("DLP-01")["name"] == "Secret leak (API keys, tokens)"


def test_every_rule_in_the_loaded_policy_is_named():
    from aicl_core.engine import Engine
    pol = Engine(POLICY).policy
    cat = Catalog(pol)
    assert pol.rules
    for r in pol.rules:                                   # rule files: the `name:` of each rule
        n = cat.rule(r.id)
        assert n["name"] == r.name and n["description"], r.id
    for r in pol.raw["controls"]["TOOL-01"]["rules"]:     # policy tool rules
        n = cat.rule(r["id"])
        assert n["name"] and n["name"] != r["id"] and n["description"], r["id"]
    assert cat.rule("matrix.confidential.external")["name"] == "Confidential data to an external model"
    assert cat.rule("some.new.rule")["name"] == "Some new rule"          # never a bare machine id without text


def test_catalog_ids_are_unchanged_and_names_are_plain_text():
    d = Catalog().as_dict()
    assert "DLP-01" in d["controls"] and d["controls"]["DLP-01"]["id"] == "DLP-01"
    for kind in ("controls", "rules"):
        for v in d[kind].values():
            for text in (v["name"], v["description"]):
                assert "\u2014" not in text and "\u2013" not in text      # AGENTS.md: plain hyphens only


def test_record_layer_rules():
    def f(cid, act, rid="x"):
        return {"control_id": cid, "rule_id": rid, "action": act}
    assert layer_of("INJ-04") == "ai" and layer_of("DLP-01") == "deterministic" and layer_of(None) == "deterministic"
    assert record_layer({"decision": 0, "findings": []}) is None                                       # clean request
    assert record_layer({"decision": 4, "findings": [f("INJ-04", 4)]}) == "ai"
    assert record_layer({"decision": 4, "findings": [f("INJ-04", 4), f("INJ-03", 4)]}) == "deterministic"  # tie: it ran first
    assert record_layer({"decision": 4, "findings": [f("INJ-04", 4), f("DLP-01", 3)]}) == "ai"          # the finding at the record's action
    assert record_layer({"decision": 4, "findings": []}) == "deterministic"                              # a refusal before decide()
    shadow = {"decision": 0, "findings": [f("INJ-04", 4, "judge.malicious")],
              "explain": ["INJ-04 rule judge.malicious: BLOCK x (shadow: not enforced)"]}
    assert record_layer(shadow) is None                                                                  # shadow findings decide nothing
    rec = enrich({"decision": 3, "findings": [f("DLP-02", 3)]})
    assert rec["detection_layer"] == "deterministic" and "detection_layer" not in rec["findings"][0]      # Finding forbids extra keys


# ---- the terminal script ----------------------------------------------------------------------------

async def test_the_script_prints_the_table_and_exits_zero(rig, capsys, monkeypatch):
    spec = importlib.util.spec_from_file_location("demo_batch_script", ROOT / "scripts" / "demo_batch.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    app, _, _ = rig()
    real = httpx.AsyncClient
    monkeypatch.setattr(mod.httpx, "AsyncClient", lambda **kw: real(transport=httpx.ASGITransport(app=app, client=LOCALHOST), **kw))
    # main() owns its event loop (asyncio.run), so it runs in a worker thread next to the test's loop
    code = await asyncio.to_thread(mod.main, ["--url", "http://gw", "--key", KEY])
    out = capsys.readouterr().out
    assert code == 0 and "TOOL-01 / CODE-AG-002" in out and "11/11 as expected" in out


# ---- the console page ----------------------------------------------------------------------------------

CONSOLE = ROOT / "w1-gateway" / "aicl_gateway" / "console"


def test_console_page_has_the_batch_button_the_names_card_and_the_layer_badge():
    html = (CONSOLE / "index.html").read_text(encoding="utf-8")
    js = (CONSOLE / "app.js").read_text(encoding="utf-8")
    css = (CONSOLE / "style.css").read_text(encoding="utf-8")
    for hook in ('id="batch-run"', 'id="batch-table"', 'id="batch-tiles"', 'id="pol-names"'):
        assert hook in html
    # one source for the names (the catalog endpoint), shown in the feed, the explain drawer, the timeline and the Policy page
    for needle in ('API + "/catalog"', "layerBadge(", "ctrlCell(r)", "rname(f.rule_id)", "renderNames()", 'API + "/demo/batch"', "judgeCell(r)"):
        assert needle in js, needle
    assert ".badge.lay-ai" in css and ".badge.lay-deterministic" in css
    assert "\u2014" not in js + html + css and "\u2013" not in js + html + css      # AGENTS.md: plain hyphens only

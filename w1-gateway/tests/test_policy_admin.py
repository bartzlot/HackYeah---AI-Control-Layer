"""T-107: console policy + budget editor (live config edits by the judges), offline."""
from __future__ import annotations

import shutil
from pathlib import Path

import httpx
import pytest

from aicl_gateway.main import create_app_from_env
from aicl_gateway.policy_admin import seed_policy

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def rig(tmp_path):
    from aicl_core import engine as eng

    def make(extra_env=None, client=("127.0.0.1", 5000)):
        pdir = tmp_path / "policy"
        if not pdir.exists():
            shutil.copytree(ROOT / "policy", pdir)
        env = {"AICL_POLICY": str(pdir / "policy.yaml"), "AICL_DATA_DIR": str(tmp_path / "d"),
               "AICL_AUDIT_PATH": str(tmp_path / "d" / "a.jsonl"), "AICL_BUDGET_DB": str(tmp_path / "d" / "b.db"),
               **(extra_env or {})}
        app = create_app_from_env(env, judge_chat=lambda b, t: {}, reload_interval=0.0, start_reload=False)
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=client), base_url="http://gw")
        return app, c, pdir / "policy.yaml"

    yield make
    eng.REGISTRY.pop("INJ-04", None)


async def test_valid_policy_edit_is_applied_at_once(rig):
    app, c, path = rig()
    v0 = app.state.engine.policy.version
    text = path.read_text(encoding="utf-8").replace("  profile: balanced          #", "  profile: strict            #", 1)
    r = await c.put("/console/api/policy", content=text, headers={"content-type": "text/plain"})
    assert r.status_code == 200 and r.json()["ok"] and r.json()["version"] != v0
    assert app.state.engine.policy.raw["defaults"]["profile"] == "strict"
    assert path.read_text(encoding="utf-8") == text
    assert not list(path.parent.glob(".policy.candidate.*"))           # no leftovers


async def test_invalid_policy_edit_is_rejected_and_the_live_file_stays(rig):
    app, c, path = rig()
    before, v0 = path.read_text(encoding="utf-8"), app.state.engine.policy.version
    bad = before.replace("  mode: enforce              #", "  mode: maybe                #", 1)
    r = await c.put("/console/api/policy", json={"yaml": bad})
    assert r.status_code == 422 and "defaults.mode" in r.json()["error"]
    assert path.read_text(encoding="utf-8") == before and app.state.engine.policy.version == v0
    assert not list(path.parent.glob(".policy.candidate.*"))


async def test_admin_token_is_required_when_configured(rig):
    app, c, path = rig({"AICL_ADMIN_TOKEN": "s3cret-admin"})
    text = path.read_text(encoding="utf-8")
    assert (await c.put("/console/api/policy", content=text)).status_code == 401
    assert (await c.put("/console/api/policy", content=text, headers={"authorization": "Bearer nope"})).status_code == 401
    r = await c.put("/console/api/policy", content=text, headers={"authorization": "Bearer s3cret-admin"})
    assert r.status_code == 200


async def test_without_a_token_only_loopback_may_write(rig):
    app, c, path = rig({"AICL_CONSOLE_REMOTE": "1"}, client=("172.18.0.1", 5000))
    r = await c.put("/console/api/policy", content=path.read_text(encoding="utf-8"))
    assert r.status_code == 403
    assert (await c.get("/console/api/budgets")).status_code == 200     # reading stays open to the console


async def test_budget_patch_keeps_comments_and_applies_to_the_ledger(rig):
    app, c, path = rig()
    r = await c.put("/console/api/budgets", json={"agents": {"demo-dev": {"usd": 0.75, "tokens": 123456},
                                                             "new-team": {"usd": 1.5, "period": "month"}},
                                                  "org": {"usd": 9.0}})
    assert r.status_code == 200, r.text
    text = path.read_text(encoding="utf-8")
    assert "# ---------- 6. budgets and rates (how much) ----------" in text      # comments kept
    assert "# v4 passthrough principal (section 10)" in text
    lim = app.state.ledger.limits
    assert lim["demo-dev"]["usd"] == 0.75 and lim["demo-dev"]["tokens"] == 123456 and lim["new-team"]["usd"] == 1.5
    got = (await c.get("/console/api/budgets")).json()
    assert got["org"]["usd"] == 9.0 and got["agents"]["new-team"]["period"] == "month"


@pytest.mark.parametrize("body, msg", [
    ({"agents": {"demo-dev": {"usd": -1}}}, "non-negative"),
    ({"agents": {"demo-dev": {"period": "week"}}}, "period"),
    ({"agents": {"demo-dev": {"tokens": "lots"}}}, "non-negative"),
    ({"agents": {"demo-dev": {"rate": 1}}}, "unknown key"),
])
async def test_bad_budget_patches_are_rejected(rig, body, msg):
    app, c, path = rig()
    before = path.read_text(encoding="utf-8")
    r = await c.put("/console/api/budgets", json=body)
    assert r.status_code == 422 and msg in r.json()["error"] and path.read_text(encoding="utf-8") == before


def test_seed_policy_copies_once_and_never_overwrites(tmp_path):
    target = tmp_path / "live" / "policy.yaml"
    seed_policy({"AICL_POLICY_SEED": str(ROOT / "policy"), "AICL_POLICY": str(target)})
    assert target.is_file() and (target.parent / "rules" / "coding_agent.yaml").is_file()
    target.write_text("edited", encoding="utf-8")
    seed_policy({"AICL_POLICY_SEED": str(ROOT / "policy"), "AICL_POLICY": str(target)})
    assert target.read_text(encoding="utf-8") == "edited"


# ---- T-114: control toggles ----------------------------------------------------------------------

async def test_switching_a_control_off_patches_only_its_mode_and_applies_at_once(rig):
    from aicl_contracts import Event, Part
    app, c, path = rig()
    secret = Event(agent_id="analyst-agent", model="gpt-4o-mini", parts=[Part(text="key AKIAIOSFODNN7EXAMPLE")])
    assert app.state.engine.decide(secret).action.name in ("REDACT", "BLOCK")
    before = path.read_text(encoding="utf-8")
    r = await c.put("/console/api/controls/DLP-01", json={"mode": "off"})
    assert r.status_code == 200 and r.json()["old"] == "enforce" and r.json()["new"] == "off"
    after = path.read_text(encoding="utf-8")
    assert "# secrets (AWS, GitHub with CRC, private keys, high-entropy in context)" in after       # comment kept
    changed = [(a, b) for a, b in zip(before.splitlines(), after.splitlines()) if a != b]
    assert len(changed) == 1 and "mode: off" in changed[0][1]
    assert not any(f.control_id == "DLP-01" for f in app.state.engine.decide(secret).findings)
    row = {x["id"]: x for x in (await c.get("/console/api/controls")).json()["controls"]}["DLP-01"]
    assert row["mode"] == "off"
    rec = [x for x in app.state.bus.recent(50) if x["event_type"] == "POLICY_CHANGED"][-1]
    assert "controls.DLP-01.mode enforce -> off" in rec["explain"][0] and "127.0.0.1" in rec["explain"][0]


async def test_kill_switch_and_identity_cannot_be_switched_off_from_the_ui(rig):
    app, c, path = rig()
    for cid in ("KILL-01", "ACCESS-01"):
        for mode in ("off", "shadow"):          # shadow only logs: the kill switch / identity would stop acting
            r = await c.put(f"/console/api/controls/{cid}", json={"mode": mode})
            assert r.status_code == 422 and "stays enforced" in r.json()["error"]
    assert (await c.put("/console/api/controls/ACCESS-01", json={"mode": "enforce"})).status_code == 200


async def test_per_profile_mode_changes_only_that_profile(rig):
    app, c, path = rig()
    r = await c.put("/console/api/controls/INJ-04", json={"mode": "off", "profile": "balanced"})
    assert r.status_code == 200
    assert r.json()["new"] == {"strict": "enforce", "balanced": "off", "permissive": "shadow"}
    pol = app.state.engine.policy
    assert pol.mode_for("INJ-04", "balanced") == "off" and pol.mode_for("INJ-04", "strict") == "enforce"


@pytest.mark.parametrize("cid, body, status", [("NOPE-9", {"mode": "off"}, 404), ("DLP-01", {"mode": "maybe"}, 422),
                                               ("DLP-01", {"mode": "off", "profile": "yolo"}, 422)])
async def test_bad_control_switches_are_rejected(rig, cid, body, status):
    app, c, path = rig()
    before = path.read_text(encoding="utf-8")
    assert (await c.put(f"/console/api/controls/{cid}", json=body)).status_code == status
    assert path.read_text(encoding="utf-8") == before


async def test_control_switch_needs_the_admin_token(rig):
    app, c, path = rig({"AICL_ADMIN_TOKEN": "t0k"})
    assert (await c.put("/console/api/controls/DLP-01", json={"mode": "off"})).status_code == 401
    r = await c.put("/console/api/controls/DLP-01", json={"mode": "shadow"}, headers={"authorization": "Bearer t0k"})
    assert r.status_code == 200


async def test_budget_patch_changes_only_the_touched_lines(rig):
    app, c, path = rig()
    before = path.read_text(encoding="utf-8").splitlines()
    r = await c.put("/console/api/budgets", json={"agents": {"demo-dev": {"usd": 3.5}, "qa-bot": {"tokens": 1000}}})
    assert r.status_code == 200, r.text
    after = path.read_text(encoding="utf-8").splitlines()
    assert len(after) == len(before) + 1                                   # one new line: qa-bot
    diff = [a for a in after if a not in before]
    assert len(diff) == 2 and any("demo-dev:" in d and "usd: 3.5" in d and "# v4 passthrough principal" in d for d in diff)
    assert any(d.strip() == "qa-bot: {tokens: 1000}" for d in diff)


# ---- T-115: intercepted AI domains ----------------------------------------------------------------

async def test_adding_a_host_makes_dns_answer_it_and_the_leaf_carries_it(rig, tmp_path):
    from dnslib import DNSRecord

    from aicl_core.interception import provider_for_host
    from aicl_gateway import ca
    from aicl_gateway.dns import AiclResolver
    from aicl_gateway.serve import refresh_leaf
    app, c, path = rig()
    listed = (await c.get("/console/api/interception")).json()["providers"]
    assert {p["name"] for p in listed} == {"anthropic", "openai"}
    r = await c.put("/console/api/interception", json={"add_host": {"provider": "anthropic", "host": "API.Claude-Proxy.example."}})
    assert r.status_code == 200 and "api.claude-proxy.example" in r.json()["hosts"], r.text
    raw = app.state.engine.policy.raw
    from aicl_core.interception import interception_cfg
    assert provider_for_host(interception_cfg(raw), "api.claude-proxy.example")[0] == "anthropic"
    # DNS: the resolver reads the live policy -> the new host resolves to the gateway at once

    class H:
        client_address = ("10.77.0.10", 5353)
    ans = AiclResolver(lambda: app.state.engine.policy.raw).resolve(DNSRecord.question("api.claude-proxy.example"), H())
    assert [str(a.rdata) for a in ans.rr] == [raw["interception"]["dns"]["gateway_ip"]]
    # TLS: the reload hook reissues the leaf with the new SAN (no restart)
    hosts = refresh_leaf(None, raw, tmp_path)
    leaf = ca.x509.load_pem_x509_certificate((tmp_path / "data/ca/aicl-leaf.pem").read_bytes())
    assert "api.claude-proxy.example" in hosts and "api.claude-proxy.example" in ca.leaf_hosts(leaf)
    rec = [x for x in app.state.bus.recent(20) if x["event_type"] == "POLICY_CHANGED"][-1]
    assert "+ host api.claude-proxy.example on anthropic" in rec["explain"][0]
    assert "anthropic:" in path.read_text(encoding="utf-8") and "# ---------- 10. clients" in path.read_text(encoding="utf-8")


async def test_remove_host_and_add_provider_with_protocol_defaults(rig):
    app, c, path = rig()
    await c.put("/console/api/interception", json={"add_host": {"provider": "openai", "host": "api.openai-eu.example"}})
    r = await c.put("/console/api/interception", json={"remove_host": {"provider": "openai", "host": "api.openai-eu.example"}})
    assert r.status_code == 200 and "api.openai-eu.example" not in r.json()["hosts"]
    r = await c.put("/console/api/interception", json={"add_provider": {"name": "mistral", "host": "api.mistral.example",
                                                                         "protocol": "openai_chat"}})
    assert r.status_code == 200, r.text
    p = {x["name"]: x for x in (await c.get("/console/api/interception")).json()["providers"]}["mistral"]
    assert p["inspect"] == ["/v1/chat/completions"] and p["upstream"] == "https://api.mistral.example"


@pytest.mark.parametrize("body, status, msg", [
    ({"add_host": {"provider": "anthropic", "host": "*.anthropic.com"}}, 422, "wildcard"),
    ({"add_host": {"provider": "anthropic", "host": "dns.google"}}, 422, "DNS-over-HTTPS"),
    ({"add_host": {"provider": "anthropic", "host": "api.openai.com"}}, 422, "already intercepted"),
    ({"add_host": {"provider": "nope", "host": "a.example.com"}}, 404, "does not exist"),
    ({"add_host": {"provider": "anthropic", "host": "not a host"}}, 422, "valid host"),
    ({"remove_host": {"provider": "anthropic", "host": "api.anthropic.com"}}, 422, "at least one"),
    ({"add_provider": {"name": "x1", "host": "api.x.example", "protocol": "grpc"}}, 422, "protocol"),
    ({"add_provider": {"name": "x2", "host": "api.x.example", "protocol": "openai_chat", "upstream": "http://plain"}}, 422, "https"),
])
async def test_bad_interception_edits_are_rejected(rig, body, status, msg):
    app, c, path = rig()
    before = path.read_text(encoding="utf-8")
    r = await c.put("/console/api/interception", json=body)
    assert r.status_code == status and msg in r.json()["error"]
    assert path.read_text(encoding="utf-8") == before


async def test_interception_edit_needs_the_admin_token(rig):
    app, c, path = rig({"AICL_ADMIN_TOKEN": "t0k"})
    body = {"add_host": {"provider": "anthropic", "host": "api.x.example"}}
    assert (await c.put("/console/api/interception", json=body)).status_code == 401
    assert (await c.put("/console/api/interception", json=body, headers={"authorization": "Bearer t0k"})).status_code == 200


# ---- review fixes ---------------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ['{"agents": {"demo-dev": {"usd": NaN}}}', '{"agents": {"demo-dev": {"usd": Infinity}}}',
                                 '{"agents": {"demo-dev": {"tokens": 1.5}}}'])
async def test_non_finite_or_fractional_budget_values_are_rejected(rig, raw):
    app, c, path = rig()
    before = path.read_text(encoding="utf-8")
    r = await c.put("/console/api/budgets", content=raw, headers={"content-type": "application/json"})
    assert r.status_code == 422 and path.read_text(encoding="utf-8") == before


async def test_tiny_usd_caps_are_kept_exactly(rig):
    app, c, path = rig()
    assert (await c.put("/console/api/budgets", json={"agents": {"demo-dev": {"usd": 1e-07}}})).status_code == 200
    assert app.state.ledger.limits["demo-dev"]["usd"] == 1e-07


async def test_local_d_overrides_never_leak_into_policy_yaml(rig):
    app, c, path = rig()
    (path.parent / "local.d").mkdir(exist_ok=True)
    (path.parent / "local.d" / "zz-o.yaml").write_text(
        'interception: {providers: {anthropic: {upstream: "http://127.0.0.1:9"}}}\n', encoding="utf-8")
    app.state.engine.store.refresh(force=True)
    r = await c.put("/console/api/interception", json={"add_host": {"provider": "anthropic", "host": "api.x.example"}})
    assert r.status_code == 200
    assert "127.0.0.1:9" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("body, msg", [
    ({"add_provider": {"name": "x3", "host": "api.y.example", "protocol": "openai_chat",
                       "upstream": "https://x.example.com\n    mode: off #"}}, "plain https URL"),
    ({"add_provider": {"name": "null", "host": "api.y.example", "protocol": "openai_chat"}}, "YAML word"),
    ({"add_provider": {"name": "true", "host": "api.y.example", "protocol": "openai_chat"}}, "YAML word"),
])
async def test_review_bad_interception_values_are_rejected(rig, body, msg):
    app, c, path = rig()
    r = await c.put("/console/api/interception", json=body)
    assert r.status_code == 422 and msg in r.json()["error"]


async def test_deny_cidrs_also_match_ipv4_mapped_clients(tmp_path):
    from aicl_gateway.app import create_app
    app = create_app(config={"console": {"remote": True, "deny_cidrs": ["10.77.0.0/24"]}})
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("::ffff:10.77.0.10", 1)), base_url="http://gw")
    assert (await c.get("/console/api/summary")).status_code == 403

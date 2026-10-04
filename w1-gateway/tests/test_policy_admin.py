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
        r = await c.put(f"/console/api/controls/{cid}", json={"mode": "off"})
        assert r.status_code == 422 and "cannot be switched off" in r.json()["error"]
    assert (await c.put("/console/api/controls/ACCESS-01", json={"mode": "shadow"})).status_code == 200


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

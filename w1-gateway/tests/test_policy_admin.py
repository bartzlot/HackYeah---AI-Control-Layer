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

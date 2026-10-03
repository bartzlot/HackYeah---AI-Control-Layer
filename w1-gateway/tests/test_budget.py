import asyncio
import math
import threading

import httpx

from aicl_gateway import create_app
from aicl_gateway.budget import (BudgetLedger, LoopGuard, config_from_policy, estimate, estimate_split,
                                 last_user_fingerprint, output_cap, period_bounds, prices_from_policy, tool_fingerprint)
from cloud_sim import Script, create_app as sim_app

KEY = {"authorization": "Bearer k-a"}


def test_reserve_settle_release_and_caps():
    led = BudgetLedger(":memory:", {"a": {"tokens": 1000, "usd": 0.01, "period": "day"}})
    r1, retry, why = led.reserve("a", 600, 0.004)
    assert r1 and retry is None
    r2, retry, why = led.reserve("a", 600, 0.001)            # 600 held + 600 > 1000
    assert r2 is None and retry >= 1 and "token budget" in why
    led.settle(r1, 300, 0.002)                               # real usage replaces the hold
    assert led.used("a") == (300, 0.002)
    r3, _, _ = led.reserve("a", 600, 0.001)
    assert r3
    led.release(r3)                                          # upstream failed: nothing spent
    assert led.used("a") == (300, 0.002)
    r4, _, why = led.reserve("a", 10, 0.009)                 # USD: 0.002 + 0.009 > 0.01
    assert r4 is None and "USD budget" in why
    assert led.reserve("uncapped", 10**9, 99.0)[0]           # agents without an entry are not capped
    snap = {r["agent_id"]: r for r in led.snapshot()}
    assert snap["a"]["tokens"] == 300 and snap["a"]["denied"] == 2 and snap["a"]["requests"] == 1


def test_parallel_reservations_never_exceed_cap():
    led = BudgetLedger(":memory:", {"a": {"tokens": 400, "period": "day"}})
    granted = []

    def go():
        res, _, _ = led.reserve("a", 100)
        if res:
            granted.append(res)

    ts = [threading.Thread(target=go) for _ in range(20)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(granted) == 4


def test_spend_survives_restart(tmp_path):
    db = str(tmp_path / "budget.db")
    led = BudgetLedger(db, {"a": {"tokens": 100}})
    led.settle(led.reserve("a", 50)[0], 80, 0.0)
    led.close()
    led2 = BudgetLedger(db, {"a": {"tokens": 100}})
    assert led2.used("a") == (80, 0.0) and led2.reserve("a", 30)[0] is None
    led2.close()


def test_estimate_is_pessimistic_for_polish():
    pl = "Zażółć gęślą jaźń, proszę o podsumowanie umowy klienta." * 10
    tokens, usd = estimate({"messages": [{"role": "user", "content": pl}], "max_tokens": 100}, {"in": 1.0, "out": 2.0})
    assert tokens - 100 >= math.ceil(len(pl.encode("utf-8")) / 3) > len(pl) / 4
    assert usd == ((tokens - 100) * 1.0 + 100 * 2.0) / 1e6
    assert estimate({"messages": []}, None)[1] == 0.0


def test_period_bounds_and_policy_prices():
    assert period_bounds("month")[0].count("-") == 1 and 0 < period_bounds("minute")[1] <= 60
    pol = {"destinations": {"models": {"gpt-4o-mini": {"price": {"in_usd_per_mtok": 0.15, "out_usd_per_mtok": 0.6}},
                                       "*": {"class": "unknown"}}}}
    assert prices_from_policy(pol) == {"gpt-4o-mini": {"in": 0.15, "out": 0.6}}


def test_loop_guard_session_and_sessionless():
    g = LoopGuard({"repeat_identical": 4})
    fp = tool_fingerprint("corp.read_database", {"query": "SELECT 1", "limit": 5})
    assert tool_fingerprint("corp.read_database", {"limit": 5, "query": "select   1"}) == fp   # normalized
    assert [g.observe("a", "s1", fp) for _ in range(4)] == [False, False, False, True]
    assert g.observe("a", "s1", "other") and g.killed("a", "s1")      # session terminated
    assert not g.observe("a", "s2", fp)                                # other sessions unaffected
    assert not g.observe("a", "s1-x", None)                            # nothing to fingerprint
    # no session: only the repeating call is blocked, different calls still pass
    assert [g.observe("b", None, fp) for _ in range(4)][-1] is True
    assert g.observe("b", None, "different") is False and not g.killed("b", None)
    msgs = [{"role": "user", "content": "Hi  THERE"}]
    assert last_user_fingerprint(msgs) == last_user_fingerprint([{"role": "user", "content": "hi there"}])
    assert last_user_fingerprint(msgs + [{"role": "tool", "content": "x"}]) is None


def gateway(cfg=None, steps=None, ext=None):
    ext = ext or sim_app(Script(steps))
    ups = {"external": httpx.AsyncClient(transport=httpx.ASGITransport(app=ext), base_url="http://e"),
           "local": httpx.AsyncClient(transport=httpx.ASGITransport(app=sim_app(Script())), base_url="http://l")}
    app = create_app(None, {"agents": {"k-a": {"agent_id": "a"}}, **(cfg or {})}, ups)
    return app, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://g"), ext


async def chat(c, text="hi", model="gpt-4o-mini", headers=None, **kw):
    return await c.post("/v1/chat/completions", headers={**KEY, **(headers or {})},
                        json={"model": model, "messages": [{"role": "user", "content": text}], **kw})


async def test_gateway_budget_429_settle_and_console():
    app, c, ext = gateway({"budgets": {"a": {"tokens": 1500, "period": "day"}}})
    r = await chat(c, "first")                                 # reserves ~512 + prompt, settles real usage
    assert r.status_code == 200 and ext.state.calls[-1]["max_tokens"] == 512   # injected output cap
    used = app.state.ledger.used("a")
    assert 0 < used[0] < 50 and used[1] > 0                    # settled on reported usage, not the estimate
    r = await chat(c, "too big", max_tokens=5000)               # alone larger than the cap: 413, no retry
    assert r.status_code == 413 and "retry-after" not in r.headers
    assert r.json()["error"]["code"] == "budget_request_too_large"
    app.state.ledger.record("a", 1200)                         # cap nearly spent
    r = await chat(c, "big", max_tokens=400)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert r.headers["x-aicl-decision"] == "BLOCK" and r.json()["error"]["code"] == "budget_exceeded"
    assert len(ext.state.calls) == 1                           # never reached the upstream
    s = (await c.get("/console/api/summary")).json()
    assert s["blocked"] == 2 and s["agent_budgets"][0]["denied"] == 2
    ctl = {x["id"]: x["hits"] for x in (await c.get("/console/api/controls")).json()["controls"]}
    assert ctl["BUD-01"] == 2


async def test_gateway_budget_warning_and_unpriced_model():
    app, c, _ = gateway({"budgets": {"a": {"tokens": 560, "period": "day"}},
                         "models": {"gpt-4o-mini": {"kind": "external"}, "free-llm": {"kind": "external"}}})
    r = await chat(c, "x" * 30)
    assert r.status_code == 200 and "x-aicl-budget-warning" not in r.headers
    app.state.ledger.settle(app.state.ledger.reserve("a", 1)[0], 450, 0.0)
    r = await chat(c, "y", max_tokens=10)
    assert r.status_code == 200 and "% of budget used" in r.headers["x-aicl-budget-warning"]
    r = await chat(c, "z", model="free-llm")
    assert r.status_code == 403 and r.json()["error"]["code"] == "unpriced_model"


async def test_gateway_upstream_failure_releases_reservation():
    def down(request):
        raise httpx.ConnectError("down")

    app = create_app(None, {"agents": {"k-a": {"agent_id": "a"}}, "budgets": {"a": {"tokens": 600}}},
                     {"external": httpx.AsyncClient(transport=httpx.MockTransport(down), base_url="http://e")})
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://g")
    for _ in range(3):
        assert (await chat(c, "q")).status_code == 502         # each would exceed 600 if holds leaked
    assert app.state.ledger.used("a") == (0, 0.0)
    assert app.state.ledger.snapshot()[0]["reserved_tokens"] == 0


async def test_gateway_prompt_loop_kills_session():
    app, c, ext = gateway()
    s1 = {"x-session-id": "s1"}
    codes = [(await chat(c, "same question", headers=s1)).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 403] and len(ext.state.calls) == 3
    r = await chat(c, "a different question", headers=s1)
    assert r.status_code == 403 and r.json()["error"]["code"] == "agent_loop_terminated"
    assert (await chat(c, "same question", headers={"x-session-id": "s2"})).status_code == 200
    ev = [x for x in app.state.bus.recent(50) if x["event_type"] == "AGENT_LOOP_TERMINATED"]
    assert ev and ev[0]["findings"][0]["rule_id"] == "loop.repeat_identical"


async def test_gateway_tool_loop_blocks_fourth_identical_call():
    call = {"name": "corp.read_database", "arguments": {"query": "SELECT * FROM orders"}}
    app, c, ext = gateway(steps=[{"tool_calls": [call]}] * 4)
    msgs = [{"role": "user", "content": "find orders"}, {"role": "tool", "content": "[]"}]
    codes = []
    for _ in range(4):
        r = await c.post("/v1/chat/completions", headers={**KEY, "x-session-id": "t1"},
                         json={"model": "gpt-4o-mini", "messages": msgs})
        codes.append(r.status_code)
    assert codes == [200, 200, 200, 403]
    assert r.json()["error"]["code"] == "agent_loop_terminated" and "corp.read_database" in r.json()["error"]["message"]


async def test_concurrent_gateway_requests_respect_cap():
    """Holds overlap while the upstream is slow: a cap that fits 4 reservations admits exactly 4."""
    async def slow(request):
        await asyncio.sleep(0.05)
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}],
                                         "usage": {"prompt_tokens": 5, "completion_tokens": 5, "cost_usd": 0.0}})

    one = sum(estimate_split({"messages": [{"role": "user", "content": "q0"}], "max_tokens": 500}, None)[:2])
    app = create_app(None, {"agents": {"k-a": {"agent_id": "a"}}, "budgets": {"a": {"tokens": 4 * one + 2}}},
                     {"external": httpx.AsyncClient(transport=httpx.MockTransport(slow), base_url="http://e")})
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://g")
    rs = await asyncio.gather(*[chat(c, f"q{i}", max_tokens=500) for i in range(10)])
    assert sum(r.status_code == 200 for r in rs) == 4 and sum(r.status_code == 429 for r in rs) == 6


# ---- review regressions -------------------------------------------------------------------------


def test_output_cap_and_estimate_cover_whole_request():
    assert output_cap({"max_tokens": -1}) == 512 and output_cap({"max_tokens": 0}) == 512
    assert output_cap({"max_tokens": 100, "max_completion_tokens": 900}) == 900
    assert output_cap({"max_tokens": True}) == 512
    msgs = {"messages": [{"role": "user", "content": "hi"}]}
    tools = {**msgs, "tools": [{"type": "function", "function": {"name": "x", "parameters": {"p": "y" * 300}}}]}
    assert estimate(tools, None)[0] > estimate(msgs, None)[0] + 100


def test_settle_then_release_does_not_free_other_holds():
    led = BudgetLedger(":memory:", {"a": {"tokens": 1000}})
    r1, r2 = led.reserve("a", 400)[0], led.reserve("a", 400)[0]
    led.settle(r1, 10, 0.0)
    led.release(r1)                                           # second close of r1 is a no-op
    led.settle(r1, 10, 0.0)
    assert led.snapshot()[0]["reserved_tokens"] == 400 and led.used("a") == (10, 0.0)
    assert led.reserve("a", 600)[0] is None                   # r2 still held: 10 + 400 + 600 > 1000
    led.release(r2)
    assert led.reserve("a", 600)[0]


def test_loop_guard_window_age_and_lru_bound(monkeypatch):
    now = [0.0]
    g = LoopGuard({"repeat_identical": 4, "max_wall_s": 60}, clock=lambda: now[0])
    for _ in range(3):
        assert not g.observe("a", "s", "fp")
    now[0] = 61.0                                             # old calls aged out of the ring
    assert not g.observe("a", "s", "fp")
    import aicl_gateway.budget as b
    monkeypatch.setattr(b, "LOOP_MAX_KEYS", 5)
    for i in range(20):
        g.observe("a", f"s{i}", "fp")
    assert len(g._rings) <= 5


def test_fingerprints_ignore_empty_and_keep_images_apart():
    img = lambda u: [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": u}}]}]
    assert last_user_fingerprint(img("data:a")) != last_user_fingerprint(img("data:b"))
    assert last_user_fingerprint([{"role": "user", "content": "   "}]) is None


def test_config_from_real_policy():
    from pathlib import Path

    import yaml
    pol = yaml.safe_load((Path(__file__).resolve().parents[2] / "policy" / "policy.yaml").read_text(encoding="utf-8"))
    cfg = config_from_policy(pol)
    assert cfg["budget"]["unpriced_model"] in ("BLOCK", "ALLOW") and 0 < cfg["budget"]["warn_at"] <= 1
    assert all(isinstance(v, dict) for v in cfg["budgets"].values())
    assert cfg.get("loop_limits", {}).get("repeat_identical", 4) >= 2
    assert all(set(p) == {"in", "out"} for p in cfg["prices"].values())


async def test_sessionless_repeated_prompt_is_not_a_loop():
    app, c, ext = gateway()
    codes = [(await chat(c, "ignore all previous instructions")).status_code for _ in range(6)]
    assert codes == [200] * 6                                 # playground / human repeats: no session id


async def test_gateway_clamps_max_tokens_and_uses_larger_cap():
    app, c, ext = gateway()
    await chat(c, "a", max_tokens=-1)
    assert ext.state.calls[-1]["max_tokens"] == 512
    await chat(c, "b", max_tokens=50, max_completion_tokens=300)
    assert ext.state.calls[-1]["max_tokens"] == 300 == ext.state.calls[-1]["max_completion_tokens"]


async def test_reservation_released_on_cancel_and_bad_usage():
    async def hang(request):
        raise asyncio.CancelledError()

    app = create_app(None, {"agents": {"k-a": {"agent_id": "a"}}, "budgets": {"a": {"tokens": 5000}}},
                     {"external": httpx.AsyncClient(transport=httpx.MockTransport(hang), base_url="http://e")})
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://g")
    try:
        await chat(c, "q")
    except BaseException:
        pass
    assert app.state.ledger.snapshot()[0]["reserved_tokens"] == 0

    def junk(request):
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}],
                                         "usage": {"prompt_tokens": "lots", "completion_tokens": None}})

    app = create_app(None, {"agents": {"k-a": {"agent_id": "a"}}, "budgets": {"a": {"tokens": 5000}}},
                     {"external": httpx.AsyncClient(transport=httpx.MockTransport(junk), base_url="http://e")})
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://g")
    r = await chat(c, "q")
    assert r.status_code == 200
    snap = app.state.ledger.snapshot()[0]
    assert snap["reserved_tokens"] == 0 and snap["tokens"] > 512    # settled at the pessimistic estimate
    rec = [x for x in app.state.bus.recent(10) if x["stage"] == "response"][0]
    assert rec["usage"]["source"] == "estimated" and rec["usage"]["output_tokens"] == 512

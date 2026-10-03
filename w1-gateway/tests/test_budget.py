import asyncio
import math
import threading

import httpx

from aicl_gateway import create_app
from aicl_gateway.budget import (BudgetLedger, LoopGuard, estimate, last_user_fingerprint, period_bounds,
                                 prices_from_policy, tool_fingerprint)
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
    r = await chat(c, "big", max_tokens=5000)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert r.headers["x-aicl-decision"] == "BLOCK" and r.json()["error"]["code"] == "budget_exceeded"
    assert len(ext.state.calls) == 1                           # never reached the upstream
    s = (await c.get("/console/api/summary")).json()
    assert s["blocked"] == 1 and s["agent_budgets"][0]["denied"] == 1
    ctl = {x["id"]: x["hits"] for x in (await c.get("/console/api/controls")).json()["controls"]}
    assert ctl["BUD-01"] == 1


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

    app = create_app(None, {"agents": {"k-a": {"agent_id": "a"}}, "budgets": {"a": {"tokens": 4 * 520}}},
                     {"external": httpx.AsyncClient(transport=httpx.MockTransport(slow), base_url="http://e")})
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://g")
    rs = await asyncio.gather(*[chat(c, f"q{i}", max_tokens=500) for i in range(10)])
    assert sum(r.status_code == 200 for r in rs) == 4 and sum(r.status_code == 429 for r in rs) == 6

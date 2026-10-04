"""AICL performance telemetry (PDF section 6: "produce performance telemetry"). Offline, deterministic.

    make bench          ->  reports/bench.json + a table on stdout

Measures decide() latency (p50 / p95 / max, ms) on the real policy for shapes that matter:
  small chat prompt, coding-agent turn (Claude Code sized: ~400 KB of system + history + tool results),
  tool call, and the full gateway path (passthrough PEP, Anthropic mock upstream over ASGI) so the
  overhead AICL adds to one Claude Code request is visible end to end. The INJ-04 judge is a fake here
  (the local model's latency is reported by the live console, Performance page).
"""
from __future__ import annotations

import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "w2-core"), str(ROOT / "w1-gateway"), str(ROOT / "contracts")]

import httpx  # noqa: E402

from aicl_contracts import Event, Part, Stage, ToolCall  # noqa: E402
from aicl_core.engine import Engine  # noqa: E402

LOREM = ("The service reads orders from the queue, validates them, and writes the result to the ledger. "
         "Retries use exponential backoff; idempotency keys prevent double booking. ")


def pct(xs: list[float]) -> dict:
    xs = sorted(xs)
    return {"p50": round(statistics.median(xs), 2), "p95": round(xs[int(0.95 * (len(xs) - 1))], 2),
            "max": round(xs[-1], 2), "n": len(xs)}


def timeit(fn, n: int) -> dict:
    fn()                                    # warm caches / imports
    out = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t0) * 1000)
    return pct(out)


def coding_turn(kb: int = 400) -> Event:
    body = (LOREM * (kb * 1024 // len(LOREM) // 4))
    parts = [Part(role="system", text="You are Claude Code. " + body),
             Part(role="system", text="<system-reminder>CLAUDE.md: use uv, run tests</system-reminder>" + body),
             Part(role="user", text="Refactor the ledger writer and add tests."),
             Part(role="tool", trusted=False, text="src/ledger.py\n" + body),
             Part(role="user", text="Also check the retry policy for orders from Acme Bank.")]
    return Event(stage=Stage.PROMPT, agent_id="claude-code", model="claude-sonnet-5-5", parts=parts)


def main() -> None:
    eng = Engine(ROOT / "policy" / "policy.yaml")
    small = Event(stage=Stage.PROMPT, agent_id="analyst-agent", model="gpt-4o-mini",
                  parts=[Part(text="My PESEL is 44051401458, summarise the contract for ACME.")])
    big = coding_turn()
    tool = Event(stage=Stage.TOOL_ARGS, agent_id="claude-code", model="claude-sonnet-5-5",
                 tool_calls=[ToolCall(name="Bash", arguments={"command": "pytest -q && git diff --stat"})])
    res = {"decide_small_prompt_ms": timeit(lambda: eng.decide(small), 200),
           "decide_coding_turn_400kb_ms": timeit(lambda: eng.decide(big), 20),
           "decide_tool_call_ms": timeit(lambda: eng.decide(tool), 200)}
    seq = iter(range(10**6))      # cold: a new text every time (no shared view cache, like a brand-new turn)
    res["decide_coding_turn_400kb_cold_ms"] = timeit(lambda: eng.decide(big.model_copy(update={"parts": [
        p.model_copy(update={"text": p.text + f" turn {next(seq)}"}) for p in big.parts]})), 10)
    res["coding_turn_per_control_ms"] = {k: round(v / 1000, 2) for k, v in eng.decide(big).latency_us.items()}
    res["gateway_passthrough_overhead_ms"] = asyncio.run(gateway_overhead())
    out = ROOT / "reports" / "bench.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(res, indent=2), encoding="utf-8")
    w = max(len(k) for k in res)
    for k, v in res.items():
        print(f"{k.ljust(w)}  {json.dumps(v)}")
    print(f"\nwritten {out.relative_to(ROOT)}")


async def gateway_overhead() -> dict:
    """Server-Timing aicl;dur (gateway time minus upstream time) over the passthrough PEP, Claude Code shaped."""
    import shutil
    import tempfile

    from aicl_gateway.main import create_app_from_env
    from aicl_gateway.mock_providers import anthropic_app
    tmp = Path(tempfile.mkdtemp())
    shutil.copytree(ROOT / "policy", tmp / "policy")
    env = {"AICL_POLICY": str(tmp / "policy" / "policy.yaml"), "AICL_DATA_DIR": str(tmp / "d"),
           "AICL_AUDIT_PATH": str(tmp / "d" / "a.jsonl"), "AICL_BUDGET_DB": str(tmp / "d" / "b.db")}
    ups = {"anthropic": httpx.AsyncClient(transport=httpx.ASGITransport(app=anthropic_app()),
                                          base_url="https://api.anthropic.com")}
    fake = lambda b, t: {"message": {"content": json.dumps({"prompt_injection": "none", "data_exfiltration": "none",  # noqa: E731
                                                            "jailbreak": "none", "tool_abuse": "none", "verdict": "benign"})}}
    app = create_app_from_env(env, upstreams=ups, judge_chat=fake, reload_interval=0.0, start_reload=False)
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://api.anthropic.com")
    hist = (LOREM * 900)
    body = {"model": "claude-sonnet-5-5", "max_tokens": 32000, "stream": True,
            "system": [{"type": "text", "text": "You are Claude Code. " + hist}],
            "messages": [{"role": "user", "content": [{"type": "text", "text": "<system-reminder>ctx</system-reminder>"},
                                                      {"type": "text", "text": "fix the failing test"}]}],
            "tools": [{"name": f"tool{i}", "description": "x" * 200, "input_schema": {"type": "object"}} for i in range(275)],
            "metadata": {"user_id": "bench"}}
    hdr = {"x-api-key": "sk-ant-synthetic-bench", "user-agent": "claude-cli/2.1.289", "content-type": "application/json"}
    data = json.dumps(body)
    vals = []
    for i in range(30):
        r = await c.post("/v1/messages?beta=true", content=data, headers=hdr)
        st = dict(x.strip().split(";dur=") for x in r.headers["server-timing"].split(","))
        if i:                                   # first request warms imports and caches
            vals.append(float(st["aicl"]))
    res = pct(vals)
    res["request_kb"] = round(len(data) / 1024)
    return res


if __name__ == "__main__":
    main()

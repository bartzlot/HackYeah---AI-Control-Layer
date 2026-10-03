import csv
import io
import json
import sys
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from console_api import FIXTURES, ConsoleStore, make_console_router, store_with_fixtures  # noqa: E402


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
    prompts = [r for r in recs if r["stage"] == "prompt"]
    s = (await c.get("/console/api/summary")).json()
    assert s["requests"] == len(prompts)
    assert s["blocked"] == sum(r["decision"] == 4 for r in prompts) > 0
    assert s["redacted"] == sum(r["decision"] == 3 for r in prompts) > 0
    assert s["requests"] == s["blocked"] + s["redacted"] + s["allowed"]
    assert s["cost_usd"] == pytest.approx(sum(r["usage"]["usd"] for r in recs), abs=1e-6)
    assert s["controls_enforced"] < s["controls_total"]
    assert s["posture_pct"] == round(100 * s["controls_enforced"] / s["controls_total"], 1)
    assert 0 < s["budget_used_pct"] < 100


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

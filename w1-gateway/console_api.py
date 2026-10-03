"""Console API (T-105 UI part): in-memory audit store + FastAPI router for the dashboard.

make_console_router(store) -> APIRouter. Mount it on the gateway app (or any FastAPI app).
Records are AuditRecord JSON dicts (contracts/aicl_contracts.py). Raw text never appears here.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from collections import deque
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

CONSOLE_DIR = Path(__file__).parent / "console"
FIXTURES = CONSOLE_DIR / "fixtures.jsonl"

DEFAULT_CONTROLS: list[dict[str, Any]] = [
    {"id": "DLP-01", "name": "Secret detection", "severity": "critical", "category": "secret", "mode": "enforce", "action": "BLOCK"},
    {"id": "DLP-02", "name": "PII detection (PL_PESEL, IBAN, e-mail)", "severity": "high", "category": "pii", "mode": "enforce", "action": "REDACT"},
    {"id": "DLP-03", "name": "Destination matrix (local / external / unknown)", "severity": "high", "category": "pii", "mode": "enforce", "action": "BLOCK"},
    {"id": "INJ-01", "name": "Injection signatures", "severity": "high", "category": "injection", "mode": "enforce", "action": "BLOCK"},
    {"id": "INJ-04", "name": "Semantic injection classifier", "severity": "high", "category": "injection", "mode": "shadow", "action": "WARN"},
    {"id": "TOOL-01", "name": "Tool argument validation (shell, paths)", "severity": "critical", "category": "tool_abuse", "mode": "enforce", "action": "BLOCK"},
    {"id": "TOOL-02", "name": "Tool authorization and approvals", "severity": "high", "category": "tool_abuse", "mode": "enforce", "action": "BLOCK"},
    {"id": "BUD-01", "name": "Budgets and rate limits", "severity": "medium", "category": "resource", "mode": "enforce", "action": "BLOCK"},
    {"id": "BUD-02", "name": "Agent loop guard", "severity": "medium", "category": "resource", "mode": "enforce", "action": "BLOCK"},
    {"id": "SUP-01", "name": "MCP tool pinning", "severity": "medium", "category": "supply_chain", "mode": "off", "action": "WARN"},
]


_NAMES = ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"]


def dec_name(v: Any) -> str:
    """AuditRecord JSON carries the Action IntEnum as int; accept names too."""
    if isinstance(v, bool) or v is None:
        return "ALLOW"
    if isinstance(v, int):
        return _NAMES[v] if 0 <= v < len(_NAMES) else "ALLOW"
    return str(v).upper()


class ConsoleStore:
    """Bounded in-memory audit store with pub/sub for SSE."""

    def __init__(self, budget_usd: float = 1.0, controls: list[dict[str, Any]] | None = None,
                 maxlen: int = 5000) -> None:
        self.budget_usd = budget_usd
        self.controls = [dict(c) for c in (controls or DEFAULT_CONTROLS)]
        self._records: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._subs: set[asyncio.Queue] = set()

    # -- ingest ---------------------------------------------------------
    def append(self, record: dict[str, Any]) -> None:
        self._records.append(record)
        for q in list(self._subs):
            try:
                q.put_nowait(record)
            except asyncio.QueueFull:
                pass

    def load_lines(self, lines) -> int:
        n = 0
        for line in lines:
            line = line.strip()
            if line:
                self.append(json.loads(line))
                n += 1
        return n

    def load_file(self, path: str | Path = FIXTURES) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        with p.open(encoding="utf-8") as f:
            return self.load_lines(f)

    # -- query ----------------------------------------------------------
    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        """Newest first."""
        if limit <= 0:
            return []
        return list(reversed(self._records))[:limit]

    def all(self) -> list[dict[str, Any]]:
        return list(self._records)

    def summary(self) -> dict[str, Any]:
        recs = list(self._records)
        prompts = [r for r in recs if r.get("stage") == "prompt"]
        by_dec: dict[str, int] = {}
        for r in prompts:
            d = dec_name(r.get("decision"))
            by_dec[d] = by_dec.get(d, 0) + 1
        cost = round(sum((r.get("usage") or {}).get("usd", 0.0) for r in recs), 6)
        cats: dict[str, int] = {}
        for r in recs:
            for f in r.get("findings", []):
                c = f.get("category", "other")
                cats[c] = cats.get(c, 0) + 1
        timeline: dict[str, dict[str, int]] = {}
        for r in recs:
            b = str(r.get("ts", ""))[:16]
            row = timeline.setdefault(b, {"allow": 0, "redact": 0, "block": 0})
            d = dec_name(r.get("decision"))
            row["block" if d == "BLOCK" else "redact" if d == "REDACT" else "allow"] += 1
        enforced = sum(1 for c in self.controls if c.get("mode") == "enforce")
        total_c = len(self.controls)
        return {
            "requests": len(prompts),
            "allowed": by_dec.get("ALLOW", 0) + by_dec.get("LOG", 0) + by_dec.get("WARN", 0),
            "redacted": by_dec.get("REDACT", 0),
            "blocked": by_dec.get("BLOCK", 0),
            "cost_usd": cost,
            "budget_usd": self.budget_usd,
            "budget_used_pct": round(100 * cost / self.budget_usd, 1) if self.budget_usd else 0.0,
            "controls_total": total_c,
            "controls_enforced": enforced,
            "posture_pct": round(100 * enforced / total_c, 1) if total_c else 0.0,
            "categories": cats,
            "timeline": [{"t": k, **v} for k, v in sorted(timeline.items())],
            "events_total": len(recs),
        }

    def control_rows(self) -> list[dict[str, Any]]:
        hits: dict[str, int] = {}
        for r in self._records:
            for f in r.get("findings", []):
                cid = f.get("control_id", "")
                hits[cid] = hits.get(cid, 0) + 1
        return [{**c, "hits": hits.get(c["id"], 0)} for c in self.controls]

    # -- pub/sub --------------------------------------------------------
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)


def store_with_fixtures(**kw) -> ConsoleStore:
    s = ConsoleStore(**kw)
    s.load_file(FIXTURES)
    return s


CSV_COLUMNS = ["ts", "event_id", "request_id", "event_type", "severity", "decision", "would_decision", "stage",
               "channel", "agent_id", "model", "destination", "tool", "controls", "categories",
               "redaction_count", "usd", "policy_version"]


def _csv_row(r: dict[str, Any]) -> list[Any]:
    fs = r.get("findings", [])
    return [r.get("ts"), r.get("event_id"), r.get("request_id"), r.get("event_type"), r.get("severity"),
            dec_name(r.get("decision")), dec_name(r.get("would_decision")) if r.get("would_decision") is not None else "", r.get("stage"), r.get("channel"), r.get("agent_id"),
            r.get("model"), r.get("destination"), r.get("tool"),
            "|".join(sorted({f.get("control_id", "") for f in fs})),
            "|".join(sorted({f.get("category", "") for f in fs})),
            r.get("redaction_count", 0), (r.get("usage") or {}).get("usd", 0.0), r.get("policy_version")]


def make_console_router(store: ConsoleStore) -> APIRouter:
    router = APIRouter(prefix="/console")

    @router.get("")
    @router.get("/")
    async def index():
        return FileResponse(CONSOLE_DIR / "index.html", media_type="text/html")

    @router.get("/static/{name}")
    async def static(name: str):
        p = (CONSOLE_DIR / name).resolve()
        if p.parent != CONSOLE_DIR.resolve() or not p.is_file() or p.name == "fixtures.jsonl":
            return JSONResponse({"error": "not found"}, status_code=404)
        return FileResponse(p)

    @router.get("/api/summary")
    async def summary():
        return store.summary()

    @router.get("/api/controls")
    async def controls():
        return {"controls": store.control_rows()}

    @router.get("/api/events")
    async def events(limit: int = Query(100, ge=0, le=5000)):
        return {"events": store.list(limit)}

    @router.get("/api/export.jsonl")
    async def export_jsonl():
        body = "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in store.all())
        return Response(body, media_type="application/x-ndjson",
                        headers={"Content-Disposition": "attachment; filename=audit.jsonl"})

    @router.get("/api/export.csv")
    async def export_csv():
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(CSV_COLUMNS)
        for r in store.all():
            w.writerow(_csv_row(r))
        return Response(buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=audit.csv"})

    @router.get("/api/stream")
    async def stream(replay: int = Query(0, ge=0, le=500), max_events: int = Query(0, ge=0)):
        """SSE of new AuditRecords. replay=N sends the last N first; max_events>0 closes after that many (tests)."""
        q = store.subscribe()
        backlog = list(store.all())[-replay:] if replay else []

        async def gen():
            sent = 0
            try:
                yield ": connected\n\n"
                for r in backlog:
                    yield f"id: {r.get('event_id', '')}\nevent: audit\ndata: {json.dumps(r)}\n\n"
                    sent += 1
                    if max_events and sent >= max_events:
                        return
                while True:
                    try:
                        r = await asyncio.wait_for(q.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
                        continue
                    yield f"id: {r.get('event_id', '')}\nevent: audit\ndata: {json.dumps(r)}\n\n"
                    sent += 1
                    if max_events and sent >= max_events:
                        return
            finally:
                store.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return router

"""Console API (T-105): in-memory audit store + FastAPI router for the dashboard.

make_console_router(store) -> APIRouter. Mount it on the gateway app (or any FastAPI app).
Records are AuditRecord JSON dicts (contracts/aicl_contracts.py). Raw text never appears here.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from collections import deque
from itertools import islice
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

CONSOLE_DIR = Path(__file__).parent / "console"
FIXTURES = CONSOLE_DIR / "fixtures.jsonl"

# Static catalog: display name, severity and category per control id. Mode and default action come
# from policy.yaml when a policy is attached (controls_from_policy); this list is the offline default.
CATALOG: dict[str, dict[str, str]] = {
    "DLP-01": {"name": "Secret detection (AWS, GitHub, PEM, JWT)", "severity": "critical", "category": "secret"},
    "DLP-02": {"name": "PII detection with validators (PESEL, IBAN, card, e-mail)", "severity": "high", "category": "pii"},
    "DLP-05": {"name": "Destination DLP (data class x local / external / unknown)", "severity": "high", "category": "pii"},
    "INJ-03": {"name": "Injection signatures + historical exploit rules", "severity": "high", "category": "injection"},
    "INJ-04": {"name": "Semantic injection judge (local LLM, gray band)", "severity": "high", "category": "injection"},
    "TOOL-01": {"name": "Tool authorization + argument rules", "severity": "critical", "category": "tool_abuse"},
    "BUD-01": {"name": "Budgets (tokens, USD) + loop guard", "severity": "medium", "category": "resource"},
}
DEFAULT_ACTIONS = {"DLP-01": "REDACT", "DLP-02": "REDACT", "DLP-05": "BLOCK", "INJ-03": "BLOCK", "INJ-04": "WARN",
                   "TOOL-01": "BLOCK", "BUD-01": "BLOCK"}
DEFAULT_CONTROLS: list[dict[str, Any]] = [
    {"id": cid, **meta, "mode": "enforce", "action": DEFAULT_ACTIONS[cid]} for cid, meta in CATALOG.items()]


def _mode(v: Any, profile: str, default: Any = "enforce") -> str:
    """policy mode: word, per-profile map, or a YAML 1.1 boolean (bare off -> False). Same fallbacks as
    the w2 engine (Policy.mode_for): missing mode -> defaults.mode, profile missing from a map -> enforce."""
    if v is None:
        v = default
    if isinstance(v, dict):
        v = v.get(profile, "enforce")
    if v is False:
        return "off"
    if v is True or v is None:
        return "enforce"
    v = str(v).lower()
    return v if v in ("enforce", "shadow", "off") else "enforce"


def _action(c: dict[str, Any], cid: str) -> str:
    a = c.get("action")
    if isinstance(a, str):
        return a.upper()
    if isinstance(a, dict) and a:
        acts = {str(x).upper() for x in a.values()}
        order = ("BLOCK", "REDACT", "WARN", "LOG", "ALLOW")
        return "/".join(x for x in order if x in acts) or DEFAULT_ACTIONS.get(cid, "BLOCK")
    if c.get("default"):
        return str(c["default"]).upper()
    return DEFAULT_ACTIONS.get(cid, "BLOCK")


def controls_from_policy(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Rows for the controls table from a raw policy dict. Catalog controls missing from the policy stay
    in the list as mode off (they count against posture, research/13 section 14)."""
    defaults = policy.get("defaults") or {}
    profile = str(defaults.get("profile") or "balanced")
    pcs = policy.get("controls") or {}
    if not isinstance(pcs, dict):
        pcs = {}
    rows = []
    for cid in dict.fromkeys([*CATALOG, *pcs]):
        c = pcs.get(cid)
        meta = CATALOG.get(cid, {"name": str(cid), "severity": "medium", "category": "other"})
        if not isinstance(c, dict):
            rows.append({"id": cid, **meta, "mode": "off", "action": DEFAULT_ACTIONS.get(cid, "BLOCK")})
            continue
        rows.append({"id": cid, **meta, "mode": _mode(c.get("mode"), profile, defaults.get("mode", "enforce")), "action": _action(c, cid)})
    return rows


def budget_from_policy(policy: dict[str, Any]) -> float | None:
    org = (policy.get("budgets") or {}).get("org") or {}
    try:
        return float(org["usd"])
    except (KeyError, TypeError, ValueError):
        return None


_NAMES = ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"]


def dec_name(v: Any) -> str:
    """AuditRecord JSON carries the Action IntEnum as int; accept names too."""
    if isinstance(v, bool) or v is None:
        return "ALLOW"
    if isinstance(v, int):
        return _NAMES[v] if 0 <= v < len(_NAMES) else "ALLOW"
    return str(v).upper()


def dec_rank(v: Any) -> int:
    n = dec_name(v)
    return _NAMES.index(n) if n in _NAMES else 0


PolicySource = Callable[[], "dict[str, Any] | None"]


class ConsoleStore:
    """Bounded in-memory audit store with pub/sub for SSE.

    policy: raw policy dict or a callable returning it (hot reload); drives the controls table and the
    org USD budget. controls / budget_usd given explicitly win over the policy.
    """

    def __init__(self, budget_usd: float | None = None, controls: list[dict[str, Any]] | None = None,
                 maxlen: int = 5000, policy: "dict[str, Any] | PolicySource | None" = None) -> None:
        self._budget_usd = budget_usd
        self._controls = [dict(c) for c in controls] if controls else None
        self._policy = policy
        self._records: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._subs: set[asyncio.Queue] = set()

    def policy(self) -> dict[str, Any] | None:
        p = self._policy
        if callable(p):
            try:
                p = p()
            except Exception:
                return None
        return p if isinstance(p, dict) else None

    @property
    def controls(self) -> list[dict[str, Any]]:
        if self._controls is not None:
            return self._controls
        pol = self.policy()
        return controls_from_policy(pol) if pol else [dict(c) for c in DEFAULT_CONTROLS]

    @property
    def budget_usd(self) -> float:
        if self._budget_usd is not None:
            return self._budget_usd
        pol = self.policy()
        b = budget_from_policy(pol) if pol else None
        return b if b is not None else 1.0

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
    def list(self, limit: int = 100, request_id: str | None = None) -> list[dict[str, Any]]:
        """Newest first; optionally only the records of one request."""
        if limit <= 0:
            return []
        recs = reversed(self._records)
        if request_id:
            recs = (r for r in recs if r.get("request_id") == request_id)
        return list(islice(recs, limit))

    def all(self) -> list[dict[str, Any]]:
        return list(self._records)

    def summary(self) -> dict[str, Any]:
        """KPIs (research/13 section 14): one request = one request_id; its final decision is the max
        over all its records (prompt, response, tool_args)."""
        recs = [r for r in self._records if r.get("stage") != "lifecycle"]
        final: dict[str, int] = {}
        bucket: dict[str, str] = {}          # request -> minute of its first record
        for i, r in enumerate(recs):
            rid = r.get("request_id") or r.get("event_id") or f"#{i}"
            final[rid] = max(final.get(rid, 0), dec_rank(r.get("decision")))
            bucket.setdefault(rid, str(r.get("ts", ""))[:16])
        by_dec = {n: 0 for n in _NAMES}
        for v in final.values():
            by_dec[_NAMES[v]] += 1
        cost, tokens = 0.0, 0
        cats: dict[str, int] = {}
        timeline: dict[str, dict[str, int]] = {}
        for r in recs:
            u = r.get("usage") or {}
            cost += u.get("usd") or 0.0
            tokens += (u.get("input_tokens") or 0) + (u.get("output_tokens") or 0)
            for f in r.get("findings", []):
                c = f.get("category", "other")
                cats[c] = cats.get(c, 0) + 1
        for rid, v in final.items():      # timeline counts requests by final decision, like the tiles
            row = timeline.setdefault(bucket[rid], {"allow": 0, "redact": 0, "block": 0})
            row["block" if v == 4 else "redact" if v == 3 else "allow"] += 1
        cost = round(cost, 6)
        controls = self.controls
        enforced = sum(1 for c in controls if c.get("mode") == "enforce")
        total_c = len(controls)
        budget = self.budget_usd
        return {
            "requests": len(final),
            "allowed": by_dec["ALLOW"] + by_dec["LOG"] + by_dec["WARN"],
            "redacted": by_dec["REDACT"],
            "blocked": by_dec["BLOCK"],
            "cost_usd": cost,
            "tokens": tokens,
            "budget_usd": budget,
            "budget_used_pct": round(100 * cost / budget, 1) if budget else 0.0,
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


LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def make_console_router(store: ConsoleStore, playground: dict | None = None,
                        expose_key: bool = False) -> APIRouter:
    """playground = {"api_key", "models"}; the key is handed only to loopback clients unless
    expose_key (console.expose_demo_key) is set for a firewalled demo host."""
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

    @router.get("/api/playground")
    async def playground_cfg(request: Request):
        pg = dict(playground or {"api_key": None, "models": {"local": [], "external": []}})
        host = request.client.host if request.client else ""
        if not (expose_key or host in LOOPBACK):
            pg["api_key"] = None
        return pg

    @router.get("/api/summary")
    async def summary():
        return store.summary()

    @router.get("/api/controls")
    async def controls():
        return {"controls": store.control_rows()}

    @router.get("/api/events")
    async def events(limit: int = Query(100, ge=0, le=5000), request_id: str | None = None):
        return {"events": store.list(limit, request_id)}

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

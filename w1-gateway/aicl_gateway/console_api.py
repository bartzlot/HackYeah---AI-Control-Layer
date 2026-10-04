"""Console API (T-105): in-memory audit store + FastAPI router for the dashboard.

make_console_router(store) -> APIRouter. Mount it on the gateway app (or any FastAPI app).
Records are AuditRecord JSON dicts (contracts/aicl_contracts.py). Raw text never appears here.
"""
from __future__ import annotations

import asyncio
import csv
import hmac
import ipaddress
import io
import json
from collections import deque
from itertools import islice
from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from . import names

CONSOLE_DIR = Path(__file__).parent / "console"
FIXTURES = CONSOLE_DIR / "fixtures.jsonl"

# Static catalog: display name, severity and category per control id. Mode and default action come
# from policy.yaml when a policy is attached (controls_from_policy); this list is the offline default.
_SEV = {"DLP-01": ("critical", "secret"), "DLP-02": ("high", "pii"), "DLP-05": ("high", "pii"), "INJ-03": ("high", "injection"),
        "INJ-04": ("high", "injection"), "TOOL-01": ("critical", "tool_abuse"), "BUD-01": ("medium", "resource")}
CATALOG: dict[str, dict[str, str]] = {
    cid: {"name": names.CONTROLS[cid][0], "description": names.CONTROLS[cid][1], "severity": sev, "category": cat,
          "layer": names.layer_of(cid)} for cid, (sev, cat) in _SEV.items()}
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
        nm = names.CONTROLS.get(cid)
        meta = CATALOG.get(cid) or {"name": nm[0] if nm else names.humanize(cid), "description": nm[1] if nm else "Control from the policy.",
                                    "severity": "medium", "category": "other", "layer": names.layer_of(cid)}
        if not isinstance(c, dict):
            rows.append({"id": cid, **meta, "mode": "off", "action": DEFAULT_ACTIONS.get(cid, "BLOCK")})
            continue
        rows.append({"id": cid, **meta, "mode": _mode(c.get("mode"), profile, defaults.get("mode", "enforce")), "action": _action(c, cid),
                     "mode_spec": c.get("mode", defaults.get("mode", "enforce")), "locked": cid in ("KILL-01", "ACCESS-01")})
    return rows


def budget_from_policy(policy: dict[str, Any]) -> float | None:
    org = (policy.get("budgets") or {}).get("org") or {}
    try:
        return float(org["usd"])
    except (KeyError, TypeError, ValueError):
        return None


_NAMES = ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"]
NON_DECISION = {"PASSTHROUGH", "DNS_QUERY", "BYPASS_SUSPECTED"}


def tool_of(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    for needle, name in (("claude-cli", "Claude Code"), ("claude-code", "Claude Code"), ("codex", "Codex"), ("anthropic-sdk", "Anthropic SDK"),
                         ("openai/", "OpenAI SDK"), ("python-httpx", "httpx"), ("curl", "curl")):
        if needle in ua:
            return name
    return (user_agent or "unknown").split("/")[0][:24]


def _count(items) -> dict[str, int]:
    out: dict[str, int] = {}
    for x in items:
        out[str(x)] = out.get(str(x), 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def _pcts(values, scale: float = 1.0) -> dict[str, float]:
    v = sorted(x / scale for x in values if isinstance(x, (int, float)))
    if not v:
        return {"p50": 0.0, "p95": 0.0, "max": 0.0}

    def pick(q: float) -> float:
        return v[min(len(v) - 1, int(round(q * (len(v) - 1))))]
    return {"p50": round(pick(0.5), 2), "p95": round(pick(0.95), 2), "max": round(v[-1], 2)}


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
                 maxlen: int = 5000, policy: "dict[str, Any] | PolicySource | None" = None,
                 budgets: "Callable[[], list[dict[str, Any]]] | None" = None) -> None:
        self._budget_usd = budget_usd
        self._controls = [dict(c) for c in controls] if controls else None
        self._policy = policy
        self._budgets = budgets             # ledger snapshot: per-agent spend vs limits (T-104)
        self._records: deque[dict[str, Any]] = deque(maxlen=maxlen)
        self._subs: set[asyncio.Queue] = set()
        self.catalog: "Callable[[], names.Catalog]" = names.Catalog   # names of controls and rules (T-123); main.py wires the live policy

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
        names.enrich(record)                # detection_layer for the feed and the exports (T-123)
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

    def load_tail(self, path: str | Path, n: int = 5000) -> int:
        """The last n records of the audit JSONL: the console keeps its history across a restart."""
        p = Path(path)
        if not p.is_file():
            return 0
        lines = deque(maxlen=n)
        with p.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                lines.append(line)
        loaded = 0
        for line in lines:
            try:
                self._records.append(names.enrich(json.loads(line)))
                loaded += 1
            except ValueError:
                continue
        return loaded

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

    def explain(self, event_id: str) -> dict[str, Any] | None:
        """T-119 drawer: the decide() timeline of the request the clicked record belongs to (None = unknown id)."""
        from .explain import timeline
        rec = next((r for r in reversed(self._records) if r.get("event_id") == event_id), None)
        if rec is None:
            return None
        rid = rec.get("request_id")
        group = [r for r in self._records if r.get("request_id") == rid
                 and r.get("stage") not in ("lifecycle", "dns")] if rid else []
        return {"event_id": event_id, **timeline(group or [rec])}

    def decisions(self) -> list[dict[str, Any]]:
        """Records that are policy decisions on AI traffic (not DNS lookups, not proxied probes)."""
        return [r for r in self._records if r.get("stage") not in ("lifecycle", "dns")
                and r.get("event_type") not in NON_DECISION]

    def summary(self) -> dict[str, Any]:
        """KPIs (research/13 section 14): one request = one request_id; its final decision is the max
        over all its records (prompt, response, tool_args)."""
        recs = self.decisions()
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
            "agent_budgets": self.agent_budgets(),
            "clients": len({r.get("agent_id") for r in recs if r.get("protocol")}),
            "protocols": _count(r.get("protocol") or "managed" for r in recs if r.get("stage") == "prompt"),
            "bypass_alerts": sum(1 for r in self._records if r.get("event_type") == "BYPASS_SUSPECTED"),
            "overhead_ms": _pcts([(r.get("latency_us") or {}).get("total") for r in recs], 1000.0),
            "top_rules": self.top_rules(),
            "by_layer": _count(r["detection_layer"] for r in recs if r.get("detection_layer") and dec_rank(r.get("decision")) >= 3),
        }

    def top_rules(self, limit: int = 5) -> list[dict[str, Any]]:
        """Rules whose BLOCK finding decided a blocked record (shadow-mode findings do not count): rule id,
        control, name, count, last seen. Newest first among equal counts."""
        rows: dict[tuple[str, str], dict[str, Any]] = {}
        cat = self.catalog()
        for r in self.decisions():
            if dec_rank(r.get("decision")) != 4:
                continue
            seen: set[tuple[str, str]] = set()
            for f in r.get("findings", []):
                if dec_rank(f.get("action")) != 4:
                    continue
                key = (str(f.get("control_id") or ""), str(f.get("rule_id") or ""))
                if key in seen:
                    continue
                seen.add(key)
                row = rows.setdefault(key, {"rule_id": key[1], "control_id": key[0], "control_name": CATALOG.get(key[0], {}).get("name", ""),
                                            "rule_name": cat.rule(key[1], key[0])["name"], "layer": names.layer_of(key[0]),
                                            "category": f.get("category", ""), "count": 0, "last_seen": ""})
                row["count"] += 1
                row["last_seen"] = max(row["last_seen"], str(r.get("ts") or ""))
        return sorted(rows.values(), key=lambda x: (x["count"], x["last_seen"]), reverse=True)[:limit]

    # -- v4 views (research/14 s.9) ---------------------------------------------------------------
    def clients(self) -> list[dict[str, Any]]:
        """Who is behind the AI traffic: principal + address + tool, with spend and outcomes."""
        rows: dict[tuple, dict[str, Any]] = {}
        final: dict[tuple, dict[str, int]] = {}
        for r in self.decisions():
            key = (r.get("agent_id") or "anonymous", r.get("client_ip") or "-")
            row = rows.setdefault(key, {"principal": key[0], "client_ip": key[1], "tools": set(), "protocols": set(),
                                        "models": set(), "tokens": 0, "usd": 0.0, "last": "", "hosts": set()})
            if r.get("user_agent"):
                row["tools"].add(tool_of(r["user_agent"]))
            if r.get("protocol"):
                row["protocols"].add(r["protocol"])
            if r.get("model"):
                row["models"].add(r["model"])
            if r.get("upstream_host"):
                row["hosts"].add(r["upstream_host"])
            u = r.get("usage") or {}
            row["tokens"] += (u.get("input_tokens") or 0) + (u.get("output_tokens") or 0)
            row["usd"] += u.get("usd") or 0.0
            row["last"] = max(row["last"], str(r.get("ts") or ""))
            f = final.setdefault(key, {})
            rid = r.get("request_id") or r.get("event_id")
            f[rid] = max(f.get(rid, 0), dec_rank(r.get("decision")))
        out = []
        for key, row in rows.items():
            fin = list(final.get(key, {}).values())
            out.append({**{k: (sorted(v) if isinstance(v, set) else v) for k, v in row.items()},
                        "usd": round(row["usd"], 6), "requests": len(fin), "blocked": sum(1 for v in fin if v == 4),
                        "redacted": sum(1 for v in fin if v == 3)})
        return sorted(out, key=lambda x: x["last"], reverse=True)

    def network(self, resolver: dict[str, Any] | None = None) -> dict[str, Any]:
        dns = [r for r in self._records if r.get("stage") == "dns"]
        hosts = _count(r.get("upstream_host") for r in dns if r.get("upstream_host"))
        bypass = [r for r in self._records if r.get("event_type") == "BYPASS_SUSPECTED"]
        passthrough = [r for r in self._records if r.get("event_type") == "PASSTHROUGH"]
        return {"dns_records": len(dns), "intercepted_by_host": hosts,
                "bypass_alerts": [{"ts": r.get("ts"), "client_ip": r.get("client_ip"), "principal": r.get("agent_id"),
                                   "what": (r.get("explain") or [""])[0]} for r in reversed(bypass[-50:])],
                "passthrough": {"total": len(passthrough),
                                "paths": _count((r.get("explain") or [""])[0].split(" -> ")[0] for r in passthrough)},
                "resolver": resolver or {}, "last_request": self.last_request()}

    def last_request(self) -> dict[str, Any] | None:
        """The path the most recent request took, for the network diagram: was its host looked up through AICL DNS
        (an intercepted DNS_QUERY of the same client, stored before the request), what the decide() step said
        (max over the request's records) and where it went on: upstream, a block before the provider, or a block of the provider's answer."""
        recs = list(self._records)

        def is_decision(r: dict[str, Any]) -> bool:
            return r.get("stage") not in ("lifecycle", "dns") and r.get("event_type") not in NON_DECISION
        last = next((r for r in reversed(recs) if is_decision(r)), None)
        if last is None:
            return None
        rid = last.get("request_id") or last.get("event_id")
        idx = [i for i, r in enumerate(recs) if is_decision(r) and (r.get("request_id") or r.get("event_id")) == rid]
        group = [recs[i] for i in idx]
        worst = max(group, key=lambda r: dec_rank(r.get("decision")))
        host = next((r["upstream_host"] for r in group if r.get("upstream_host")), None)
        client_ip = next((r["client_ip"] for r in group if r.get("client_ip")), None)
        dns_seen = bool(host or client_ip) and any(r.get("stage") == "dns" and r.get("event_type") == "DNS_QUERY" and r.get("upstream_host")
                       and (not host or r["upstream_host"] == host) and (not client_ip or r.get("client_ip") == client_ip)
                       for r in recs[:idx[0]])
        decision = dec_name(worst.get("decision"))
        # BLOCK on the request side never reaches the provider; on model output (response, tool_args) it already did
        outcome = "upstream" if decision != "BLOCK" else "response_block" if worst.get("stage") in ("response", "tool_args") else "block"
        controls = sorted({f.get("control_id") for r in group for f in r.get("findings") or [] if f.get("control_id")})
        return {"request_id": rid, "ts": group[0].get("ts"), "principal": group[0].get("agent_id"), "client_ip": client_ip,
                "tool": tool_of(group[0]["user_agent"]) if group[0].get("user_agent") else None, "host": host,
                "protocol": next((r["protocol"] for r in group if r.get("protocol")), None),
                "model": next((r["model"] for r in group if r.get("model")), None),
                "destination": group[0].get("destination"), "decision": decision, "stage": worst.get("stage"),
                "controls": controls[:6], "dns_seen": dns_seen, "outcome": outcome}

    def performance(self) -> dict[str, Any]:
        """Decision latency per control (research/13 s.13): p50 / p95 / max in ms over the stored records."""
        per: dict[str, list[float]] = {}
        for r in self.decisions():
            for k, v in (r.get("latency_us") or {}).items():
                if isinstance(v, (int, float)):
                    per.setdefault(k, []).append(v)
        rows = [{"control": k, "count": len(v), **_pcts(v, 1000.0)} for k, v in per.items()]
        rows.sort(key=lambda x: (x["control"] != "total", -x["p95"]))
        return {"controls": rows}

    def agent_budgets(self) -> list[dict[str, Any]]:
        if not self._budgets:
            return []
        try:
            return list(self._budgets())
        except Exception:
            return []

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


def _cell(v: Any) -> Any:
    """CSV formula-injection guard: model and tool names come from clients / model output."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", chr(9), chr(13)):
        return "'" + v
    return v


def _csv_row(r: dict[str, Any]) -> list[Any]:
    return [_cell(v) for v in _csv_raw(r)]


def _csv_raw(r: dict[str, Any]) -> list[Any]:
    fs = r.get("findings", [])
    return [r.get("ts"), r.get("event_id"), r.get("request_id"), r.get("event_type"), r.get("severity"),
            dec_name(r.get("decision")), dec_name(r.get("would_decision")) if r.get("would_decision") is not None else "", r.get("stage"), r.get("channel"), r.get("agent_id"),
            r.get("model"), r.get("destination"), r.get("tool"),
            "|".join(sorted({f.get("control_id", "") for f in fs})),
            "|".join(sorted({f.get("category", "") for f in fs})),
            r.get("redaction_count", 0), (r.get("usage") or {}).get("usd", 0.0), r.get("policy_version")]


LOOPBACK = {"127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"}


def is_local(request: Request) -> bool:
    """Direct loopback client; anything relayed by a proxy (forwarded headers) is not local."""
    if request.headers.get("x-forwarded-for") or request.headers.get("forwarded"):
        return False
    return bool(request.client) and request.client.host in LOOPBACK


def make_console_router(store: ConsoleStore, playground: "dict | Callable[[], dict] | None" = None,
                        remote: bool = False, info: "dict[str, Callable[[], Any]] | None" = None,
                        deny_cidrs: "list[str] | None" = None, admin_token: str | None = None,
                        demo_batch: "Callable[[], Any] | None" = None) -> APIRouter:
    """The console (UI, audit API, exports, playground demo key) is host-only (research/13 section 14):
    non-loopback clients get 403 unless remote=True (console.remote, only on a firewalled demo host)."""

    denied = [ipaddress.ip_network(c, strict=False) for c in (deny_cidrs or []) if c]

    async def host_only(request: Request) -> None:
        if not remote and not is_local(request):
            raise HTTPException(403, "console is host-only (set console.remote on a firewalled demo host)")
        if denied and request.client:        # the client network (developer laptops) never reaches the console
            try:
                ip = ipaddress.ip_address(request.client.host)
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                    ip = ip.ipv4_mapped
            except ValueError:
                ip = None
            if ip is not None and any(ip in n for n in denied):
                raise HTTPException(403, "console is not served to the client network (AICL_CONSOLE_DENY_CIDRS)")

    router = APIRouter(prefix="/console", dependencies=[Depends(host_only)])

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
    async def playground_cfg():
        pg = playground() if callable(playground) else playground   # callable = live after policy reloads
        return pg or {"api_key": None, "models": {"local": [], "external": []}}

    @router.get("/api/summary")
    async def summary():
        return store.summary()

    @router.get("/api/controls")
    async def controls():
        return {"controls": store.control_rows()}

    @router.get("/api/events")
    async def events(limit: int = Query(100, ge=0, le=5000), request_id: str | None = None):
        return {"events": store.list(limit, request_id)}

    def _info(name: str, default: Any = None) -> Any:
        fn = (info or {}).get(name)
        try:
            return fn() if fn else default
        except Exception:  # noqa: BLE001 - a view must never break the console
            return default

    @router.get("/api/explain/{event_id}")
    async def explain(event_id: str):
        """T-119: per-request decide() timeline for the explain drawer (spans as hashes / tokens only)."""
        out = store.explain(event_id)
        if out is None:
            return JSONResponse({"error": "unknown event"}, status_code=404)
        return out

    @router.get("/api/catalog")
    async def catalog():
        """T-123: display name + one-line description for every control and rule id, and the detection layer."""
        return store.catalog().as_dict()

    @router.get("/api/demo/presets")
    async def demo_presets():
        from .demo_batch import PRESETS
        return {"presets": [{"id": p.id, "title": p.title, "control": p.control, "model": p.model, "expect": list(p.expect),
                             "repeat": p.repeat, "notes": p.notes} for p in PRESETS]}

    batch_lock = asyncio.Lock()

    @router.post("/api/demo/batch")
    async def demo_batch_run():
        """T-123 'Run demo batch': every preset through the gateway in this process; one batch at a time."""
        if demo_batch is None:
            raise HTTPException(501, "the demo batch is not wired in this process")
        if batch_lock.locked():
            raise HTTPException(409, "a demo batch is already running")
        async with batch_lock:
            try:
                return await demo_batch()
            except LookupError as e:
                raise HTTPException(409, str(e))

    @router.get("/api/clients")
    async def clients():
        return {"clients": store.clients()}

    @router.get("/api/network")
    async def network():
        return store.network(_info("dns", {}))

    @router.get("/api/performance")
    async def performance():
        return store.performance()

    @router.get("/api/judge")
    async def judge():
        """T-117: INJ-04 local judge state for the overview tile (model, warm / degraded, p50, cache)."""
        fn = (info or {}).get("judge")
        if fn is None:
            return {"control": "INJ-04", "status": "unknown", "reason": "judge is not wired in this process"}
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - a view must never break the console
            return {"control": "INJ-04", "status": "unknown", "reason": f"judge state unavailable: {type(e).__name__}"}

    @router.get("/api/status")
    async def status(request: Request):
        """T-116: the listeners this process really runs (HTTP, TLS, DNS), CA, upstream overrides and the mode
        they add up to; the header chip shows this instead of the policy's interception.mode."""
        fn = (info or {}).get("status")
        if fn is None:
            return {"mode": "unknown", "warnings": [], "notes": []}
        try:
            return fn(request.scope.get("server"))
        except Exception as e:  # noqa: BLE001 - a view must never break the console
            return {"mode": "unknown", "warnings": [f"status unavailable: {type(e).__name__}"], "notes": []}

    @router.get("/api/policy")
    async def policy():
        """Read-only view of the live policy: version, reload error, interception, files."""
        return _info("policy", {}) or {}

    def admin(request: Request) -> None:
        """Writes need Bearer AICL_ADMIN_TOKEN; with no token configured, only a direct loopback client may write."""
        if admin_token:
            got = request.headers.get("authorization", "")
            if not hmac.compare_digest(got.encode(), f"Bearer {admin_token}".encode()):
                raise HTTPException(401, "admin token required (Authorization: Bearer AICL_ADMIN_TOKEN)")
        elif not is_local(request):
            raise HTTPException(403, "set AICL_ADMIN_TOKEN to edit the policy from a non-loopback client")

    def who(request: Request) -> str:
        ip = request.client.host if request.client else "?"
        return f"{ip} ({'admin token' if admin_token else 'loopback'})"

    async def _write(kind: str, request: Request, *extra):
        admin(request)
        fn = (info or {}).get(kind)
        if fn is None:
            raise HTTPException(501, "policy editing is not wired in this process")
        if kind == "policy_write":
            ctype = request.headers.get("content-type", "")
            if ctype.startswith("application/json"):
                payload = (await request.json() or {}).get("yaml", "")
            else:
                payload = (await request.body()).decode("utf-8", "replace")
        else:
            payload = await request.json()
        try:
            return fn(*extra, payload, who(request))
        except Exception as e:  # noqa: BLE001 - PolicyWriteError carries the HTTP status
            status = getattr(e, "status", 422)
            return JSONResponse({"ok": False, "error": str(e)}, status_code=status)

    @router.get("/api/whoami")
    async def whoami(request: Request):
        """Can this browser edit? (drives the Unlock editing button; the PUT endpoints check again)."""
        try:
            admin(request)
            can = True
        except HTTPException:
            can = False
        return {"can_edit": can, "needs_token": bool(admin_token) or not is_local(request)}

    @router.put("/api/policy")
    async def put_policy(request: Request):
        """Replace policy.yaml: validated by the real loader first; 422 keeps the live file."""
        return await _write("policy_write", request)

    @router.put("/api/controls/{cid}")
    async def put_control(cid: str, request: Request):
        """Switch one control: off / shadow / enforce (per profile when given); only controls.<id>.mode changes."""
        return await _write("control_write", request, cid)

    @router.get("/api/interception")
    async def get_interception():
        fn = (info or {}).get("interception")
        return {"providers": fn() if fn else []}

    @router.put("/api/interception")
    async def put_interception(request: Request):
        """Add / remove an intercepted AI host, or add a provider; DNS and the TLS leaf follow the reload."""
        return await _write("interception_write", request)

    @router.get("/api/budgets")
    async def get_budgets():
        pol = store.policy() or {}
        b = pol.get("budgets") or {}
        return {"agents": b.get("agents") or {}, "org": b.get("org") or {}, "usage": store.agent_budgets()}

    @router.put("/api/budgets")
    async def put_budgets(request: Request):
        return await _write("budgets_write", request)

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

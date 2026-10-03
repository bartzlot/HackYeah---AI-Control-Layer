"""T-104 (BUD-01): token / USD budget ledger (SQLite, reserve then settle) and the agent loop guard.

research/13 section 10. One process owns the ledger: settled usage lives in SQLite (survives restarts
when budget_db is a file), open reservations are held in memory under a lock, so a burst of parallel
requests can never admit more than the cap (check + hold is one critical section).
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone

# USD per million tokens, used to size reservations for priced (external) models when the policy has no price.
DEFAULT_PRICES: dict[str, dict[str, float]] = {
    "gpt-4o-mini": {"in": 0.15, "out": 0.60},
    "gpt-4o": {"in": 2.50, "out": 10.00},
}
DEFAULT_LOOP_LIMITS = {"repeat_identical": 4}
DEFAULT_MAX_TOKENS = 512          # assumed output when the client sends no max_tokens
IMAGE_TOKENS = 1500               # flat input charge per image part in the reservation
LOOP_WINDOW = 20                  # per-session ring of recent call fingerprints
LOOP_MAX_AGE_S = 600              # fingerprints older than this fall out of the ring (policy max_wall_s)
LOOP_MAX_KEYS = 10_000            # LRU bound on tracked (agent, session) pairs


def period_bounds(period: str, now: datetime | None = None) -> tuple[str, float]:
    """(period key, seconds until the period ends). period: minute | hour | day | month."""
    now = now or datetime.now(timezone.utc)
    if period == "month":
        nxt = (now.replace(day=1) + timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return now.strftime("%Y-%m"), (nxt - now).total_seconds()
    if period == "hour":
        nxt = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        return now.strftime("%Y-%m-%dT%H"), (nxt - now).total_seconds()
    if period == "minute":
        nxt = now.replace(second=0, microsecond=0) + timedelta(minutes=1)
        return now.strftime("%Y-%m-%dT%H:%M"), (nxt - now).total_seconds()
    nxt = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return now.strftime("%Y-%m-%d"), (nxt - now).total_seconds()


class Reservation:
    """One held estimate; settle() or release() closes it exactly once."""
    __slots__ = ("agent", "period", "tokens", "usd", "open")

    def __init__(self, agent: str, period: str, tokens: int, usd: float):
        self.agent, self.period, self.tokens, self.usd, self.open = agent, period, tokens, usd, True


class BudgetLedger:
    """Per-agent usage ledger. limits shape = policy budgets.agents: {agent: {tokens, usd, period}}.

    reserve() checks spent + reserved + estimate against every cap of the agent and holds the estimate;
    settle() replaces the hold with the real usage; release() drops it (upstream failed).
    Agents without an entry are not capped (the model allowlist still applies).
    """

    def __init__(self, path: str | None = ":memory:", limits: dict | None = None, warn_at: float = 0.8):
        self.limits = {k: v for k, v in (limits or {}).items() if isinstance(v, dict)}
        self.warn_at = warn_at
        self._db = sqlite3.connect(path or ":memory:", check_same_thread=False)
        if path and path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS usage (agent TEXT NOT NULL, period TEXT NOT NULL,"
                         " tokens INTEGER NOT NULL DEFAULT 0, usd REAL NOT NULL DEFAULT 0, requests INTEGER NOT NULL"
                         " DEFAULT 0, denied INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (agent, period))")
        self._db.commit()
        self._lock = threading.Lock()
        self._held: dict[tuple[str, str], list[float]] = {}

    def _period(self, agent: str) -> tuple[str, float]:
        return period_bounds(str((self.limits.get(agent) or {}).get("period", "day")))

    def _used(self, agent: str, period: str) -> tuple[int, float]:
        row = self._db.execute("SELECT tokens, usd FROM usage WHERE agent=? AND period=?", (agent, period)).fetchone()
        return (row[0], row[1]) if row else (0, 0.0)

    def _bump(self, agent: str, period: str, tokens: int = 0, usd: float = 0.0, requests: int = 0,
              denied: int = 0) -> None:
        self._db.execute("INSERT INTO usage (agent, period, tokens, usd, requests, denied) VALUES (?, ?, ?, ?, ?, ?)"
                         " ON CONFLICT(agent, period) DO UPDATE SET tokens = tokens + excluded.tokens,"
                         " usd = usd + excluded.usd, requests = requests + excluded.requests,"
                         " denied = denied + excluded.denied", (agent, period, int(tokens), float(usd), requests, denied))
        self._db.commit()

    def used(self, agent: str) -> tuple[int, float]:
        with self._lock:
            return self._used(agent, self._period(agent)[0])

    def reserve(self, agent: str, tokens: int, usd: float = 0.0):
        """-> (reservation, None, None) when granted; (None, retry_after_s, reason) when over budget;
        (None, 0, reason) when this single request is larger than the whole cap (a retry can never fit)."""
        lim = self.limits.get(agent)
        period, left = self._period(agent)
        with self._lock:
            held = self._held.setdefault((agent, period), [0, 0.0])
            if lim:
                ut, uu = self._used(agent, period)
                reason = None
                if ((lim.get("tokens") is not None and tokens > lim["tokens"])
                        or (lim.get("usd") is not None and usd > float(lim["usd"]) + 1e-12)):
                    self._bump(agent, period, denied=1)
                    return None, 0, (f"request needs {tokens} tokens / {usd:.6f} USD, more than the whole budget"
                                     f" ({lim.get('tokens')} tokens / {lim.get('usd')} USD per"
                                     f" {lim.get('period', 'day')}); lower max_tokens")
                if lim.get("tokens") is not None and ut + held[0] + tokens > lim["tokens"]:
                    reason = (f"token budget: spent {ut} + reserved {int(held[0])} + request {tokens}"
                              f" > limit {lim['tokens']} per {lim.get('period', 'day')}")
                elif lim.get("usd") is not None and uu + held[1] + usd > float(lim["usd"]) + 1e-12:
                    reason = (f"USD budget: spent {uu:.6f} + reserved {held[1]:.6f} + request {usd:.6f}"
                              f" > limit {float(lim['usd']):.2f} per {lim.get('period', 'day')}")
                if reason:
                    self._bump(agent, period, denied=1)
                    return None, max(1, math.ceil(left)), reason
            held[0] += tokens
            held[1] += usd
            return Reservation(agent, period, tokens, usd), None, None

    def _drop(self, res: "Reservation") -> bool:
        """Remove the hold once; False when it was already settled or released."""
        if not res.open:
            return False
        res.open = False
        held = self._held.setdefault((res.agent, res.period), [0, 0.0])
        held[0] = max(0, held[0] - res.tokens)
        held[1] = max(0.0, held[1] - res.usd)
        return True

    def release(self, res) -> None:
        with self._lock:
            self._drop(res)

    def settle(self, res, tokens: int, usd: float) -> None:
        with self._lock:
            if self._drop(res):
                self._bump(res.agent, res.period, tokens, usd, requests=1)

    def record(self, agent: str, tokens: int, usd: float = 0.0) -> None:
        """Book usage directly (imports, tests, cases with pre-spent budgets)."""
        with self._lock:
            self._bump(agent, self._period(agent)[0], tokens, usd)

    def utilization(self, agent: str) -> float:
        """Max of tokens / usd spent as a fraction of the cap (0 when uncapped)."""
        lim = self.limits.get(agent)
        if not lim:
            return 0.0
        t, u = self.used(agent)
        fr = [0.0]
        if lim.get("tokens"):
            fr.append(t / lim["tokens"])
        if lim.get("usd"):
            fr.append(u / float(lim["usd"]))
        return max(fr)

    def snapshot(self) -> list[dict]:
        """Current-period rows per capped or active agent (console budgets)."""
        with self._lock:
            agents = set(self.limits) | {r[0] for r in self._db.execute("SELECT DISTINCT agent FROM usage")}
            rows = []
            for a in sorted(agents):
                period, left = self._period(a)
                t, u = self._used(a, period)
                held = self._held.get((a, period), [0, 0.0])
                r = self._db.execute("SELECT requests, denied FROM usage WHERE agent=? AND period=?",
                                     (a, period)).fetchone() or (0, 0)
                lim = self.limits.get(a) or {}
                rows.append({"agent_id": a, "period": period, "resets_in_s": int(left), "tokens": t,
                             "usd": round(u, 6), "reserved_tokens": int(held[0]), "reserved_usd": round(held[1], 6),
                             "limit_tokens": lim.get("tokens"), "limit_usd": lim.get("usd"),
                             "requests": r[0], "denied": r[1]})
            return rows

    def close(self) -> None:
        self._db.close()


def output_cap(body: dict) -> int:
    """Positive output cap the request will run with: the larger of max_tokens / max_completion_tokens,
    DEFAULT_MAX_TOKENS when neither is a positive integer (Ollama treats -1 / missing as unlimited)."""
    vals = [v for v in (body.get("max_tokens"), body.get("max_completion_tokens"))
            if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v > 0]
    return int(max(vals)) if vals else DEFAULT_MAX_TOKENS


def estimate_split(body: dict, price: dict | None) -> tuple[int, int, float]:
    """Pessimistic (input tokens, output tokens, usd): ceil(utf8 bytes / 3) over the whole request except
    the model name (messages, tools, response_format; never under-counts, chars / 4 under-counts Polish by
    24 %) plus the output cap."""
    images = [0]

    def strip_images(v):     # an image costs ~IMAGE_TOKENS, not its base64 length / 3
        if isinstance(v, dict):
            if v.get("type") in ("image_url", "input_image", "image"):
                images[0] += 1
                return "[image]"
            return {k: strip_images(x) for k, x in v.items()}
        if isinstance(v, list):
            return [strip_images(x) for x in v]
        return v

    rest = strip_images({k: v for k, v in body.items() if k not in ("model", "stream", "stream_options")})
    raw = json.dumps(rest, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    tin, out = math.ceil(len(raw) / 3) + images[0] * IMAGE_TOKENS, output_cap(body)
    usd = (tin * price["in"] + out * price["out"]) / 1e6 if price else 0.0
    return tin, out, usd


def estimate(body: dict, price: dict | None) -> tuple[int, float]:
    tin, out, usd = estimate_split(body, price)
    return tin + out, usd


def config_from_policy(policy: dict) -> dict:
    """Gateway config keys for BUD-01 from a raw policy dict (budgets.agents, budgets.unpriced_model,
    budgets.ladder.warn_at, loop_limits, destinations.models.*.price). Used by the entrypoint (T-901)."""
    b = policy.get("budgets") or {}
    out = {"budgets": {k: v for k, v in (b.get("agents") or {}).items() if isinstance(v, dict)},
           "budget": {"unpriced_model": str(b.get("unpriced_model", "BLOCK")).upper(),
                      "warn_at": float((b.get("ladder") or {}).get("warn_at", 0.8))},
           "prices": prices_from_policy(policy)}
    if isinstance(policy.get("loop_limits"), dict):
        out["loop_limits"] = dict(policy["loop_limits"])
    return out


def prices_from_policy(policy: dict) -> dict[str, dict[str, float]]:
    """destinations.models.<tag>.price {in_usd_per_mtok, out_usd_per_mtok} -> {tag: {in, out}}."""
    out = {}
    models = ((policy.get("destinations") or {}).get("models")) or {}
    for tag, m in models.items():
        p = (m or {}).get("price") if isinstance(m, dict) else None
        if isinstance(p, dict) and "in_usd_per_mtok" in p and "out_usd_per_mtok" in p:
            out[tag] = {"in": float(p["in_usd_per_mtok"]), "out": float(p["out_usd_per_mtok"])}
    return out


def _norm(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _h(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def last_user_fingerprint(messages: list[dict]) -> str | None:
    """Fingerprint of a fresh user turn (last message is from the user); None mid tool-loop."""
    m = messages[-1] if messages else None
    if not isinstance(m, dict) or m.get("role") != "user":
        return None
    c = m.get("content")
    if isinstance(c, list):   # text parts plus a digest of non-text parts (images differ by content)
        c = json.dumps([p.get("text") if isinstance(p, dict) and "text" in p else p for p in c],
                       sort_keys=True, ensure_ascii=False, default=str)
    text = _norm(c if isinstance(c, str) else json.dumps(c, sort_keys=True, default=str))
    return "msg:" + _h(text) if text else None


def tool_fingerprint(name: str, args) -> str:
    """(tool, normalized args): key order and whitespace / case inside string values do not matter."""
    def norm(v):
        if isinstance(v, dict):
            return {str(k): norm(x) for k, x in v.items()}
        if isinstance(v, list):
            return [norm(x) for x in v]
        return _norm(v) if isinstance(v, str) else v
    return "tool:" + _h(name, json.dumps(norm(args), sort_keys=True, ensure_ascii=False, default=str))


class LoopGuard:
    """Per (agent, session) ring of the last LOOP_WINDOW call fingerprints younger than LOOP_MAX_AGE_S.
    The Nth identical call (repeat_identical, default 4) trips: with a session id the session is terminated
    (every later call is blocked); without one only repeats of that call are blocked while they stay in
    the ring. Prompt fingerprints are only fed for requests with a session id (see app.py), so a presenter
    repeating a prompt in the playground is not mistaken for a loop. Bounded: LRU over LOOP_MAX_KEYS pairs."""

    def __init__(self, limits: dict | None = None, clock=time.monotonic):
        lim = {**DEFAULT_LOOP_LIMITS, **{k: v for k, v in (limits or {}).items() if v is not None}}
        self.threshold = max(2, int(lim["repeat_identical"]))
        self.max_age = float(lim.get("max_wall_s") or LOOP_MAX_AGE_S)
        self._clock = clock
        self._rings: OrderedDict[tuple[str, str], deque] = OrderedDict()
        self._killed: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._lock = threading.Lock()

    def killed(self, agent: str, session: str | None) -> bool:
        return session is not None and (agent, session) in self._killed

    def observe(self, agent: str, session: str | None, fp: str | None) -> bool:
        """Record one call; True when this call must be blocked (loop tripped or session terminated)."""
        key = (agent, session if session is not None else "\x00no-session")
        now = self._clock()
        with self._lock:
            if key in self._killed:
                return True
            if fp is None:
                return False
            ring = self._rings.pop(key, None) or deque(maxlen=LOOP_WINDOW)
            self._rings[key] = ring                       # most recently used last
            while ring and now - ring[0][0] > self.max_age:
                ring.popleft()
            ring.append((now, fp))
            while len(self._rings) > LOOP_MAX_KEYS:
                self._rings.popitem(last=False)
            if sum(1 for _, x in ring if x == fp) >= self.threshold:
                if session is not None:
                    self._killed[key] = now
                    self._rings.pop(key, None)
                    while len(self._killed) > LOOP_MAX_KEYS:
                        self._killed.popitem(last=False)
                return True
            return False

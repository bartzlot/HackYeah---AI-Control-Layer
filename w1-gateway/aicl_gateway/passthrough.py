"""v4 passthrough PEP (research/14): AI API clients (Claude Code, Codex, SDKs) reach the real provider through AICL.

Routing (no client change in transparent mode):
  Host / SNI = an intercepted provider host (AICL DNS points it at us)   -> that provider, path as sent
  /anthropic/<path>, /openai/<path> on the gateway's own host (mode A)   -> that provider, prefix stripped
  /v1/messages, /api/hello on the gateway's own host (ANTHROPIC_BASE_URL) -> anthropic

Per inspected request (`interception.providers.<p>.inspect`): identity (client ip + key fingerprint + user agent ->
`clients:`) -> model allowlist -> decide() on the prompt parts (tool results are untrusted) -> redaction in place
-> budget reserve -> forward with the client's own credentials -> buffer the answer -> decide() on the text and on
every tool call -> native answer (unchanged bytes when nothing changed) -> settle the budget. Blocks use the
provider's own contract (`interception.block_style`, measured on Claude Code in research/14 s.3). Every other
path is proxied as a byte stream and audited.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Awaitable, Callable

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from aicl_contracts import Action, Decision, DestKind, Event, Part, Stage, ToolCall, Usage
from aicl_core import interception as icpt
from aicl_core.engine import resolve_destination

from .budget import prices_from_policy

HOP = {"host", "content-length", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
       "trailer", "transfer-encoding", "upgrade", "accept-encoding"}
RESP_DROP = {"content-length", "transfer-encoding", "connection", "content-encoding", "keep-alive"}
PREFIXES = {"/anthropic": "anthropic", "/openai": "openai"}
ANTHROPIC_BARE = ("/v1/messages", "/api/")       # served for ANTHROPIC_BASE_URL=http://gateway:port
CHARS_PER_TOKEN = 4


# ------------------------------------------------------------------------------------------------ helpers

def credential_hash(headers) -> str | None:
    """sha256(client key)[:8] from x-api-key or Authorization: Bearer; the key itself is never stored."""
    key = headers.get("x-api-key") or ""
    auth = headers.get("authorization") or ""
    if not key and auth.lower().startswith("bearer "):
        key = auth[7:].strip()
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8] if key else None


def _why(d: Decision) -> str:
    lines = [ln for ln in d.explain[1:-1] if ln] or d.explain[-1:]
    return "; ".join(lines[-2:]) or "blocked by policy"


@dataclass
class Slot:
    """Where one text part lives in the request JSON (a path of keys / indices to the string)."""
    path: tuple
    part: Part


@dataclass
class Parsed:
    model: str
    stream: bool
    slots: list[Slot]
    session: str | None = None
    est_out: int = 4096


@dataclass
class Answer:
    """The provider's answer reduced to what the controls look at, plus how to rebuild it."""
    texts: list[tuple[int, str]] = field(default_factory=list)        # (block index, text)
    tools: list[tuple[int, ToolCall]] = field(default_factory=list)   # (block index, call)
    usage: Usage | None = None
    cache_read: int = 0          # prompt-cache tokens inside usage.input_tokens (billed at a fraction)
    cache_write: int = 0


CACHE_READ_X, CACHE_WRITE_X = 0.1, 1.25   # Anthropic standard multipliers (pricing page, 2026-10-04)


def usage_usd(a: "Answer", usage: Usage, price: dict | None) -> float:
    if not price:
        return 0.0
    plain = max(0, usage.input_tokens - a.cache_read - a.cache_write)
    return (plain * price["in"] + a.cache_read * price["in"] * CACHE_READ_X
            + a.cache_write * price["in"] * CACHE_WRITE_X + usage.output_tokens * price["out"]) / 1e6


class BodyError(ValueError):
    pass


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:      # a provider parser may keep the FIRST value while we inspected the last one
            raise BodyError(f"duplicate JSON key {k!r}")
        d[k] = v
    return d


def strict_json(raw: bytes) -> Any:
    """JSON with duplicate keys and pathological nesting refused (never inspect one view, forward another)."""
    try:
        return json.loads(raw, object_pairs_hook=_no_dupes)
    except RecursionError as e:
        raise BodyError("JSON nested too deeply") from e
    except UnicodeDecodeError as e:
        raise BodyError(f"body is not UTF-8: {e}") from e


def _set_path(obj: Any, path: tuple, value: Any) -> None:
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value


def apply_spans(text: str, reds) -> str:
    floor = len(text) + 1
    for r in sorted(reds, key=lambda r: (r.start, r.end), reverse=True):
        if r.end > floor:
            continue
        text = text[:r.start] + r.replacement + text[r.end:]
        floor = r.start
    return text


# ------------------------------------------------------------------------------------------------ SSE

def sse_parse(raw: bytes) -> list[tuple[str | None, str]]:
    """Raw SSE bytes -> [(event name, data string)] (comments and blank keep-alives dropped)."""
    out = []
    for block in raw.replace(b"\r\n", b"\n").split(b"\n\n"):
        name, data = None, []
        for line in block.decode("utf-8", "replace").split("\n"):
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip(" ") if line[5:6] == " " else line[5:])
        if name is not None or data:
            out.append((name, "\n".join(data)))
    return out


def sse_dump(events: list[tuple[str | None, str]]) -> bytes:
    parts = []
    for name, data in events:
        parts.append((f"event: {name}\n" if name else "") + f"data: {data}\n\n")
    return "".join(parts).encode("utf-8")


# ------------------------------------------------------------------------------------------------ adapters

class AnthropicMessages:
    """Anthropic Messages API (POST /v1/messages), streaming and not."""
    protocol = "anthropic_messages"

    # ---- request
    def parse(self, body: dict) -> Parsed:
        slots: list[Slot] = []
        sysp = body.get("system")
        if isinstance(sysp, str):
            slots.append(Slot(("system",), Part(role="system", text=sysp)))
        elif isinstance(sysp, list):
            for i, b in enumerate(sysp):
                if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str):
                    slots.append(Slot(("system", i, "text"), Part(role="system", text=b["text"])))
        for mi, m in enumerate(body.get("messages") or []):
            if not isinstance(m, dict):
                continue
            role = str(m.get("role", "user"))
            c = m.get("content")
            if isinstance(c, str):
                slots.append(Slot(("messages", mi, "content"), Part(role=role, text=c)))
                continue
            for ci, b in enumerate(c if isinstance(c, list) else []):
                if not isinstance(b, dict):
                    continue
                t = b.get("type")
                if t == "text" and isinstance(b.get("text"), str):
                    # Claude Code wraps its own context (CLAUDE.md, tool lists, environment) in <system-reminder>
                    # blocks inside user turns: system-prompt scaffold, still scanned by every deterministic
                    # control, but not sent to the semantic judge (no attacker channel, and a false positive there
                    # would block every session)
                    scaffold = role == "user" and b["text"].lstrip().startswith("<system-reminder>")
                    slots.append(Slot(("messages", mi, "content", ci, "text"),
                                      Part(role="system" if scaffold else role, text=b["text"])))
                elif t == "tool_result":     # output of a tool the agent ran: web pages, files, command output
                    tc = b.get("content")
                    if isinstance(tc, str):
                        slots.append(Slot(("messages", mi, "content", ci, "content"),
                                          Part(role="tool", text=tc, trusted=False)))
                    elif isinstance(tc, list):
                        for ti, tb in enumerate(tc):
                            if isinstance(tb, dict) and tb.get("type") == "text" and isinstance(tb.get("text"), str):
                                slots.append(Slot(("messages", mi, "content", ci, "content", ti, "text"),
                                                  Part(role="tool", text=tb["text"], trusted=False)))
                # thinking / redacted_thinking (signed), tool_use history, images, documents: never touched
        meta = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
        mt = body.get("max_tokens")
        return Parsed(model=str(body.get("model") or ""), stream=bool(body.get("stream")), slots=slots,
                      session=str(meta.get("user_id"))[:200] if meta.get("user_id") else None,
                      est_out=int(mt) if isinstance(mt, int) and mt > 0 else 4096)

    # ---- native blocks
    def error(self, status: int, etype: str, message: str, rid: str) -> Response:
        return JSONResponse({"type": "error", "error": {"type": etype, "message": message}, "request_id": rid},
                            status_code=status, headers={"request-id": rid})

    def text_reply(self, model: str, text: str, stream: bool, rid: str, usage_in: int = 0) -> Response:
        msg = {"id": "msg_aicl_" + rid[-12:], "type": "message", "role": "assistant", "model": model,
               "content": [{"type": "text", "text": text}], "stop_reason": "end_turn", "stop_sequence": None,
               "usage": {"input_tokens": usage_in, "output_tokens": 0}}
        if not stream:
            return JSONResponse(msg, headers={"request-id": rid})
        start = dict(msg, content=[], stop_reason=None)
        evs = [("message_start", {"type": "message_start", "message": start}),
               ("content_block_start", {"type": "content_block_start", "index": 0,
                                        "content_block": {"type": "text", "text": ""}}),
               ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                        "delta": {"type": "text_delta", "text": text}}),
               ("content_block_stop", {"type": "content_block_stop", "index": 0}),
               ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn",
                                                                     "stop_sequence": None},
                                  "usage": {"output_tokens": 0}}),
               ("message_stop", {"type": "message_stop"})]
        return Response(sse_dump([(n, json.dumps(d)) for n, d in evs]), media_type="text/event-stream",
                        headers={"request-id": rid})

    # ---- response
    def read_json(self, resp: dict) -> Answer:
        a = Answer()
        for i, b in enumerate(resp.get("content") or []):
            if isinstance(b, dict) and b.get("type") == "text":
                a.texts.append((i, str(b.get("text") or "")))
            elif isinstance(b, dict) and b.get("type") in ("tool_use", "server_tool_use"):
                inp = b.get("input") if isinstance(b.get("input"), dict) else {"_value": b.get("input")}
                a.tools.append((i, ToolCall(name=str(b.get("name") or ""), arguments=inp)))
        u = resp.get("usage") or {}
        a.usage = _anthropic_usage(u)
        a.cache_read, a.cache_write = _cache_tokens(u)
        return a

    def read_sse(self, events: list[tuple[str | None, str]]) -> tuple[Answer, dict]:
        """-> (answer, state) where state keeps the parsed events per block for a rebuild."""
        a, blocks, usage_in, usage_out, cache = Answer(), {}, 0, 0, {}
        parsed = []
        for name, data in events:
            try:
                d = json.loads(data) if data and data[:1] in "{[" else None
            except ValueError:
                d = None
            parsed.append((name, data, d))
            if not isinstance(d, dict):
                continue
            t = d.get("type")
            if t == "message_start":
                u = (d.get("message") or {}).get("usage") or {}
                usage_in = int(u.get("input_tokens") or 0)
                cache = u
            elif t == "content_block_start":
                cb = d.get("content_block") or {}
                blocks[d.get("index")] = {"type": cb.get("type"), "name": cb.get("name"), "text": [], "json": []}
            elif t == "content_block_delta":
                b = blocks.get(d.get("index"))
                delta = d.get("delta") or {}
                if b is not None and delta.get("type") == "text_delta":
                    b["text"].append(str(delta.get("text") or ""))
                elif b is not None and delta.get("type") == "input_json_delta":
                    b["json"].append(str(delta.get("partial_json") or ""))
            elif t == "message_delta":
                usage_out = int(((d.get("usage") or {}).get("output_tokens")) or usage_out)
        for i, b in sorted(blocks.items(), key=lambda kv: kv[0] if isinstance(kv[0], int) else -1):
            if b["type"] == "text":
                a.texts.append((i, "".join(b["text"])))
            elif b["type"] in ("tool_use", "server_tool_use"):
                try:
                    args = json.loads("".join(b["json"]) or "{}")
                except ValueError:
                    args = {"_raw": "".join(b["json"])}
                a.tools.append((i, ToolCall(name=str(b["name"] or ""), arguments=args if isinstance(args, dict)
                                            else {"_value": args})))
        a.usage = _anthropic_usage({**cache, "input_tokens": usage_in, "output_tokens": usage_out})
        a.cache_read, a.cache_write = _cache_tokens(cache)
        return a, {"events": parsed}

    def rebuild_json(self, resp: dict, new_text: dict[int, str], drop_tools: set[int], note: str | None) -> dict:
        out = copy.deepcopy(resp)
        content = out.get("content") or []
        for i, b in enumerate(content):
            if i in new_text:
                b["text"] = new_text[i]
            if i in drop_tools:
                content[i] = {"type": "text", "text": note or "[AICL] tool call blocked"}
        if drop_tools:
            out["stop_reason"] = "end_turn"
        return out

    def rebuild_sse(self, state: dict, new_text: dict[int, str], drop_tools: set[int], note: str | None) -> bytes:
        """Original events, with each changed block replaced by one start / delta / stop of the new text."""
        out: list[tuple[str | None, str]] = []
        changed = set(new_text) | drop_tools
        for name, data, d in state["events"]:
            idx = d.get("index") if isinstance(d, dict) else None
            t = d.get("type") if isinstance(d, dict) else None
            if idx in changed and t in ("content_block_start", "content_block_delta", "content_block_stop"):
                if t == "content_block_start":
                    text = new_text.get(idx, note or "[AICL] tool call blocked") if idx not in drop_tools \
                        else (note or "[AICL] tool call blocked")
                    for ev in ({"type": "content_block_start", "index": idx,
                                "content_block": {"type": "text", "text": ""}},
                               {"type": "content_block_delta", "index": idx,
                                "delta": {"type": "text_delta", "text": text}},
                               {"type": "content_block_stop", "index": idx}):
                        out.append((ev["type"], json.dumps(ev)))
                continue
            if t == "message_delta" and drop_tools:
                d = copy.deepcopy(d)
                d.setdefault("delta", {})["stop_reason"] = "end_turn"
                out.append((name, json.dumps(d)))
                continue
            out.append((name, data))
        return sse_dump(out)


def _cache_tokens(u: dict) -> tuple[int, int]:
    """(cache reads, cache writes in 5-minute-write units: a 1-hour write costs 2x base = 1.6 x the 1.25x rate)."""
    try:
        read = int(u.get("cache_read_input_tokens") or 0)
        write = int(u.get("cache_creation_input_tokens") or 0)
        cc = u.get("cache_creation") if isinstance(u.get("cache_creation"), dict) else {}
        one_h = int(cc.get("ephemeral_1h_input_tokens") or 0)
        return read, write + round(one_h * (2.0 / CACHE_WRITE_X - 1.0))
    except (TypeError, ValueError):
        return 0, 0


def _anthropic_usage(u: dict) -> Usage:
    try:
        inp = int(u.get("input_tokens") or 0) + int(u.get("cache_creation_input_tokens") or 0) \
            + int(u.get("cache_read_input_tokens") or 0)
        return Usage(input_tokens=max(0, inp), output_tokens=max(0, int(u.get("output_tokens") or 0)),
                     source="reported")
    except (TypeError, ValueError):
        return Usage(source="estimated")


ADAPTERS: dict[str, Any] = {"anthropic_messages": AnthropicMessages()}


def register_adapter(protocol: str, adapter: Any) -> None:
    ADAPTERS[protocol] = adapter


# ------------------------------------------------------------------------------------------------ the PEP

class Passthrough:
    """Owns provider clients; called by the gateway middleware for every request it routes to a provider."""

    def __init__(self, *, policy: Callable[[], dict | None], run_decide: Callable[[Event], Awaitable[Decision | None]],
                 audit, ledger, timeout: float, clients: dict[str, httpx.AsyncClient] | None = None):
        self.policy, self.run_decide, self.audit, self.ledger = policy, run_decide, audit, ledger
        self.timeout = timeout
        self.clients: dict[str, httpx.AsyncClient] = dict(clients or {})
        self._owned: list[httpx.AsyncClient] = []

    async def aclose(self) -> None:
        for c in self._owned:
            await c.aclose()

    # ---- routing
    def route(self, request: Request) -> tuple[str, dict, str, dict] | None:
        """-> (provider name, provider entry, upstream path, interception cfg) or None (not ours)."""
        raw = self.policy() or {}
        cfg = icpt.interception_cfg(raw)
        if cfg["mode"] == "off":
            return None
        path = request.url.path
        q = ("?" + request.url.query) if request.url.query else ""
        hit = icpt.provider_for_host(cfg, request.headers.get("host"))
        if hit:
            return hit[0], hit[1], path + q, cfg
        provs = cfg.get("providers") or {}
        for pre, name in PREFIXES.items():
            if (path == pre or path.startswith(pre + "/")) and name in provs:
                return name, provs[name], (path[len(pre):] or "/") + q, cfg
        if "anthropic" in provs and any(path == p.rstrip("/") or path.startswith(p) for p in ANTHROPIC_BARE):
            return "anthropic", provs["anthropic"], path + q, cfg
        return None

    def client(self, name: str, prov: dict) -> httpx.AsyncClient:
        c = self.clients.get(name)
        if c is None:
            # AICL_UPSTREAM_<PROVIDER> overrides the policy (offline demo: the local Anthropic mock)
            base = os.environ.get(f"AICL_UPSTREAM_{name.upper()}") or prov.get("upstream") or "https://" + prov["hosts"][0]
            c = httpx.AsyncClient(base_url=base, timeout=httpx.Timeout(self.timeout, connect=10.0))
            self.clients[name] = c
            self._owned.append(c)
        return c

    # ---- entry
    async def handle(self, request: Request, name: str, prov: dict, upath: str, cfg: dict) -> Response:
        t0 = time.perf_counter()
        ctx = {"up": 0.0, "action": Action.ALLOW, "rid": "req_" + uuid.uuid4().hex[:12]}
        try:
            resp = await self._dispatch(request, name, prov, upath, cfg, ctx)
        except Exception as e:  # noqa: BLE001 - nothing unexpected may ever forward a request: fail closed
            ctx["action"] = Action.BLOCK
            resp = JSONResponse({"type": "error", "error": {"type": "api_error", "message":
                                 f"[AICL] gateway error, request not forwarded ({type(e).__name__})"}},
                                status_code=500)
        total = (time.perf_counter() - t0) * 1000
        resp.headers["x-aicl-request-id"] = ctx["rid"]
        resp.headers["x-aicl-decision"] = ctx["action"].name
        resp.headers["server-timing"] = (f"aicl;dur={max(total - ctx['up'], 0):.1f}, upstream;dur={ctx['up']:.1f}, "
                                         f"total;dur={total:.1f}")
        return resp

    def _refuse(self, ctx: dict, status: int, message: str, etype: str = "invalid_request_error") -> Response:
        ctx["action"] = Action.BLOCK
        return JSONResponse({"type": "error", "error": {"type": etype, "message": "[AICL] " + message}},
                            status_code=status)

    async def _dispatch(self, request: Request, name: str, prov: dict, upath: str, cfg: dict, ctx: dict) -> Response:
        adapter = ADAPTERS.get(prov.get("protocol"))
        if not icpt.is_canonical(upath):    # /v1//messages, /V1/messages, /v1/%6Dessages: refuse every spelling trick
            return self._refuse(ctx, 400, f"non-canonical request path {upath.split('?')[0]!r}")
        if icpt.is_inspected(prov, upath):
            if adapter is None:             # listed for inspection but no parser for it yet: fail closed
                return self._refuse(ctx, 400, f"{prov.get('protocol')} is not inspectable by this gateway yet")
            if request.method != "POST":
                return self._refuse(ctx, 405, f"{request.method} {upath.split('?')[0]} is not allowed", "not_found_error")
            return await self._inspect(request, name, prov, upath, cfg, adapter, ctx)
        return await self._proxy(request, name, prov, upath, cfg, ctx, adapter)

    def _who(self, request: Request, raw: dict) -> dict:
        ip = request.client.host if request.client else None
        ch = credential_hash(request.headers)
        ua = request.headers.get("user-agent")
        who = icpt.client_for(raw, ip, ch, ua)
        who.update(ip=ip, credential_hash=ch, user_agent=(ua or "")[:200] or None)
        return who

    def _base(self, who: dict, prov: dict, name: str, model: str | None, session: str | None, rid: str) -> dict:
        dest = DestKind.EXTERNAL
        if model:   # by model tag like decide() (destinations.models): an Ollama cloud tag stays unknown
            dest = resolve_destination(SimpleNamespace(raw=self.policy() or {}),
                                       Event(model=model, destination=DestKind.LOCAL))
        return dict(agent_id=who["principal"], session_id=session, request_id=rid, model=model,
                    destination=dest,
                    profile=who.get("profile"), protocol=prov.get("protocol"),
                    upstream_host=(prov.get("hosts") or [name])[0], client_ip=who["ip"],
                    credential_hash=who["credential_hash"], user_agent=who["user_agent"])

    async def _decide(self, event: Event, ctx: dict) -> Decision:
        d = await self.run_decide(event)
        if d is None:     # engine failure: fail closed
            d = Decision(action=Action.BLOCK, would_action=Action.BLOCK, decision_id=uuid.uuid4().hex[:16],
                         explain=["decide() failed", "decision BLOCK (fail closed)"])
            self.audit.from_decision(event, d, "REQUEST_BLOCKED")
        else:
            self.audit.from_decision(event, d)
        ctx["action"] = max(ctx["action"], d.action)
        return d

    def _block(self, adapter, cfg: dict, kind: str, message: str, parsed: Parsed | None, ctx: dict) -> Response:
        """Native block: kind = hard | soft | budget -> interception.block_style.<protocol>.<kind>."""
        ctx["action"] = Action.BLOCK
        style = (cfg["block_style"].get(adapter.protocol) or {}).get(kind, "http_400")
        text = "[AICL] " + message
        rid = ctx["rid"]
        if style in ("assistant_text", "refusal") and parsed is not None:
            return adapter.text_reply(parsed.model, text, parsed.stream, rid)
        status, etype = {"http_402": (402, "billing_error"), "http_429": (429, "rate_limit_error")}.get(
            style, (400, "invalid_request_error"))
        return adapter.error(status, etype, text, rid)

    async def _inspect(self, request: Request, name: str, prov: dict, upath: str, cfg: dict, adapter,
                       ctx: dict) -> Response:
        raw_policy = self.policy() or {}
        rid = ctx["rid"]
        body_bytes = await request.body()
        if len(body_bytes) > int(cfg["max_body_kb"]) * 1024:
            return self._block(adapter, cfg, "hard", f"request body {len(body_bytes) // 1024} KB is over "
                               f"interception.max_body_kb {cfg['max_body_kb']}", None, ctx)
        if request.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
            return adapter.error(400, "invalid_request_error", "[AICL] compressed request bodies are not "
                                 "accepted (they cannot be inspected)", rid)
        try:
            body = strict_json(body_bytes)
            if not isinstance(body, dict):
                raise ValueError("not an object")
            parsed = adapter.parse(body)
        except (ValueError, TypeError) as e:
            return adapter.error(400, "invalid_request_error", f"[AICL] request is not valid JSON: {e}", rid)
        who = self._who(request, raw_policy)
        base = self._base(who, prov, name, parsed.model, parsed.session, rid)

        # ---- identity and model
        if not who["matched"] and who.get("action") == "BLOCK":
            self.audit.denied(Event(stage=Stage.PROMPT, **base), "unknown client: interception.unknown_client "
                              "action BLOCK", "REQUEST_BLOCKED")
            return self._block(adapter, cfg, "hard", "this client is not registered in the AICL policy "
                               "(clients:)", parsed, ctx)
        if not icpt.model_allowed(who.get("models"), parsed.model):
            self.audit.denied(Event(stage=Stage.PROMPT, **base), f"model not allowed for {who['principal']}: "
                              f"{parsed.model}")
            return self._block(adapter, cfg, "hard", f"model {parsed.model} is not allowed for "
                               f"{who['principal']} by the AICL policy", parsed, ctx)

        # ---- request stage
        d = await self._decide(Event(stage=Stage.PROMPT, parts=[s.part for s in parsed.slots], **base), ctx)
        if d.action == Action.BLOCK:
            return self._block(adapter, cfg, "hard", f"request blocked by policy: {_why(d)} "
                               f"(decision {d.decision_id})", parsed, ctx)
        out_bytes = body_bytes
        if d.action == Action.REDACT and d.redactions:
            out_bytes = json.dumps(self._redacted(body, parsed, d), ensure_ascii=False).encode("utf-8")

        # ---- budget: reserve the worst case, settle with reported usage
        prices = prices_from_policy(raw_policy)
        price = prices.get(parsed.model)
        unpriced = str(((raw_policy.get("budgets") or {}).get("unpriced_model")) or "BLOCK").upper()
        if price is None and unpriced == "BLOCK":
            why = f"model {parsed.model} has no price in destinations.models, budgets cannot be enforced"
            self.audit.denied(Event(stage=Stage.PROMPT, **base), why, "BUDGET_EXCEEDED")
            return self._block(adapter, cfg, "budget", why, parsed, ctx)
        est_in = max(1, len(out_bytes) // CHARS_PER_TOKEN)
        est_usd = ((est_in * price["in"] + parsed.est_out * price["out"]) / 1e6) if price else 0.0
        res, retry, why = self.ledger.reserve(who["principal"], est_in + parsed.est_out, est_usd)
        if res is None:
            self.audit.denied(Event(stage=Stage.PROMPT, **base), f"budget exceeded for {who['principal']}: {why}",
                              "BUDGET_EXCEEDED")
            return self._block(adapter, cfg, "budget", f"budget exceeded for {who['principal']}: {why}", parsed, ctx)
        try:
            return await self._forward_inspected(request, name, prov, upath, cfg, adapter, parsed, base, out_bytes,
                                                 res, price, ctx)
        finally:
            self.ledger.release(res)

    async def _forward_inspected(self, request, name, prov, upath, cfg, adapter, parsed: Parsed, base, out_bytes,
                                 res, price, ctx) -> Response:
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP}
        headers["accept-encoding"] = "identity"
        t_up = time.perf_counter()
        try:
            up = await self.client(name, prov).post(upath, content=out_bytes, headers=headers)
        except httpx.HTTPError as e:
            return adapter.error(502, "api_error", f"[AICL] upstream {name} unreachable: {type(e).__name__}",
                                 ctx["rid"])
        ctx["up"] = (time.perf_counter() - t_up) * 1000
        rh = {k: v for k, v in up.headers.items() if k.lower() not in RESP_DROP}
        ctype = up.headers.get("content-type", "")
        if up.status_code != 200:      # provider errors go back untouched (the client knows them natively)
            return Response(up.content, status_code=up.status_code, headers=rh)
        sse = "text/event-stream" in ctype
        try:
            if sse:
                events = sse_parse(up.content)
                answer, state = adapter.read_sse(events)
            else:
                resp_json = up.json()
                answer = adapter.read_json(resp_json)
        except ValueError:
            return Response(up.content, status_code=up.status_code, headers=rh)

        usage = answer.usage or Usage(source="estimated")
        usd = usage_usd(answer, usage, price)
        usage = usage.model_copy(update={"usd": round(usd, 6)})
        self.ledger.settle(res, usage.input_tokens + usage.output_tokens, usd)

        new_text: dict[int, str] = {}
        drop: set[int] = set()
        note = None
        # ---- response text
        if answer.texts:
            d = await self._decide(Event(stage=Stage.RESPONSE, usage=usage,
                                         parts=[Part(role="assistant", text=t) for _, t in answer.texts], **base), ctx)
            if d.action == Action.BLOCK:
                return self._block(adapter, cfg, "soft", f"the model's answer was withheld by policy: {_why(d)} "
                                   f"(decision {d.decision_id})", parsed, ctx)
            if d.action == Action.REDACT and d.redactions:
                by_part: dict[int, list] = {}
                for r in d.redactions:
                    by_part.setdefault(r.part, []).append(r)
                for pi, reds in by_part.items():
                    if 0 <= pi < len(answer.texts):
                        bi, t = answer.texts[pi]
                        new_text[bi] = apply_spans(t, reds)
        # ---- tool calls the agent is about to execute
        if answer.tools:
            calls = [t for _, t in answer.tools]
            td = await self._decide(Event(stage=Stage.TOOL_ARGS, tool_calls=calls, **base), ctx)
            if td.action == Action.BLOCK:
                drop = {i for i, _ in answer.tools}
                note = (f"[AICL] tool call blocked ({', '.join(c.name for c in calls)}): {_why(td)} "
                        f"(decision {td.decision_id}). The command was not executed.")
        if not new_text and not drop:
            return Response(up.content, status_code=200, headers=rh)       # byte-identical
        if sse:
            return Response(adapter.rebuild_sse(state, new_text, drop, note), status_code=200, headers=rh)
        return JSONResponse(adapter.rebuild_json(resp_json, new_text, drop, note), headers=rh)

    async def _proxy(self, request: Request, name: str, prov: dict, upath: str, cfg: dict, ctx: dict,
                     adapter=None) -> Response:
        """Not inspected. Bodyless methods stream through. A request WITH a body is either a prompt-shaped JSON
        (count_tokens and friends: request-stage decide + redaction, answer streamed) or a path listed in
        providers.<p>.raw_paths (token refresh, telemetry: forwarded as is, audited); anything else is refused.
        interception.proxy_other_paths: false closes everything not inspected."""
        raw_policy = self.policy() or {}
        who = self._who(request, raw_policy)
        base = self._base(who, prov, name, None, None, ctx["rid"])
        path_only = upath.split("?", 1)[0]
        if not cfg["proxy_other_paths"]:
            self.audit.denied(Event(stage=Stage.PROMPT, **base), f"path not allowed: {request.method} {upath}",
                              "REQUEST_BLOCKED")
            return self._refuse(ctx, 404, f"{path_only} is not allowed by the AICL policy", "not_found_error")
        body = await request.body()
        if len(body) > int(cfg["max_body_kb"]) * 1024:
            return self._refuse(ctx, 413, f"request body over interception.max_body_kb {cfg['max_body_kb']}",
                                "request_too_large")
        note = "passthrough"
        if body and request.method not in ("GET", "HEAD", "OPTIONS"):
            if icpt.path_matches(prov.get("raw_paths") or [], path_only):
                note = "passthrough raw_paths"
            else:
                obj = None
                if adapter is not None and request.headers.get("content-encoding", "identity").lower() in ("", "identity"):
                    try:
                        obj = strict_json(body)
                    except ValueError:
                        obj = None
                if not (isinstance(obj, dict) and isinstance(obj.get("messages"), list)):
                    self.audit.denied(Event(stage=Stage.PROMPT, **base), f"uninspectable body: {request.method} "
                                      f"{path_only}", "REQUEST_BLOCKED")
                    return self._refuse(ctx, 400, f"{request.method} {path_only} carries a body AICL cannot inspect "
                                        f"(add it to providers.{name}.inspect or raw_paths)")
                parsed = adapter.parse(obj)
                base = self._base(who, prov, name, parsed.model, parsed.session, ctx["rid"])
                d = await self._decide(Event(stage=Stage.PROMPT, parts=[s.part for s in parsed.slots], **base), ctx)
                if d.action == Action.BLOCK:
                    return self._refuse(ctx, 400, f"request blocked by policy: {_why(d)} (decision {d.decision_id})")
                if d.action == Action.REDACT and d.redactions:
                    body = json.dumps(self._redacted(obj, parsed, d), ensure_ascii=False).encode("utf-8")
                note = "passthrough request-inspected"
        headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP}
        headers["accept-encoding"] = "identity"
        t_up = time.perf_counter()
        try:
            req = self.client(name, prov).build_request(request.method, upath, content=body or None, headers=headers)
            up = await self.client(name, prov).send(req, stream=True)
        except httpx.HTTPError as e:
            return self._refuse(ctx, 502, f"upstream {name} unreachable: {type(e).__name__}", "api_error")
        ctx["up"] = (time.perf_counter() - t_up) * 1000
        d = Decision(action=ctx["action"], decision_id=uuid.uuid4().hex[:16],
                     explain=[f"{note} {request.method} {path_only} -> {up.status_code}"])
        self.audit.from_decision(Event(stage=Stage.PROMPT, **base), d, "PASSTHROUGH")
        # raw bytes are relayed, so content-encoding stays (only hop-by-hop and length headers are dropped)
        rh = {k: v for k, v in up.headers.items() if k.lower() not in RESP_DROP - {"content-encoding"}}

        async def body_iter():
            try:
                async for chunk in up.aiter_raw():
                    yield chunk
            finally:
                await up.aclose()
        return StreamingResponse(body_iter(), status_code=up.status_code, headers=rh)

    @staticmethod
    def _redacted(obj: dict, parsed: "Parsed", d: Decision) -> dict:
        fwd = copy.deepcopy(obj)
        by_part: dict[int, list] = {}
        for r in d.redactions:
            by_part.setdefault(r.part, []).append(r)
        for idx, reds in by_part.items():
            if 0 <= idx < len(parsed.slots):
                s = parsed.slots[idx]
                _set_path(fwd, s.path, apply_spans(s.part.text, reds))
        return fwd

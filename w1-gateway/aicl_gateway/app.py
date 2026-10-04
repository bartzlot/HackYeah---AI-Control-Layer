"""PEP A: OpenAI-compatible LLM gateway. decide() is injected; upstreams are httpx clients.

The upstream is always called non-streaming; when the client asked for stream=true the checked
response is re-emitted as SSE (chunks + usage + [DONE]). This keeps response-stage and tool_args
decisions enforceable (nothing leaves before it is checked).
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from aicl_contracts import Action, Decision, DestKind, Event, Finding, Part, Stage, ToolCall, Usage

from .audit import Audit
from .budget import (DEFAULT_PRICES, BudgetLedger, LoopGuard, estimate_split, last_user_fingerprint, output_cap,
                     tool_fingerprint)
from .bus import EventBus
from .config import merge_config, route
from .console_api import ConsoleStore, make_console_router
from .explain import add_latency, stage_timing
from . import openai_adapters  # noqa: F401  (registers the OpenAI Responses / Chat adapters)
from .passthrough import Passthrough


def stub_decide(event: Event) -> Decision:
    return Decision(action=Action.ALLOW, decision_id=uuid.uuid4().hex[:16], explain=["stub decide: allow"])


def _err(status: int, code: str, message: str, decision_id: str | None = None) -> JSONResponse:
    err = {"message": message, "type": "invalid_request_error", "code": code}
    if decision_id:
        err["decision_id"] = decision_id
    return JSONResponse({"error": err}, status_code=status)


def _text_slots(messages: list[dict]) -> list[tuple[int, int | None, str, str]]:
    """(message index, content index or None, role, text) for every text segment."""
    slots = []
    for mi, m in enumerate(messages):
        c, role = m.get("content"), str(m.get("role", "user"))
        if isinstance(c, str):
            slots.append((mi, None, role, c))
        elif isinstance(c, list):
            for ci, p in enumerate(c):
                if isinstance(p, dict) and isinstance(p.get("text"), str):
                    slots.append((mi, ci, role, p["text"]))
    return slots


def bud_finding(rule_id: str, reason: str, **detail) -> Finding:
    return Finding(control_id="BUD-01", rule_id=rule_id, category="resource", action=Action.BLOCK,
                   reason_code=rule_id, detail={"reason": reason, **detail})


def apply_redactions(texts: list[str], redactions) -> list[str]:
    out = list(texts)
    by_part: dict[int, list] = {}
    for r in redactions:
        by_part.setdefault(r.part, []).append(r)
    for idx, rs in by_part.items():
        if not 0 <= idx < len(out):
            continue
        t, floor = out[idx], len(out[idx]) + 1
        for r in sorted(rs, key=lambda r: (r.start, r.end), reverse=True):
            if r.end > floor:  # overlaps a span already replaced
                continue
            t = t[:r.start] + r.replacement + t[r.end:]
            floor = r.start
        out[idx] = t
    return out


def _sse_chunks(resp: dict) -> list[str]:
    ch = resp["choices"][0]
    msg = ch["message"]
    base = {"id": resp.get("id"), "object": "chat.completion.chunk", "created": resp.get("created"),
            "model": resp.get("model")}

    def chunk(delta, fin=None, **extra):
        return "data: " + json.dumps({**base, "choices": [{"index": 0, "delta": delta, "finish_reason": fin}],
                                      **extra}) + "\n\n"

    out = [chunk({"role": "assistant"})]
    text = msg.get("content") or ""
    for i in range(0, len(text), 8):
        out.append(chunk({"content": text[i:i + 8]}))
    if msg.get("tool_calls"):
        out.append(chunk({"tool_calls": [{"index": i, **t} for i, t in enumerate(msg["tool_calls"])]}))
    extra = {"usage": resp["usage"]} if resp.get("usage") else {}
    out.append(chunk({}, ch.get("finish_reason"), **extra))
    out.append("data: [DONE]\n\n")
    return out


def create_app(decide: Callable[[Event], Any] | None = None, config: dict | None = None,
               upstreams: dict[str, httpx.AsyncClient] | None = None) -> FastAPI:
    """decide: Event -> Decision (sync or async). upstreams: {"local": client, "external": client}."""
    cfg = merge_config(config)
    decide_fn = decide or stub_decide
    bus = EventBus()
    audit = Audit(cfg["audit_path"], bus)
    owned: list[httpx.AsyncClient] = []
    clients: dict[str, httpx.AsyncClient] = dict(upstreams or {})
    for kind, url in cfg["upstream_urls"].items():
        if kind not in clients:
            # a dead upstream fails fast on connect; a slow local model still gets the long read timeout
            c = httpx.AsyncClient(base_url=url, timeout=httpx.Timeout(cfg["upstream_timeout"], connect=5.0))
            clients[kind] = c
            owned.append(c)

    bcfg = cfg["budget"]
    ledger = BudgetLedger(cfg["budget_db"], cfg["budgets"], warn_at=float(bcfg.get("warn_at", 0.8)))
    loops = LoopGuard(cfg["loop_limits"])
    prices = {**DEFAULT_PRICES, **(cfg["prices"] or {})}
    ccfg = cfg["console"]
    # sync decide() runs here, not on the event loop or asyncio's small default pool: a request waiting on
    # the local judge (one Ollama call at a time) must not starve other requests' decisions
    decide_pool = ThreadPoolExecutor(max_workers=int(cfg.get("decide_workers") or 64), thread_name_prefix="decide")
    store = ConsoleStore(budget_usd=ccfg.get("budget_usd"), policy=ccfg.get("policy"), budgets=ledger.snapshot)
    if ccfg.get("fixtures"):
        store.load_file()
    elif cfg.get("audit_path"):
        store.load_tail(cfg["audit_path"])      # the dashboard keeps its history across a restart
    bus.listeners.append(store.append)

    app = FastAPI(title="aicl-gateway")
    app.state.bus, app.state.audit, app.state.config, app.state.upstreams = bus, audit, cfg, clients
    app.state.console, app.state.ledger, app.state.loops = store, ledger, loops
    def playground_view() -> dict:
        models = dict(cfg["models"])        # read per request: follows live policy reloads
        return {"api_key": ccfg.get("demo_key"),
                "models": {k: [m for m, e in models.items() if e.get("kind") == k] for k in ("local", "external")}}

    app.include_router(make_console_router(store, playground_view, remote=bool(ccfg.get("remote")),
                                           info={"dns": lambda: getattr(getattr(app.state, "dns", None), "stats", {}),
                                                 "policy": lambda: (ccfg.get("info") or dict)(),
                                                 "interception": lambda: (ccfg.get("interception") or list)(),
                                                 "status": ccfg.get("status"),
                                                 "judge": ccfg.get("judge"),
                                                 **(ccfg.get("writers") or {})},
                                           deny_cidrs=ccfg.get("deny_cidrs"), admin_token=ccfg.get("admin_token")))

    def live_policy() -> dict | None:
        p = ccfg.get("policy")
        return p() if callable(p) else p

    # v4 passthrough PEP (research/14): requests for an intercepted provider host (or /anthropic, /openai,
    # /v1/messages on our own host) go to the provider through decide(); everything else is the managed gateway.
    # Test seam: upstreams entries other than local / external are provider clients (e.g. "anthropic").
    passthrough = Passthrough(policy=live_policy, run_decide=lambda e: run_decide(e), audit=audit, ledger=ledger,
                              timeout=cfg["upstream_timeout"],
                              clients={k: v for k, v in (upstreams or {}).items() if k not in ("local", "external")})
    app.state.passthrough = passthrough

    @app.middleware("http")
    async def pep_passthrough(request: Request, call_next):
        hit = passthrough.route(request)
        if hit is None:
            return await call_next(request)
        if cfg.get("before_auth"):          # apply a reloaded policy (budgets) before the request is metered
            cfg["before_auth"]()
        return await passthrough.handle(request, *hit)

    @app.on_event("shutdown")
    async def _close():
        await passthrough.aclose()
        for c in owned:
            await c.aclose()
        bus.close()
        ledger.close()
        decide_pool.shutdown(wait=False, cancel_futures=True)

    async def run_decide(event: Event) -> Decision | None:
        try:
            if inspect.iscoroutinefunction(decide_fn):
                d = await decide_fn(event)
            else:   # sync decide (w2 engine + local judge may wait on Ollama): keep the event loop free
                d = await asyncio.get_running_loop().run_in_executor(decide_pool, decide_fn, event)
            if inspect.isawaitable(d):
                d = await d
            if not isinstance(d, Decision):
                d = Decision.model_validate(d)
        except Exception:  # fail closed
            return None
        upd = {}
        if not d.decision_id:
            upd["decision_id"] = uuid.uuid4().hex[:16]
        if not d.degraded and any(f.detail.get("degraded") for f in d.findings):
            upd["degraded"] = True    # e.g. INJ-04 judge timed out: its fail action applied
        return d.model_copy(update=upd) if upd else d

    def authenticate(request: Request) -> tuple[str, dict] | None:
        if cfg.get("before_auth"):          # entrypoint hook: apply a reloaded policy before identity
            cfg["before_auth"]()
        auth = request.headers.get("authorization", "")
        key = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        agent = cfg["agents"].get(key) if key else None
        if agent is None and key and cfg.get("agent_key_hashes"):   # policy agents.<id>.key_sha256
            agent = cfg["agent_key_hashes"].get(hashlib.sha256(key.encode("utf-8")).hexdigest())
        return (agent.get("agent_id", "anonymous"), agent) if agent is not None else None

    def allowed(agent: dict, model: str) -> bool:
        models = agent.get("models")
        return models is None or model in models

    async def guard(event: Event, ctx: dict) -> tuple[Decision | None, JSONResponse | None]:
        """decide + audit; returns (decision, error response when blocked or decide failed)."""
        d = await run_decide(event)
        if d is None:
            ctx["action"] = Action.BLOCK
            audit.denied(event, "decide() failed: fail closed", "REQUEST_BLOCKED")
            return None, _err(503, "policy_unavailable", "policy engine unavailable, request denied (fail closed)")
        audit.from_decision(event, d)
        add_latency(ctx.setdefault("stages", {}), d.latency_us)    # Server-Timing per decide() stage (T-119)
        ctx["action"] = max(ctx["action"], d.action)
        if d.action == Action.BLOCK:
            why = "; ".join(d.explain[-2:]) or "blocked by policy"
            return d, _err(403, "policy_block", f"Blocked by AI Control Layer: {why}", d.decision_id)
        return d, None

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    @app.get("/v1/models")
    async def models(request: Request):
        who = authenticate(request)
        if who is None:
            return _err(401, "invalid_api_key", "missing or invalid API key")
        data = [{"id": m, "object": "model", "owned_by": "aicl-" + e["kind"]}
                for m, e in dict(cfg["models"]).items() if allowed(who[1], m)]
        return {"object": "list", "data": data}

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        t0 = time.perf_counter()
        ctx = {"action": Action.ALLOW, "up": 0.0}
        resp = await _chat(request, ctx)
        total = (time.perf_counter() - t0) * 1000
        # decision header only when a policy verdict explains the status: not on 400 / 401 (no request yet),
        # not on an allowed request that then failed upstream (502 / passthrough error)
        if ctx.get("request_id"):
            resp.headers["X-AICL-Request-Id"] = ctx["request_id"]
            if resp.status_code < 400 or ctx["action"] == Action.BLOCK:
                resp.headers["X-AICL-Decision"] = ctx["action"].name
        if ctx.get("budget_warning"):
            resp.headers["X-AICL-Budget-Warning"] = ctx["budget_warning"]
        stages = stage_timing(ctx.get("stages"))
        resp.headers["Server-Timing"] = (f"aicl;dur={max(total - ctx['up'], 0):.1f}, " + (stages + ", " if stages else "")
                                         + f"upstream;dur={ctx['up']:.1f}, total;dur={total:.1f}")
        resp.headers["Access-Control-Expose-Headers"] = "X-AICL-Decision, X-AICL-Request-Id, X-AICL-Budget-Warning, Server-Timing, Retry-After"
        return resp

    async def _chat(request: Request, ctx: dict):
        # X-AICL-Destination is informational only (playground); routing is by model, identity by API key.
        who = authenticate(request)
        if who is None:
            return _err(401, "invalid_api_key", "missing or invalid API key")
        agent_id, agent = who
        try:
            body = await request.json()
        except ValueError:
            return _err(400, "invalid_json", "body is not valid JSON")
        model = body.get("model") if isinstance(body, dict) else None
        messages = body.get("messages") if isinstance(body, dict) else None
        if (not isinstance(model, str) or not isinstance(messages, list) or not messages
                or not all(isinstance(m, dict) for m in messages)):
            return _err(400, "invalid_request", "model (string) and messages (non-empty list) are required")
        if body.get("n") not in (None, 1):   # one choice only: budgets reserve and checks inspect one output
            return _err(400, "unsupported_n", "n > 1 is not supported by the AI Control Layer")
        stream = bool(body.get("stream"))
        kind, entry = route(cfg, model)
        base = dict(agent_id=agent_id, session_id=request.headers.get(cfg["session_header"]),
                    request_id="req_" + uuid.uuid4().hex[:12], model=model, destination=kind,
                    profile=agent.get("profile"))
        ctx["request_id"] = base["request_id"]

        if kind == DestKind.UNKNOWN or not allowed(agent, model):
            why = "unknown model" if kind == DestKind.UNKNOWN else "model not in agent allowlist"
            ctx["action"] = Action.BLOCK
            audit.denied(Event(stage=Stage.PROMPT, **base), f"{why}: {model}")
            return _err(403, "model_denied", f"model {model!r} is not permitted for this agent ({why})")

        # ---- loop guard (before policy: repeated blocked attempts count too) ----
        sid = base["session_id"]
        # prompts count only inside a session: a person repeating a prompt without one is not an agent loop
        if loops.observe(agent_id, sid, last_user_fingerprint(messages) if sid else None):
            ctx["action"] = Action.BLOCK
            why = f"agent loop: {loops.threshold} identical calls" + (f", session {sid} terminated" if sid else "")
            audit.denied(Event(stage=Stage.PROMPT, **base), why, "AGENT_LOOP_TERMINATED",
                         [bud_finding("loop.repeat_identical", why, threshold=loops.threshold)])
            return _err(403, "agent_loop_terminated", f"Blocked by AI Control Layer: {why}")

        # ---- request stage ----
        slots = _text_slots(messages)
        parts = [Part(role=r, text=t, trusted=r != "tool") for _, _, r, t in slots]
        d, error = await guard(Event(stage=Stage.PROMPT, parts=parts, **base), ctx)
        if error:
            return error
        fwd = json.loads(json.dumps(body))
        if d.action == Action.REDACT and d.redactions:
            new = apply_redactions([p.text for p in parts], d.redactions)
            for (mi, ci, _, old), text in zip(slots, new):
                if text != old:
                    if ci is None:
                        fwd["messages"][mi]["content"] = text
                    else:
                        fwd["messages"][mi]["content"][ci]["text"] = text

        # ---- budget: reserve the worst case now, settle with real usage ----
        cap = output_cap(fwd)            # always a positive cap: Ollama treats missing / -1 as unlimited
        if "max_completion_tokens" in fwd:
            fwd["max_completion_tokens"] = cap
        if "max_completion_tokens" not in fwd or "max_tokens" in fwd or kind == DestKind.LOCAL:
            fwd["max_tokens"] = cap      # (o-series upstreams reject max_tokens next to max_completion_tokens)
        price = prices.get(model) if kind == DestKind.EXTERNAL else None
        if kind == DestKind.EXTERNAL and price is None and bcfg.get("unpriced_model", "BLOCK") == "BLOCK":
            ctx["action"] = Action.BLOCK
            why = f"unpriced external model {model}: budgets cannot be enforced"
            audit.denied(Event(stage=Stage.PROMPT, **base), why, "BUDGET_EXCEEDED", [bud_finding("budget.unpriced", why)])
            return _err(403, "unpriced_model", f"Blocked by AI Control Layer: {why}")
        est_in, est_out, est_usd = estimate_split(fwd, price)
        res, retry, why = ledger.reserve(agent_id, est_in + est_out, est_usd)
        if res is None:
            ctx["action"] = Action.BLOCK
            rule = "budget.request_too_large" if retry == 0 else "budget.agent"
            audit.denied(Event(stage=Stage.PROMPT, **base), f"budget exceeded for agent {agent_id}: {why}",
                         "BUDGET_EXCEEDED", [bud_finding(rule, why, retry_after_s=retry)])
            if retry == 0:
                return _err(413, "budget_request_too_large", f"Blocked by AI Control Layer: {why}")
            r = _err(429, "budget_exceeded", f"Blocked by AI Control Layer: {why}; retry after {retry} s")
            r.headers["Retry-After"] = str(retry)
            return r
        try:
            return await _upstream_and_respond(fwd, res, est_in, est_out, est_usd, price, kind, entry, base, ctx,
                                               agent_id, sid, stream)
        finally:
            ledger.release(res)        # no-op after settle; frees the hold on any error or cancellation

    async def _upstream_and_respond(fwd, res, est_in, est_out, est_usd, price, kind, entry, base, ctx,
                                    agent_id, sid, stream):
        model = base["model"]

        # ---- upstream: own credential only, agent key never forwarded ----
        fwd["model"] = entry.get("upstream_model", model)
        fwd["stream"] = False
        if kind == DestKind.LOCAL:
            # qwen3.5 thinks by default on Ollama's OpenAI endpoint and spends the whole output budget on reasoning
            # (empty content); the project runs it with thinking off. `think: false` is ignored there, this is not.
            fwd.setdefault("reasoning_effort", "none")
        fwd.pop("stream_options", None)
        headers = {"content-type": "application/json"}
        key = cfg["upstream_keys"].get(kind.value)
        if key:
            headers["authorization"] = f"Bearer {key}"
        t_up = time.perf_counter()
        try:
            up = await clients[kind.value].post("/v1/chat/completions", json=fwd, headers=headers)
        except (httpx.HTTPError, KeyError) as e:
            return _err(502, "upstream_error", f"upstream {kind.value} unreachable: {type(e).__name__}")
        ctx["up"] = (time.perf_counter() - t_up) * 1000
        try:
            resp = up.json()
        except ValueError:
            return _err(502, "upstream_error", "upstream returned invalid JSON")
        if up.status_code != 200 or not isinstance(resp, dict) or not resp.get("choices"):
            return JSONResponse(resp if isinstance(resp, dict) else {"error": {"message": "bad upstream reply"}},
                                status_code=up.status_code if up.status_code != 200 else 502)
        resp["model"] = model
        u = resp.get("usage") if isinstance(resp.get("usage"), dict) else {}
        try:
            usage = Usage(input_tokens=max(0, int(u.get("prompt_tokens") or 0)),
                          output_tokens=max(0, int(u.get("completion_tokens") or 0)),
                          usd=max(0.0, float(u.get("cost_usd") or 0.0)), source="reported")
        except (TypeError, ValueError):
            u = {}
        if not u:   # no usable usage reported: settle the pessimistic reservation, flagged as estimated
            usage = Usage(input_tokens=est_in, output_tokens=est_out, usd=est_usd, source="estimated")
        elif kind == DestKind.EXTERNAL and not u.get("cost_usd") and price:
            usage = usage.model_copy(update={"usd": (usage.input_tokens * price["in"]
                                                     + usage.output_tokens * price["out"]) / 1e6})
        if kind != DestKind.EXTERNAL:
            usage = usage.model_copy(update={"usd": 0.0})   # local compute is not API cost
        ledger.settle(res, usage.input_tokens + usage.output_tokens, usage.usd)
        if ledger.utilization(agent_id) >= ledger.warn_at:
            ctx["budget_warning"] = f"{100 * ledger.utilization(agent_id):.0f}% of budget used"
        msg = resp["choices"][0].setdefault("message", {"role": "assistant", "content": ""})

        # ---- response stage ----
        content = msg.get("content") if isinstance(msg.get("content"), str) else ""
        d, error = await guard(Event(stage=Stage.RESPONSE, parts=[Part(role="assistant", text=content)],
                                     usage=usage, **base), ctx)
        if error:
            return error
        if d.action == Action.REDACT and d.redactions:
            msg["content"] = apply_redactions([content], d.redactions)[0]

        # ---- tool calls ----
        calls = msg.get("tool_calls") or []
        if calls:
            tcs = []
            for c in calls:
                fn = c.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = {"_raw": fn.get("arguments")}
                tcs.append(ToolCall(name=str(fn.get("name", "")),
                                    arguments=args if isinstance(args, dict) else {"_value": args}))
            looped = [t for t in tcs if loops.observe(agent_id, sid, tool_fingerprint(t.name, t.arguments))]
            if looped:
                ctx["action"] = Action.BLOCK
                why = (f"agent loop: tool {looped[0].name} called {loops.threshold} times with identical arguments"
                       + (f", session {sid} terminated" if sid else ""))
                audit.denied(Event(stage=Stage.TOOL_ARGS, tool_calls=tcs, **base), why, "AGENT_LOOP_TERMINATED",
                             [bud_finding("loop.repeat_identical", why, threshold=loops.threshold)])
                return _err(403, "agent_loop_terminated", f"Blocked by AI Control Layer: {why}")
            td, error = await guard(Event(stage=Stage.TOOL_ARGS, tool_calls=tcs, **base), ctx)
            if td is None:
                return error
            if td.action == Action.BLOCK:
                why = "; ".join(td.explain[-2:]) or "blocked by policy"
                msg.pop("tool_calls", None)
                msg["content"] = (f"[AI Control Layer] The tool call ({', '.join(t.name for t in tcs)}) "
                                  f"was blocked: {why} (decision {td.decision_id}).")
                resp["choices"][0]["finish_reason"] = "stop"

        if stream:
            return StreamingResponse(iter(_sse_chunks(resp)), media_type="text/event-stream")
        return JSONResponse(resp)

    return app

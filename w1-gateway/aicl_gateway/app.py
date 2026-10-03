"""PEP A: OpenAI-compatible LLM gateway. decide() is injected; upstreams are httpx clients.

The upstream is always called non-streaming; when the client asked for stream=true the checked
response is re-emitted as SSE (chunks + usage + [DONE]). This keeps response-stage and tool_args
decisions enforceable (nothing leaves before it is checked).
"""
from __future__ import annotations

import inspect
import json
import time
import uuid
from typing import Any, Callable

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from aicl_contracts import Action, Decision, DestKind, Event, Part, Stage, ToolCall, Usage

from .audit import Audit
from .bus import EventBus
from .config import merge_config, route
from .console_api import ConsoleStore, make_console_router


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
            c = httpx.AsyncClient(base_url=url, timeout=cfg["upstream_timeout"])
            clients[kind] = c
            owned.append(c)

    ccfg = cfg["console"]
    store = ConsoleStore(budget_usd=ccfg.get("budget_usd"), policy=ccfg.get("policy"))
    if ccfg.get("fixtures"):
        store.load_file()
    bus.listeners.append(store.append)

    app = FastAPI(title="aicl-gateway")
    app.state.bus, app.state.audit, app.state.config, app.state.upstreams = bus, audit, cfg, clients
    app.state.console = store
    models_view = {"local": [m for m, e in cfg["models"].items() if e["kind"] == "local"],
                   "external": [m for m, e in cfg["models"].items() if e["kind"] == "external"]}
    app.include_router(make_console_router(store, {"api_key": ccfg.get("demo_key"), "models": models_view},
                                           remote=bool(ccfg.get("remote"))))

    @app.on_event("shutdown")
    async def _close():
        for c in owned:
            await c.aclose()
        bus.close()

    async def run_decide(event: Event) -> Decision | None:
        try:
            d = decide_fn(event)
            if inspect.isawaitable(d):
                d = await d
            if not isinstance(d, Decision):
                d = Decision.model_validate(d)
        except Exception:  # fail closed
            return None
        if not d.decision_id:
            d = d.model_copy(update={"decision_id": uuid.uuid4().hex[:16]})
        return d

    def authenticate(request: Request) -> tuple[str, dict] | None:
        auth = request.headers.get("authorization", "")
        key = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        agent = cfg["agents"].get(key) if key else None
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
                for m, e in cfg["models"].items() if allowed(who[1], m)]
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
        resp.headers["Server-Timing"] = (f"aicl;dur={max(total - ctx['up'], 0):.1f}, upstream;dur={ctx['up']:.1f}, "
                                         f"total;dur={total:.1f}")
        resp.headers["Access-Control-Expose-Headers"] = "X-AICL-Decision, X-AICL-Request-Id, Server-Timing"
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

        # ---- upstream: own credential only, agent key never forwarded ----
        fwd["model"] = entry.get("upstream_model", model)
        fwd["stream"] = False
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
        u = resp.get("usage") or {}
        usage = Usage(input_tokens=int(u.get("prompt_tokens") or 0), output_tokens=int(u.get("completion_tokens") or 0),
                      usd=float(u.get("cost_usd") or 0.0), source="reported" if u else "estimated")
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

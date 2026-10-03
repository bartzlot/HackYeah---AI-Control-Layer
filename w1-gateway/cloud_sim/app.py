"""OpenAI-compatible priced mock. Replies are scripted (YAML) or a deterministic echo."""
from __future__ import annotations

import json
import math
import os
import time
import uuid
from pathlib import Path

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

# USD per million tokens (simulated prices, shape of the LiteLLM price map).
PRICES: dict[str, dict[str, float]] = {
    "gpt-4o-mini": {"in": 0.15, "out": 0.60},
    "gpt-4o": {"in": 2.50, "out": 10.00},
}


def estimate_tokens(text: str) -> int:
    """Deterministic token estimate: 1 token per 4 chars, at least 1 for non-empty text."""
    return math.ceil(len(text) / 4) if text else 0


def _content_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p["text"] for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
    return ""


class Script:
    """Ordered steps: {match: {contains: str}?, reply: str?, tool_calls: [{name, arguments}]?}.

    A step without `match` fires on any request; each step fires once, in order. With no
    step left (or no match) the mock echoes the last user message.
    """

    def __init__(self, steps: list[dict] | None = None):
        if not isinstance(steps or [], list):
            raise ValueError("script steps must be a list")
        for step in steps or []:
            if not isinstance(step, dict):
                raise ValueError(f"script step must be a mapping: {step!r}")
            for call in step.get("tool_calls") or []:
                if not isinstance(call, dict) or not isinstance(call.get("name"), str):
                    raise ValueError(f"tool call needs a string name: {call!r}")
        self.steps = list(steps or [])
        self.used: set[int] = set()

    def next(self, last_user: str) -> dict | None:
        for i, step in enumerate(self.steps):
            if i in self.used:
                continue
            needle = (step.get("match") or {}).get("contains")
            if needle is None or needle in last_user:
                self.used.add(i)
                return step
        return None


def load_script(path: str | os.PathLike | None) -> Script:
    if not path:
        return Script()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return Script(data.get("steps", []))


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message, "type": "invalid_request_error"}}, status)


def create_app(script: Script | None = None, prices: dict | None = None) -> FastAPI:
    app = FastAPI(title="cloud-sim")
    prices = PRICES if prices is None else prices
    script = script if script is not None else load_script(os.environ.get("AICL_CLOUDSIM_SCRIPT"))
    app.state.script = script
    app.state.calls = []

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/v1/models")
    def models():
        return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "cloud-sim"} for m in prices]}

    @app.post("/v1/chat/completions")
    async def chat(request: Request):
        try:
            body = await request.json()
        except ValueError:
            return _error(400, "invalid_json", "body is not valid JSON")
        if not isinstance(body, dict):
            return _error(400, "invalid_request", "body must be a JSON object")
        model = body.get("model")
        messages = body.get("messages")
        if not isinstance(model, str) or model not in prices:
            return _error(404, "model_not_found", f"model {model!r} is not priced")
        if not isinstance(messages, list) or not messages or not all(isinstance(m, dict) for m in messages):
            return _error(400, "invalid_request", "messages must be a non-empty list")
        app.state.calls.append(body)

        prompt_text = " ".join(_content_text(m.get("content")) for m in messages)
        last_user = next((_content_text(m.get("content")) for m in reversed(messages) if m.get("role") == "user"), "")
        step = script.next(last_user)
        reply = (step or {}).get("reply") if step else f"echo: {last_user}"
        tool_calls = [
            {"id": f"call_{i}", "type": "function",
             "function": {"name": t["name"], "arguments": t["arguments"] if isinstance(t.get("arguments"), str) else json.dumps(t.get("arguments", {}))}}
            for i, t in enumerate((step or {}).get("tool_calls") or [])
        ]
        message: dict = {"role": "assistant", "content": reply if not tool_calls else (reply or None)}
        if tool_calls:
            message["tool_calls"] = tool_calls
        finish = "tool_calls" if tool_calls else "stop"

        p_tok = estimate_tokens(prompt_text)
        c_tok = estimate_tokens((reply or "") + "".join(t["function"]["arguments"] for t in tool_calls))
        price = prices[model]
        cost = (p_tok * price["in"] + c_tok * price["out"]) / 1_000_000
        usage = {"prompt_tokens": p_tok, "completion_tokens": c_tok, "total_tokens": p_tok + c_tok,
                 "cost_usd": round(cost, 10)}
        cid, created = f"chatcmpl-{uuid.uuid4().hex[:12]}", int(time.time())

        if body.get("stream"):
            def sse():
                def chunk(delta, fin=None, **extra):
                    return "data: " + json.dumps({"id": cid, "object": "chat.completion.chunk", "created": created,
                        "model": model, "choices": [{"index": 0, "delta": delta, "finish_reason": fin}], **extra}) + "\n\n"
                yield chunk({"role": "assistant"})
                text = reply or ""
                for i in range(0, len(text), 8):
                    yield chunk({"content": text[i:i + 8]})
                if tool_calls:
                    yield chunk({"tool_calls": [{"index": i, **t} for i, t in enumerate(tool_calls)]})
                yield chunk({}, finish, usage=usage)
                yield "data: [DONE]\n\n"
            return StreamingResponse(sse(), media_type="text/event-stream")

        return {"id": cid, "object": "chat.completion", "created": created, "model": model,
                "choices": [{"index": 0, "message": message, "finish_reason": finish}], "usage": usage}

    return app

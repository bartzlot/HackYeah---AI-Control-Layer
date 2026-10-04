"""OpenAI adapters for the passthrough PEP (research/14 s.3): Responses API (Codex CLI, Agents SDK) and Chat
Completions (SDKs). Same contract as passthrough.AnthropicMessages: parse a request into inspectable parts,
read the answer, rebuild it with redacted text / blocked tool calls, and answer blocks natively.

Codex CLI 0.160.0 measured against a mock (research/14 s.3): a 200 assistant message shows our text; 400
invalid_request_error and response.failed show `ERROR: [AICL] ...`; 402 shows the message; 429
insufficient_quota is replaced by "Quota exceeded" and a refusal part is not shown at all (never use them).
"""
from __future__ import annotations

import copy
import json
import time
from typing import Any

from fastapi.responses import JSONResponse, Response

from aicl_contracts import Part, ToolCall, Usage

from .passthrough import Answer, Parsed, Slot, register_adapter, sse_dump

SCAFFOLD = ("<environment_context>", "<user_instructions>", "# AGENTS.md instructions", "<permissions instructions>")
ETYPES = {"billing_error": ("insufficient_quota", "aicl_budget"), "invalid_request_error": ("invalid_request_error",
                                                                                           "aicl_policy_block")}


def _openai_error(status: int, etype: str, message: str, rid: str) -> Response:
    t, code = ETYPES.get(etype, (etype, "aicl"))
    return JSONResponse({"error": {"message": message, "type": t, "param": None, "code": code}},
                        status_code=status, headers={"x-request-id": rid})


def _args(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        v = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {"_raw": raw}
    return v if isinstance(v, dict) else {"_value": v}


def _text_of(output: Any) -> list[tuple[tuple, str]]:
    """Tool output: a string, or a list of {type: input_text|output_text, text} -> [(path suffix, text)]."""
    if isinstance(output, str):
        return [((), output)]
    out = []
    for i, b in enumerate(output if isinstance(output, list) else []):
        if isinstance(b, dict) and isinstance(b.get("text"), str):
            out.append(((i, "text"), b["text"]))
    return out


# ------------------------------------------------------------------------------------------------ Responses

class OpenAIResponses:
    protocol = "openai_responses"

    def parse(self, body: dict) -> Parsed:
        slots: list[Slot] = []
        if isinstance(body.get("instructions"), str):
            slots.append(Slot(("instructions",), Part(role="system", text=body["instructions"])))
        inp = body.get("input")
        if isinstance(inp, str):
            slots.append(Slot(("input",), Part(role="user", text=inp)))
        for i, it in enumerate(inp if isinstance(inp, list) else []):
            if not isinstance(it, dict):
                continue
            t = it.get("type", "message")
            if t == "message":
                role = str(it.get("role", "user"))
                role = "system" if role == "developer" else role
                c = it.get("content")
                if isinstance(c, str):
                    slots.append(Slot(("input", i, "content"), Part(role=role, text=c)))
                    continue
                for j, b in enumerate(c if isinstance(c, list) else []):
                    if isinstance(b, dict) and isinstance(b.get("text"), str):
                        scaffold = role == "user" and b["text"].lstrip().startswith(SCAFFOLD)
                        slots.append(Slot(("input", i, "content", j, "text"),
                                          Part(role="system" if scaffold else role, text=b["text"])))
            elif t in ("function_call_output", "custom_tool_call_output", "local_shell_call_output",
                       "mcp_call_output", "computer_call_output"):
                for suffix, text in _text_of(it.get("output")):
                    slots.append(Slot(("input", i, "output") + suffix, Part(role="tool", text=text, trusted=False)))
            # reasoning (encrypted_content), function_call history, images: never touched
        mo = body.get("max_output_tokens")
        return Parsed(model=str(body.get("model") or ""), stream=bool(body.get("stream")), slots=slots,
                      session=str(body.get("prompt_cache_key"))[:200] if body.get("prompt_cache_key") else None,
                      est_out=int(mo) if isinstance(mo, int) and mo > 0 else 4096)

    def error(self, status: int, etype: str, message: str, rid: str) -> Response:
        return _openai_error(status, etype, message, rid)

    @staticmethod
    def _message_item(text: str, iid: str = "msg_aicl") -> dict:
        return {"id": iid, "type": "message", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": text, "annotations": []}]}

    def _response(self, model: str, output: list, rid: str, usage: dict | None = None) -> dict:
        return {"id": "resp_aicl_" + rid[-12:], "object": "response", "created_at": int(time.time()), "model": model,
                "status": "completed", "output": output,
                "usage": usage or {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}

    def _stream(self, resp: dict) -> bytes:
        seq = iter(range(100000))
        start = dict(resp, status="in_progress", output=[])
        ev: list[tuple[str, dict]] = [("response.created", {"type": "response.created", "response": start}),
                                      ("response.in_progress", {"type": "response.in_progress", "response": start})]
        for oi, item in enumerate(resp.get("output") or []):
            if item.get("type") == "message":
                ev.append(("response.output_item.added", {"type": "response.output_item.added", "output_index": oi,
                                                          "item": dict(item, status="in_progress", content=[])}))
                for ci, part in enumerate(item.get("content") or []):
                    text = part.get("text", "")
                    ev.append(("response.content_part.added", {"type": "response.content_part.added",
                                                               "item_id": item.get("id"), "output_index": oi,
                                                               "content_index": ci, "part": dict(part, text="")}))
                    ev.append(("response.output_text.delta", {"type": "response.output_text.delta",
                                                              "item_id": item.get("id"), "output_index": oi,
                                                              "content_index": ci, "delta": text}))
                    ev.append(("response.output_text.done", {"type": "response.output_text.done",
                                                             "item_id": item.get("id"), "output_index": oi,
                                                             "content_index": ci, "text": text}))
                    ev.append(("response.content_part.done", {"type": "response.content_part.done",
                                                              "item_id": item.get("id"), "output_index": oi,
                                                              "content_index": ci, "part": part}))
            else:
                ev.append(("response.output_item.added", {"type": "response.output_item.added", "output_index": oi,
                                                          "item": item}))
            ev.append(("response.output_item.done", {"type": "response.output_item.done", "output_index": oi,
                                                     "item": item}))
        ev.append(("response.completed", {"type": "response.completed", "response": resp}))
        return sse_dump([(n, json.dumps({**d, "sequence_number": next(seq)})) for n, d in ev])

    def text_reply(self, model: str, text: str, stream: bool, rid: str, usage_in: int = 0) -> Response:
        resp = self._response(model, [self._message_item(text)], rid)
        if stream:
            return Response(self._stream(resp), media_type="text/event-stream", headers={"x-request-id": rid})
        return JSONResponse(resp, headers={"x-request-id": rid})

    # ---- response
    def read_json(self, resp: dict) -> Answer:
        a = Answer()
        for oi, item in enumerate(resp.get("output") or []):
            if not isinstance(item, dict):
                continue
            t = item.get("type")
            if t == "message":
                for ci, part in enumerate(item.get("content") or []):
                    if isinstance(part, dict) and part.get("type") == "output_text":
                        a.texts.append((oi * 1000 + ci, str(part.get("text") or "")))
            elif t == "function_call":
                a.tools.append((oi, ToolCall(name=str(item.get("name") or ""), arguments=_args(item.get("arguments")))))
            elif t == "custom_tool_call":
                a.tools.append((oi, ToolCall(name=str(item.get("name") or ""), arguments={"input": item.get("input")})))
            elif t == "local_shell_call":
                cmd = ((item.get("action") or {}).get("command")) or []
                a.tools.append((oi, ToolCall(name="local_shell", arguments={
                    "command": " ".join(map(str, cmd)) if isinstance(cmd, list) else str(cmd)})))
        u = resp.get("usage") or {}
        try:
            a.usage = Usage(input_tokens=int(u.get("input_tokens") or 0), output_tokens=int(u.get("output_tokens") or 0),
                            source="reported")
            a.cache_read = int(((u.get("input_tokens_details") or {}).get("cached_tokens")) or 0)
        except (TypeError, ValueError):
            a.usage = Usage(source="estimated")
        return a

    def read_sse(self, events: list[tuple[str | None, str]]) -> tuple[Answer, dict]:
        final = None
        for name, data in events:
            if name in ("response.completed", "response.incomplete") or '"response.completed"' in data[:60]:
                try:
                    final = json.loads(data).get("response")
                except ValueError:
                    final = None
        if not isinstance(final, dict):     # failed / unexpected stream: nothing to inspect, pass it through
            return Answer(), {"final": None}
        return self.read_json(final), {"final": final}

    def _rebuilt(self, resp: dict, new_text: dict[int, str], drop: set[int], note: str | None) -> dict:
        out = copy.deepcopy(resp)
        items = out.get("output") or []
        for key, text in new_text.items():
            oi, ci = divmod(key, 1000)
            items[oi]["content"][ci]["text"] = text
        for oi in sorted(drop):
            items[oi] = self._message_item(note or "[AICL] tool call blocked", f"msg_aicl_{oi}")
        return out

    def rebuild_json(self, resp: dict, new_text: dict[int, str], drop_tools: set[int], note: str | None) -> dict:
        return self._rebuilt(resp, new_text, drop_tools, note)

    def rebuild_sse(self, state: dict, new_text: dict[int, str], drop_tools: set[int], note: str | None) -> bytes:
        return self._stream(self._rebuilt(state["final"], new_text, drop_tools, note))


# ------------------------------------------------------------------------------------------------ Chat Completions

class OpenAIChat:
    protocol = "openai_chat"

    def parse(self, body: dict) -> Parsed:
        slots: list[Slot] = []
        for mi, m in enumerate(body.get("messages") or []):
            if not isinstance(m, dict):
                continue
            role = str(m.get("role", "user"))
            role = "system" if role == "developer" else role
            trusted = role != "tool"
            c = m.get("content")
            if isinstance(c, str):
                slots.append(Slot(("messages", mi, "content"), Part(role=role, text=c, trusted=trusted)))
            for ci, b in enumerate(c if isinstance(c, list) else []):
                if isinstance(b, dict) and isinstance(b.get("text"), str):
                    slots.append(Slot(("messages", mi, "content", ci, "text"), Part(role=role, text=b["text"],
                                                                                    trusted=trusted)))
        mt = body.get("max_completion_tokens") or body.get("max_tokens")
        return Parsed(model=str(body.get("model") or ""), stream=bool(body.get("stream")), slots=slots,
                      est_out=int(mt) if isinstance(mt, int) and mt > 0 else 4096)

    def error(self, status: int, etype: str, message: str, rid: str) -> Response:
        return _openai_error(status, etype, message, rid)

    def _completion(self, model: str, message: dict, finish: str, rid: str, usage: dict | None = None) -> dict:
        return {"id": "chatcmpl-aicl" + rid[-12:], "object": "chat.completion", "created": int(time.time()),
                "model": model, "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}

    def _stream(self, resp: dict) -> bytes:
        ch = resp["choices"][0]
        msg = ch["message"]
        base = {"id": resp.get("id"), "object": "chat.completion.chunk", "created": resp.get("created"),
                "model": resp.get("model")}

        def chunk(delta, fin=None, **extra):
            return (None, json.dumps({**base, "choices": [{"index": 0, "delta": delta, "finish_reason": fin}], **extra}))
        out = [chunk({"role": "assistant", "content": ""})]
        if msg.get("content"):
            out.append(chunk({"content": msg["content"]}))
        if msg.get("tool_calls"):
            out.append(chunk({"tool_calls": [{"index": i, **t} for i, t in enumerate(msg["tool_calls"])]}))
        out.append(chunk({}, ch.get("finish_reason"), **({"usage": resp["usage"]} if resp.get("usage") else {})))
        out.append((None, "[DONE]"))
        return sse_dump(out)

    def text_reply(self, model: str, text: str, stream: bool, rid: str, usage_in: int = 0) -> Response:
        resp = self._completion(model, {"role": "assistant", "content": text}, "stop", rid)
        if stream:
            return Response(self._stream(resp), media_type="text/event-stream", headers={"x-request-id": rid})
        return JSONResponse(resp, headers={"x-request-id": rid})

    def read_json(self, resp: dict) -> Answer:
        a = Answer()
        ch = (resp.get("choices") or [{}])[0]
        msg = ch.get("message") or {}
        if isinstance(msg.get("content"), str):
            a.texts.append((0, msg["content"]))
        for i, t in enumerate(msg.get("tool_calls") or []):
            fn = (t or {}).get("function") or {}
            a.tools.append((i, ToolCall(name=str(fn.get("name") or ""), arguments=_args(fn.get("arguments")))))
        u = resp.get("usage") or {}
        try:
            a.usage = Usage(input_tokens=int(u.get("prompt_tokens") or 0),
                            output_tokens=int(u.get("completion_tokens") or 0), source="reported")
            a.cache_read = int(((u.get("prompt_tokens_details") or {}).get("cached_tokens")) or 0)
        except (TypeError, ValueError):
            a.usage = Usage(source="estimated")
        return a

    def read_sse(self, events: list[tuple[str | None, str]]) -> tuple[Answer, dict]:
        """Aggregate chat.completion.chunk deltas into one completion (content, tool calls, usage)."""
        content, calls, finish, usage, head = [], {}, None, None, {}
        for _, data in events:
            if not data or data.strip() == "[DONE]":
                continue
            try:
                d = json.loads(data)
            except ValueError:
                continue
            head = head or {k: d.get(k) for k in ("id", "created", "model")}
            if d.get("usage"):
                usage = d["usage"]
            for c in d.get("choices") or []:
                delta = c.get("delta") or {}
                if isinstance(delta.get("content"), str):
                    content.append(delta["content"])
                for tc in delta.get("tool_calls") or []:
                    slot = calls.setdefault(tc.get("index", 0), {"id": None, "type": "function",
                                                                 "function": {"name": "", "arguments": ""}})
                    slot["id"] = tc.get("id") or slot["id"]
                    fn = tc.get("function") or {}
                    slot["function"]["name"] += fn.get("name") or ""
                    slot["function"]["arguments"] += fn.get("arguments") or ""
                finish = c.get("finish_reason") or finish
        msg: dict[str, Any] = {"role": "assistant", "content": "".join(content) or None}
        if calls:
            msg["tool_calls"] = [calls[k] for k in sorted(calls)]
        resp = {"id": head.get("id"), "object": "chat.completion", "created": head.get("created"),
                "model": head.get("model"), "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
                "usage": usage}
        return self.read_json(resp), {"final": resp}

    def _rebuilt(self, resp: dict, new_text: dict[int, str], drop: set[int], note: str | None) -> dict:
        out = copy.deepcopy(resp)
        ch = out["choices"][0]
        msg = ch.setdefault("message", {"role": "assistant"})
        if 0 in new_text:
            msg["content"] = new_text[0]
        if drop:
            msg.pop("tool_calls", None)
            msg["content"] = ((msg.get("content") or "") + "\n" if msg.get("content") else "") + (note or "[AICL] tool call blocked")
            ch["finish_reason"] = "stop"
        return out

    def rebuild_json(self, resp: dict, new_text: dict[int, str], drop_tools: set[int], note: str | None) -> dict:
        return self._rebuilt(resp, new_text, drop_tools, note)

    def rebuild_sse(self, state: dict, new_text: dict[int, str], drop_tools: set[int], note: str | None) -> bytes:
        return self._stream(self._rebuilt(state["final"], new_text, drop_tools, note))


register_adapter("openai_responses", OpenAIResponses())
register_adapter("openai_chat", OpenAIChat())

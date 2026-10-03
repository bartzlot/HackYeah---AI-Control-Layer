import json

import httpx
import pytest

from cloud_sim import PRICES, Script, create_app, estimate_tokens, load_script


def client(script=None, prices=None):
    app = create_app(script or Script(), prices)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://sim"), app


def req(text="hello", model="gpt-4o-mini", **kw):
    return {"model": model, "messages": [{"role": "user", "content": text}], **kw}


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("a") == 1
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abcde") == 2


async def test_models_lists_priced_models():
    c, _ = client()
    r = await c.get("/v1/models")
    assert {m["id"] for m in r.json()["data"]} == set(PRICES)


async def test_echo_reply_and_usage_cost():
    c, _ = client()
    r = await c.post("/v1/chat/completions", json=req("abcdefgh"))
    body = r.json()
    assert body["choices"][0]["message"]["content"] == "echo: abcdefgh"
    u = body["usage"]
    assert u["prompt_tokens"] == 2
    assert u["completion_tokens"] == estimate_tokens("echo: abcdefgh")
    assert u["total_tokens"] == u["prompt_tokens"] + u["completion_tokens"]
    expected = (u["prompt_tokens"] * 0.15 + u["completion_tokens"] * 0.60) / 1e6
    assert u["cost_usd"] == pytest.approx(expected)


async def test_unpriced_model_is_rejected():
    c, _ = client()
    r = await c.post("/v1/chat/completions", json=req(model="mystery"))
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "model_not_found"


@pytest.mark.parametrize("payload", [{"model": "gpt-4o-mini"}, {"model": "gpt-4o-mini", "messages": []}])
async def test_bad_messages_rejected(payload):
    c, _ = client()
    assert (await c.post("/v1/chat/completions", json=payload)).status_code == 400


async def test_invalid_json_rejected():
    c, _ = client()
    r = await c.post("/v1/chat/completions", content=b"{nope", headers={"content-type": "application/json"})
    assert r.status_code == 400


async def test_scripted_reply_and_tool_calls_in_order():
    script = Script([
        {"match": {"contains": "weather"}, "tool_calls": [{"name": "get_weather", "arguments": {"city": "Krakow"}}]},
        {"reply": "done"},
    ])
    c, _ = client(script)
    first = (await c.post("/v1/chat/completions", json=req("what is the weather"))).json()["choices"][0]
    assert first["finish_reason"] == "tool_calls"
    call = first["message"]["tool_calls"][0]["function"]
    assert call["name"] == "get_weather" and json.loads(call["arguments"]) == {"city": "Krakow"}
    second = (await c.post("/v1/chat/completions", json=req("anything"))).json()["choices"][0]
    assert second["message"]["content"] == "done" and second["finish_reason"] == "stop"
    third = (await c.post("/v1/chat/completions", json=req("again"))).json()["choices"][0]
    assert third["message"]["content"] == "echo: again"


async def test_script_step_skipped_when_match_fails():
    script = Script([{"match": {"contains": "zzz"}, "reply": "secret"}])
    c, _ = client(script)
    r = await c.post("/v1/chat/completions", json=req("nothing"))
    assert r.json()["choices"][0]["message"]["content"] == "echo: nothing"


async def test_multipart_content_is_read():
    c, _ = client()
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": [{"type": "text", "text": "hi there"}]}]}
    assert (await c.post("/v1/chat/completions", json=body)).json()["choices"][0]["message"]["content"] == "echo: hi there"


async def test_stream_emits_sse_with_usage_and_done():
    c, _ = client(Script([{"reply": "one two"}]))
    r = await c.post("/v1/chat/completions", json=req(stream=True))
    assert r.headers["content-type"].startswith("text/event-stream")
    lines = [l for l in r.text.split("\n\n") if l]
    assert lines[-1] == "data: [DONE]"
    chunks = [json.loads(l[6:]) for l in lines[:-1]]
    text = "".join(c["choices"][0]["delta"].get("content", "") for c in chunks)
    assert text.split() == ["one", "two"]
    assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
    assert chunks[-1]["usage"]["completion_tokens"] == estimate_tokens("one two")


async def test_calls_are_recorded():
    c, app = client()
    await c.post("/v1/chat/completions", json=req("x"))
    assert len(app.state.calls) == 1


def test_load_script_from_yaml(tmp_path):
    f = tmp_path / "s.yaml"
    f.write_text("steps:\n  - reply: hi\n  - match: {contains: x}\n    reply: y\n", encoding="utf-8")
    s = load_script(f)
    assert len(s.steps) == 2
    assert load_script(None).steps == []

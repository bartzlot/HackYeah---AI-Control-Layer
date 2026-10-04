"""T-132 live event toasts: a demo batch reaches the console's live stream (the toasts' source), and the page has the
toast hooks on that stream."""
import httpx

from test_demo_batch import LOCALHOST, ROOT, rig  # noqa: F401  (rig is a fixture)


async def test_a_demo_batch_pushes_its_decisions_to_the_live_stream(rig):  # noqa: F811
    app, _, _ = rig()
    q = app.state.console.subscribe()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=LOCALHOST), base_url="http://gw") as c:
        assert (await c.post("/console/api/demo/batch")).status_code == 200
    live = []
    while not q.empty():
        live.append(q.get_nowait())
    toasts = [r for r in live if r.get("stage") != "dns" and r.get("event_type") not in ("PASSTHROUGH", "DNS_QUERY")]
    assert len(toasts) >= 11                                        # at least one toast per preset
    assert {"BLOCK", "REDACT"} <= {str(r["decision"]).upper() if isinstance(r["decision"], str)
                                   else ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"][r["decision"]] for r in toasts}


def test_console_page_has_the_toast_panel_on_the_live_stream():
    html = (ROOT / "w1-gateway/aicl_gateway/console/index.html").read_text(encoding="utf-8")
    js = (ROOT / "w1-gateway/aicl_gateway/console/app.js").read_text(encoding="utf-8")
    css = (ROOT / "w1-gateway/aicl_gateway/console/style.css").read_text(encoding="utf-8")
    assert 'id="toasts"' in html and "#toasts" in css and ".toast" in css
    stream = js[js.index('es.addEventListener("audit"'):]
    assert "toast(r)" in stream[:400]                              # every live record goes through toast()
    assert "TOAST_MAX" in js and "select(r)" in js[js.index("function toast("):js.index("// live stream")]

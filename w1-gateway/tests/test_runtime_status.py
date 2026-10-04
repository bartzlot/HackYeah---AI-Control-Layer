"""T-116 console runtime mode: GET /console/api/status reports the listeners this process really runs (HTTP,
TLS, DNS), the CA and upstream overrides; the header chip shows that mode, with a warning when the policy says
transparent but no TLS or DNS listener runs. Offline: real sockets on 127.0.0.1 only.
"""
from __future__ import annotations

import shutil
import threading
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from aicl_core import engine as eng
from aicl_gateway import serve
from aicl_gateway.console_api import ConsoleStore, make_console_router
from aicl_gateway.dns import wait_ready
from aicl_gateway.main import create_app_from_env

from test_ca_dns_tls import free_port, wait_listening

ROOT = Path(__file__).resolve().parents[2]
CONSOLE = ROOT / "w1-gateway" / "aicl_gateway" / "console"


def env_for(tmp_path: Path, mode: str | None = None, **extra) -> dict:
    shutil.copytree(ROOT / "policy", tmp_path / "policy")
    pol = tmp_path / "policy" / "policy.yaml"
    if mode is not None:
        pol.write_text(pol.read_text(encoding="utf-8").replace("  mode: transparent\n", f"  mode: {mode}\n", 1),
                       encoding="utf-8")
    d = tmp_path / "d"
    return {"AICL_POLICY": str(pol), "AICL_DATA_DIR": str(d), "AICL_AUDIT_PATH": str(d / "a.jsonl"),
            "AICL_BUDGET_DB": str(d / "b.db"), "AICL_CA_ROOT": str(tmp_path), **extra}


@pytest.fixture(autouse=True)
def _no_overrides(monkeypatch):
    monkeypatch.delenv("AICL_UPSTREAM_ANTHROPIC", raising=False)
    monkeypatch.delenv("AICL_UPSTREAM_OPENAI", raising=False)
    yield
    eng.REGISTRY.pop("INJ-04", None)


async def get_status(app) -> dict:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:18080") as c:
        r = await c.get("/console/api/status")
    assert r.status_code == 200
    return r.json()


async def test_factory_app_is_base_url_and_warns_when_the_policy_says_transparent(tmp_path):
    """uvicorn --factory (Cloud Run, base compose): no TLS, no DNS -> base-URL, with both warnings."""
    app = create_app_from_env(env_for(tmp_path), start_reload=False)
    try:
        s = await get_status(app)
    finally:
        app.state.engine.store.stop()
    assert s["policy_mode"] == "transparent" and s["mode"] == "base_url" and s["passthrough"] is True
    ls = s["listeners"]
    assert ls["http"]["on"] is True and ls["tls"]["on"] is False and ls["dns"]["on"] is False
    assert any("no TLS listener" in w for w in s["warnings"])
    assert any("DNS resolver is not running" in w for w in s["warnings"])
    assert s["ca"]["present"] is False and s["upstream_overrides"] == {} and s["notes"] == []


async def test_policy_base_url_without_listeners_has_no_warning(tmp_path):
    app = create_app_from_env(env_for(tmp_path, mode="base_url"), start_reload=False)
    try:
        s = await get_status(app)
    finally:
        app.state.engine.store.stop()
    assert (s["mode"], s["policy_mode"], s["warnings"]) == ("base_url", "base_url", [])


async def test_serve_with_tls_and_dns_is_transparent_and_follows_the_live_listeners(tmp_path):
    """serve.build(): live TLS + DNS -> transparent, no warning; DNS stopped -> the warning is back at once."""
    tls_port, dns_port = free_port(), free_port()
    env = env_for(tmp_path, AICL_TLS_PORT=str(tls_port), AICL_HTTP_PORT=str(free_port()),
                  AICL_DNS_LISTEN=f"127.0.0.1:{dns_port}")
    app, servers, dns = serve.build(env)
    tls = servers[1]
    th = threading.Thread(target=tls.run, daemon=True)
    try:
        s = await get_status(app)
        assert s["listeners"]["tls"]["on"] is False and s["listeners"]["dns"]["on"] is False   # built, not started
        assert s["mode"] == "base_url" and s["listeners"]["http"]["on"] is False

        th.start()
        dns.start(sweep_s=3600)
        wait_listening(tls, tls_port)
        wait_ready(dns_port)
        s = await get_status(app)
        assert s["mode"] == "transparent" and s["warnings"] == []
        assert s["listeners"]["tls"] == {"on": True, "bind": "127.0.0.1", "port": tls_port}
        assert s["listeners"]["dns"] == {"on": True, "bind": "127.0.0.1", "port": dns_port}
        assert s["ca"] == {"present": True, "path": "data/ca/aicl-ca.pem"}
        assert "api.anthropic.com" in s["intercepted_hosts"]

        dns.stop()
        s = await get_status(app)
        assert s["mode"] == "transparent" and s["listeners"]["dns"]["on"] is False
        assert len(s["warnings"]) == 1 and "DNS resolver is not running" in s["warnings"][0]
    finally:
        dns.stop()
        tls.should_exit = True
        if th.is_alive():
            th.join(timeout=5)
        app.state.engine.store.stop()


async def test_policy_off_with_listeners_running_warns_passthrough_disabled(tmp_path):
    tls_port = free_port()
    env = env_for(tmp_path, mode="off", AICL_TLS_PORT=str(tls_port), AICL_HTTP_PORT=str(free_port()))
    app, servers, _ = serve.build(env)
    tls = servers[1]
    th = threading.Thread(target=tls.run, daemon=True)
    th.start()
    try:
        wait_listening(tls, tls_port)
        s = await get_status(app)
    finally:
        tls.should_exit = True
        th.join(timeout=5)
        app.state.engine.store.stop()
    assert (s["mode"], s["passthrough"]) == ("off", False)
    assert any("passthrough is disabled" in w for w in s["warnings"])


async def test_loopback_gateway_ip_with_dns_running_warns(tmp_path):
    dns_port = free_port()
    env = env_for(tmp_path, AICL_DNS_LISTEN=f"127.0.0.1:{dns_port}", AICL_HTTP_PORT=str(free_port()))
    pol = Path(env["AICL_POLICY"])
    pol.write_text(pol.read_text(encoding="utf-8").replace("gateway_ip: 10.77.0.2", "gateway_ip: 127.0.0.1", 1),
                   encoding="utf-8")
    app, _, dns = serve.build(env)
    dns.start(sweep_s=3600)
    try:
        wait_ready(dns_port)
        s = await get_status(app)
    finally:
        dns.stop()
        app.state.engine.store.stop()
    assert any("sent to themselves" in w for w in s["warnings"])


async def test_upstream_override_is_a_note_without_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("AICL_UPSTREAM_ANTHROPIC", "http://user:secret@mock-anthropic:18210/base?k=v")
    app = create_app_from_env(env_for(tmp_path, mode="base_url"), start_reload=False)
    try:
        s = await get_status(app)
    finally:
        app.state.engine.store.stop()
    assert s["upstream_overrides"] == {"anthropic": "http://mock-anthropic:18210/base"}
    assert s["warnings"] == [] and len(s["notes"]) == 1 and "mock-anthropic" in s["notes"][0]
    assert "secret" not in str(s) and "k=v" not in str(s)


async def test_status_route_without_wiring_or_with_a_failing_view_never_breaks():
    for info in (None, {"status": lambda served=None: 1 / 0}):
        app = FastAPI()
        app.include_router(make_console_router(ConsoleStore(), info=info))
        s = await get_status(app)
        assert s["mode"] == "unknown"
    assert s["warnings"] == ["status unavailable: ZeroDivisionError"]


def test_header_chip_reads_the_runtime_status_not_the_policy_mode():
    js = (CONSOLE / "app.js").read_text(encoding="utf-8")
    assert 'API + "/status"' in js and '"interception: "' not in js
    assert 'c.className = "chip mode" + (w.length ? " warn" : "")' in js
    assert ".chip.mode.warn{" in (CONSOLE / "style.css").read_text(encoding="utf-8")

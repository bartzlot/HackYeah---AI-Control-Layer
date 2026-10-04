"""T-110 (AICL CA + TLS listener) and T-111 (AICL DNS resolver), offline: real sockets on 127.0.0.1 only.

TLS: a client that trusts ONLY the AICL CA opens TLS to the gateway with SNI api.anthropic.com (what a client
does after the AICL DNS answered with the gateway address) and gets a verified handshake and an inspected,
proxied answer from the Anthropic mock. DNS: intercepted names -> gateway ip, AAAA empty, DoH sinkholed,
the rest forwarded to an upstream (a local fake upstream here).
"""
from __future__ import annotations

import json
import shutil
import socket
import ssl
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSServer

from aicl_gateway import ca
from aicl_gateway.dns import AiclResolver, Dns, wait_ready
from aicl_gateway.main import create_app_from_env
from aicl_gateway.mock_providers import anthropic_app

ROOT = Path(__file__).resolve().parents[2]
HOSTS = ["api.anthropic.com", "api.openai.com"]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---- CA ------------------------------------------------------------------------------------------

def test_ca_and_leaf_chain_verifies_with_the_intercepted_hosts(tmp_path):
    tls = {"ca_cert": "ca/aicl-ca.pem", "ca_key": "ca/aicl-ca.key", "leaf_days": 30}
    cert_path, key_path = ca.ensure(tls, HOSTS, ["10.77.0.2"], root=tmp_path)
    root = x509.load_pem_x509_certificate((tmp_path / "ca/aicl-ca.pem").read_bytes())
    chain = x509.load_pem_x509_certificates(cert_path.read_bytes())
    leaf = chain[0]
    assert len(chain) == 2 and chain[1] == root
    root.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert set(HOSTS) <= set(ca.leaf_hosts(leaf))
    ips = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)
    assert "10.77.0.2" in {str(i) for i in ips}


def test_leaf_is_reissued_only_when_the_host_list_changes(tmp_path):
    tls = {"ca_cert": "ca/aicl-ca.pem", "ca_key": "ca/aicl-ca.key"}
    c1, _ = ca.ensure(tls, HOSTS, [], root=tmp_path)
    s1 = c1.read_bytes()
    ca_bytes = (tmp_path / "ca/aicl-ca.pem").read_bytes()
    ca.ensure(tls, HOSTS, [], root=tmp_path)
    assert c1.read_bytes() == s1                              # unchanged
    ca.ensure(tls, HOSTS + ["generativelanguage.googleapis.com"], [], root=tmp_path)
    assert c1.read_bytes() != s1                              # new SAN list -> new leaf
    assert (tmp_path / "ca/aicl-ca.pem").read_bytes() == ca_bytes   # the root never changes


def test_ca_export_prints_install_commands(tmp_path, monkeypatch, capsys):
    pdir = tmp_path / "policy"
    shutil.copytree(ROOT / "policy", pdir)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AICL_POLICY", str(pdir / "policy.yaml"))
    assert ca.main(["export"]) == 0
    out = capsys.readouterr().out
    assert "certutil" in out and "NODE_EXTRA_CA_CERTS" in out and "update-ca-certificates" in out
    assert (tmp_path / "data/ca/aicl-ca.pem").exists()


# ---- TLS listener end to end ---------------------------------------------------------------------

@pytest.fixture
def tls_gateway(tmp_path):
    from aicl_core import engine as eng
    pdir = tmp_path / "policy"
    shutil.copytree(ROOT / "policy", pdir)
    mock = anthropic_app()
    env = {"AICL_POLICY": str(pdir / "policy.yaml"), "AICL_DATA_DIR": str(tmp_path / "data"),
           "AICL_AUDIT_PATH": str(tmp_path / "data/audit.jsonl"), "AICL_BUDGET_DB": str(tmp_path / "data/b.db")}
    ups = {"anthropic": httpx.AsyncClient(transport=httpx.ASGITransport(app=mock), base_url="https://api.anthropic.com")}
    app = create_app_from_env(env, upstreams=ups, judge_chat=lambda b, t: {"message": {"content": json.dumps(
        {"prompt_injection": "none", "data_exfiltration": "none", "jailbreak": "none", "tool_abuse": "none",
         "verdict": "benign"})}}, reload_interval=0.0, start_reload=False)
    cert, key = ca.ensure({"ca_cert": "ca/aicl-ca.pem", "ca_key": "ca/aicl-ca.key"}, HOSTS, [], root=tmp_path)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, ssl_certfile=str(cert),
                                           ssl_keyfile=str(key), log_level="warning", lifespan="off"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield port, tmp_path / "ca/aicl-ca.pem", mock
    server.should_exit = True
    th.join(timeout=5)
    eng.REGISTRY.pop("INJ-04", None)


def https_raw(port: int, cafile: Path, sni: str, request: bytes) -> bytes:
    ctx = ssl.create_default_context(cafile=str(cafile))      # trusts ONLY the AICL root
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=sni) as tls:
            tls.sendall(request)
            out = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                out += chunk
    return out


def test_tls_handshake_for_the_provider_name_and_inspected_passthrough(tls_gateway):
    port, cafile, mock = tls_gateway
    body = json.dumps({"model": "claude-sonnet-5-5", "max_tokens": 100, "stream": False,
                       "messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"}]}).encode()
    req = (b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nx-api-key: sk-ant-synthetic\r\n"
           b"content-type: application/json\r\nconnection: close\r\ncontent-length: " + str(len(body)).encode()
           + b"\r\n\r\n" + body)
    raw = https_raw(port, cafile, "api.anthropic.com", req)
    head, _, payload = raw.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200") and b"x-aicl-decision: redact" in head.lower()
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(mock.state.seen[-1]["body"])


def test_tls_refuses_a_name_outside_the_leaf(tls_gateway):
    port, cafile, _ = tls_gateway
    with pytest.raises(ssl.SSLCertVerificationError):
        https_raw(port, cafile, "www.example.com", b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")


def test_a_client_without_the_aicl_ca_fails_closed(tls_gateway):
    port, _, mock = tls_gateway
    ctx = ssl.create_default_context()                        # system roots only
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        with pytest.raises(ssl.SSLCertVerificationError):
            ctx.wrap_socket(sock, server_hostname="api.anthropic.com")
    assert not mock.state.seen                                # nothing leaked anywhere


# ---- DNS -----------------------------------------------------------------------------------------

class FakeUpstream(BaseResolver):
    def resolve(self, request, handler):
        r = request.reply()
        if QTYPE[request.q.qtype] == "A":
            r.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=60))
        return r


@pytest.fixture
def dns_rig(tmp_path):
    upstream, up_port = None, 0
    for _ in range(20):                 # Windows reserves port ranges (Hyper-V): retry on WinError 10013
        try:
            up_port = free_port()
            upstream = DNSServer(FakeUpstream(), address="127.0.0.1", port=up_port)
            break
        except OSError:
            continue
    upstream.start_thread()
    raw = {"interception": {"mode": "transparent",
                            "providers": {"anthropic": {"hosts": ["api.anthropic.com"], "protocol": "anthropic_messages",
                                                        "inspect": ["/v1/messages"]}},
                            "dns": {"gateway_ip": "10.77.0.2", "upstream": [f"127.0.0.1:{up_port}"],
                                    "doh_sinkhole": ["dns.google"], "log_queries": False}},
           "clients": [{"match": {"cidr": "127.0.0.0/8"}, "principal": "demo-dev"}]}
    holder = {"raw": raw}
    records = []

    class Sink:
        def emit(self, rec):
            records.append(rec)
    dns = None
    for _ in range(20):
        try:
            dns = Dns(AiclResolver(lambda: holder["raw"], audit=Sink()), f"127.0.0.1:{free_port()}").start()
            break
        except OSError:
            continue
    wait_ready(dns.port)
    yield dns, holder, records
    dns.stop()
    upstream.stop()


def ask(port: int, name: str, qtype: str = "A", tcp: bool = False) -> DNSRecord:
    return DNSRecord.parse(DNSRecord.question(name, qtype).send("127.0.0.1", port, tcp=tcp, timeout=3))


def test_intercepted_host_resolves_to_the_gateway_over_udp_and_tcp(dns_rig):
    dns, _, records = dns_rig
    for tcp in (False, True):
        r = ask(dns.port, "api.anthropic.com", tcp=tcp)
        assert [str(a.rdata) for a in r.rr] == ["10.77.0.2"]
    rec = records[-1]
    assert rec.event_type == "DNS_QUERY" and rec.agent_id == "demo-dev" and rec.upstream_host == "api.anthropic.com"


def test_aaaa_for_an_intercepted_host_is_empty_so_ipv6_cannot_bypass(dns_rig):
    dns, _, _ = dns_rig
    r = ask(dns.port, "api.anthropic.com", "AAAA")
    assert r.header.rcode == RCODE.NOERROR and not r.rr


def test_doh_resolver_is_sinkholed_and_flagged(dns_rig):
    dns, _, records = dns_rig
    r = ask(dns.port, "dns.google")
    assert r.header.rcode == RCODE.NXDOMAIN
    assert records[-1].event_type == "BYPASS_SUSPECTED" and records[-1].decision >= 2


def test_other_names_are_forwarded_upstream(dns_rig):
    dns, _, _ = dns_rig
    before = dns.resolver.stats["forwarded"]
    r = ask(dns.port, "example.com")
    assert [str(a.rdata) for a in r.rr] == ["93.184.216.34"]
    assert dns.resolver.stats["forwarded"] == before + 1


def test_live_policy_edit_changes_the_host_list(dns_rig):
    dns, holder, _ = dns_rig
    raw = json.loads(json.dumps(holder["raw"]))
    raw["interception"]["providers"]["anthropic"]["hosts"].append("api.example-llm.com")
    holder["raw"] = raw
    assert [str(a.rdata) for a in ask(dns.port, "api.example-llm.com").rr] == ["10.77.0.2"]
    raw2 = json.loads(json.dumps(raw))
    raw2["interception"]["mode"] = "off"            # interception off: names resolve normally again
    holder["raw"] = raw2
    assert [str(a.rdata) for a in ask(dns.port, "api.anthropic.com").rr] == ["93.184.216.34"]


# ---- T-208: NET-01 lookup without traffic through AICL -------------------------------------------

def test_net01_lookup_without_a_gateway_request_raises_a_bypass_alert():
    from aicl_gateway.dns import AiclResolver, BypassWatch, report_stale
    now = [0.0]
    watch = BypassWatch(window_s=30, clock=lambda: now[0])
    recs = []

    class Sink:
        def emit(self, r):
            recs.append(r)
    raw = {"interception": {"mode": "transparent", "providers": {"anthropic": {
        "hosts": ["api.anthropic.com"], "protocol": "anthropic_messages", "inspect": ["/v1/messages"]}},
        "dns": {"gateway_ip": "10.77.0.2", "upstream": ["127.0.0.1:9"], "doh_sinkhole": [], "log_queries": False}}}
    res = AiclResolver(lambda: raw, audit=Sink(), watch=watch)

    class H:
        client_address = ("10.77.0.10", 5353)
    res.resolve(DNSRecord.question("api.anthropic.com"), H())       # laptop A: looks up, never connects
    H.client_address = ("10.77.0.11", 5353)
    res.resolve(DNSRecord.question("api.anthropic.com"), H())       # laptop B: looks up and connects
    watch.note_request("10.77.0.11", "api.anthropic.com")
    now[0] = 10
    assert report_stale(res) == 0                                    # still inside the window
    now[0] = 31
    assert report_stale(res) == 1
    alert = [r for r in recs if r.event_type == "BYPASS_SUSPECTED"]
    assert len(alert) == 1 and alert[0].client_ip == "10.77.0.10" and "NET-01" in alert[0].explain[0]
    assert report_stale(res) == 0                                    # reported once


async def test_net01_passthrough_requests_clear_the_pending_lookup(tmp_path):
    from aicl_gateway.dns import BypassWatch
    from aicl_core import engine as eng
    shutil.copytree(ROOT / "policy", tmp_path / "policy")
    env = {"AICL_POLICY": str(tmp_path / "policy" / "policy.yaml"), "AICL_DATA_DIR": str(tmp_path / "d"),
           "AICL_AUDIT_PATH": str(tmp_path / "d" / "a.jsonl"), "AICL_BUDGET_DB": str(tmp_path / "d" / "b.db")}
    mock = anthropic_app()
    app = create_app_from_env(env, upstreams={"anthropic": httpx.AsyncClient(transport=httpx.ASGITransport(app=mock),
                                                                           base_url="https://api.anthropic.com")},
                              judge_chat=lambda b, t: {}, reload_interval=0.0, start_reload=False)
    w = BypassWatch(window_s=0, clock=lambda: 100.0)
    app.state.passthrough.watch = w
    w.note_lookup("127.0.0.1", "api.anthropic.com")
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://api.anthropic.com")
    await c.head("/api/hello", headers={"x-api-key": "sk-ant-synthetic"})
    assert w.sweep() == []
    eng.REGISTRY.pop("INJ-04", None)


def test_leaf_is_reissued_when_the_gateway_ip_or_the_ca_changes(tmp_path):
    tls = {"ca_cert": "ca/aicl-ca.pem", "ca_key": "ca/aicl-ca.key"}
    c1, _ = ca.ensure(tls, HOSTS, ["10.77.0.2"], root=tmp_path)
    first = c1.read_bytes()
    ca.ensure(tls, HOSTS, ["10.77.0.3"], root=tmp_path)
    second = c1.read_bytes()
    assert second != first
    ca.init_ca(tmp_path / "ca/aicl-ca.pem", tmp_path / "ca/aicl-ca.key", force=True)   # new root
    ca.ensure(tls, HOSTS, ["10.77.0.3"], root=tmp_path)
    assert c1.read_bytes() != second


def test_t115_new_intercepted_host_gets_tls_without_a_restart(tmp_path):
    """serve.build(): the running TLS listener serves a host added to the policy after start (new leaf, new SAN)."""
    from aicl_core import engine as eng
    from aicl_gateway import policy_admin, serve
    shutil.copytree(ROOT / "policy", tmp_path / "policy")
    tls_port = free_port()
    env = {"AICL_POLICY": str(tmp_path / "policy" / "policy.yaml"), "AICL_DATA_DIR": str(tmp_path / "d"),
           "AICL_AUDIT_PATH": str(tmp_path / "d" / "a.jsonl"), "AICL_BUDGET_DB": str(tmp_path / "d" / "b.db"),
           "AICL_TLS_PORT": str(tls_port), "AICL_HTTP_PORT": str(free_port()), "AICL_CA_ROOT": str(tmp_path)}
    app, servers, dns = serve.build(env)
    tls = servers[1]
    th = threading.Thread(target=tls.run, daemon=True)
    th.start()
    for _ in range(100):
        if tls.started:
            break
        time.sleep(0.05)
    cafile = tmp_path / "data" / "ca" / "aicl-ca.pem"
    req = b"GET /healthz HTTP/1.1\r\nHost: x\r\nconnection: close\r\n\r\n"
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            https_raw(tls_port, cafile, "api.claude-proxy.example", req)
        policy_admin.edit_interception(Path(env["AICL_POLICY"]),
                                       {"add_host": {"provider": "anthropic", "host": "api.claude-proxy.example"}},
                                       app.state.engine)
        out = https_raw(tls_port, cafile, "api.claude-proxy.example", req)
        assert out.startswith(b"HTTP/1.1 200")
    finally:
        tls.should_exit = True
        th.join(timeout=5)
        app.state.engine.store.stop()
        eng.REGISTRY.pop("INJ-04", None)

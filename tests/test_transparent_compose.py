"""T-014: the transparent demo compose models the organization network correctly (static checks, offline)."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
C = yaml.safe_load((ROOT / "docker-compose.transparent.yml").read_text(encoding="utf-8"))
POL = yaml.safe_load((ROOT / "policy" / "policy.yaml").read_text(encoding="utf-8"))


def test_corp_network_has_no_route_out():
    assert C["networks"]["corp"]["internal"] is True


def test_devbox_only_on_corp_with_aicl_dns_and_no_base_url():
    d = C["services"]["devbox"]
    assert list(d["networks"]) == ["corp"]
    gw = C["services"]["aicl"]["networks"]["corp"]["ipv4_address"]
    assert d["dns"] == [gw] == [POL["interception"]["dns"]["gateway_ip"]]
    assert "ANTHROPIC_BASE_URL" not in d["environment"] and "HTTPS_PROXY" not in d["environment"]


def test_devbox_never_sees_the_ca_key():
    d = C["services"]["devbox"]
    mounts = " ".join(d["volumes"])
    assert "aicl-ca-public" in mounts and "aicl-data" not in mounts
    assert any(v.startswith("aicl-data:/app/data") for v in C["services"]["aicl"]["volumes"])


def test_gateway_serves_dns_and_tls_and_console_is_host_only():
    g = C["services"]["aicl"]
    env = g["environment"]
    assert env["AICL_TLS_PORT"] == "443" and env["AICL_DNS_LISTEN"].endswith(":53")
    assert g["ports"] == ["127.0.0.1:${AICL_TRANSPARENT_HTTP_PORT:-18080}:18080"]
    assert set(g["networks"]) == {"corp", "egress"}


def test_policy_is_mounted_writable_for_console_edits_with_a_token():
    assert "./policy:/app/policy" in C["services"]["aicl"]["volumes"]
    assert C["services"]["aicl"]["environment"]["AICL_ADMIN_TOKEN"] == "${AICL_ADMIN_TOKEN:-}"


def test_host_port_configurable_and_smoke_and_docs():
    sh = (ROOT / "scripts" / "demo-transparent.sh").read_text(encoding="utf-8")
    assert "AICL_TRANSPARENT_HTTP_PORT" in sh and "SMOKE OK" in sh and "claude -p" in sh
    assert C["services"]["aicl"]["environment"]["AICL_HTTP_PORT"] == "18080"   # in-container port is fixed
    assert "AICL_TRANSPARENT_HTTP_PORT" in (ROOT / ".env.example").read_text(encoding="utf-8")


def test_host_section_prints_but_never_runs_trust_commands():
    sh = (ROOT / "scripts" / "demo-transparent.sh").read_text(encoding="utf-8")
    assert "host-setup" in sh and "never run" in sh
    for l in sh.splitlines():
        if "update-ca-certificates" in l or "security add-trusted-cert" in l or "Import-Certificate" in l:
            assert l.lstrip().startswith("echo"), l
    assert "Transparent mode on a host" in (ROOT / "README.md").read_text(encoding="utf-8")

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
    assert g["ports"] == ["127.0.0.1:18080:18080"]
    assert set(g["networks"]) == {"corp", "egress"}


def test_policy_is_mounted_read_only_for_live_edits():
    assert "./policy:/app/policy:ro" in C["services"]["aicl"]["volumes"]

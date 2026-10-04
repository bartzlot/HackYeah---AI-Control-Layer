"""T-013 acceptance: v4 contracts + interception: / clients: policy blocks (research/14 s.4, s.6)."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from aicl_contracts import AUDIT_EVENT_TYPES, PROTOCOLS, AuditRecord, Event, Stage
from aicl_core import interception as I
from aicl_core.engine import Engine, resolve_destination
from aicl_core.policy import PolicyError, PolicyStore, load_policy

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "policy" / "policy.yaml"


@pytest.fixture()
def pdir(tmp_path):
    d = tmp_path / "policy"
    shutil.copytree(ROOT / "policy", d)
    return d


def _with(pdir: Path, extra: str) -> Path:
    (pdir / "local.d").mkdir(exist_ok=True)
    (pdir / "local.d" / "zz-test.yaml").write_text(extra, encoding="utf-8")
    return pdir / "policy.yaml"


# ---- contracts ----------------------------------------------------------------------------------

def test_event_carries_passthrough_identity_and_defaults_stay_compatible():
    e = Event(protocol="anthropic_messages", upstream_host="api.anthropic.com", client_ip="10.77.0.5",
              credential_hash="3f2a9c1b", user_agent="claude-cli/2.1.289")
    assert e.protocol in PROTOCOLS and e.channel == "llm"
    old = Event()                                   # every pre-v4 producer keeps working
    assert old.protocol is None and old.client_ip is None
    with pytest.raises(ValueError):
        Event(protocol="grpc")
    assert Event(stage=Stage.DNS, channel="dns").stage == "dns"


def test_audit_record_has_v4_fields_and_event_types():
    r = AuditRecord(ts="2026-10-04T00:00:00Z", event_id="e1", event_type="PASSTHROUGH", decision=0,
                    stage="prompt", protocol="openai_responses", upstream_host="api.openai.com")
    assert r.upstream_host == "api.openai.com"
    assert {"PASSTHROUGH", "DNS_QUERY", "BYPASS_SUSPECTED"} <= set(AUDIT_EVENT_TYPES)


# ---- policy: the shipped file -------------------------------------------------------------------

def test_shipped_policy_has_transparent_interception_for_anthropic_and_openai():
    pol = load_policy(POLICY)
    cfg = pol.interception()
    assert cfg["mode"] == "transparent" and cfg["credentials"] == "passthrough"
    assert I.intercepted_hosts(cfg) == ["api.anthropic.com", "api.openai.com"]
    name, prov = I.provider_for_host(cfg, "API.Anthropic.COM:443")
    assert name == "anthropic" and prov["protocol"] == "anthropic_messages"
    assert I.provider_for_host(cfg, "example.com") is None
    assert cfg["max_body_kb"] >= 4096                 # Claude Code sends ~275 tool definitions
    # measured native contract (research/14 s.3): never refusal / 403 for Anthropic
    assert cfg["block_style"]["anthropic_messages"] == {"hard": "http_400", "soft": "assistant_text",
                                                        "budget": "http_402"}


def test_inspected_paths_ignore_query_and_leave_probes_to_the_proxy():
    prov = I.provider_for_host(load_policy(POLICY).interception(), "api.anthropic.com")[1]
    assert I.is_inspected(prov, "/v1/messages?beta=true")
    assert not I.is_inspected(prov, "/api/hello")
    assert not I.is_inspected(prov, "/v1/messages/count_tokens")


def test_real_provider_models_are_priced_external_and_cloud_tags_stay_unknown():
    pol = load_policy(POLICY)
    models = pol.raw["destinations"]["models"]
    assert models["claude-opus-5-5"]["price"] == {"in_usd_per_mtok": 4.0, "out_usd_per_mtok": 20.0}
    assert models["claude-sonnet-5-5"]["price"] == {"in_usd_per_mtok": 2.0, "out_usd_per_mtok": 10.0}
    assert models["gpt-5.5"]["price"] == {"in_usd_per_mtok": 5.0, "out_usd_per_mtok": 30.0}
    for tag, want in (("claude-opus-5-5", "external"), ("claude-some-future-9", "external"),
                      ("gpt-6-astra", "external"), ("gpt-oss:120b-cloud", "unknown"), ("mystery", "unknown")):
        assert resolve_destination(pol, Event(model=tag, destination="local")).value == want, tag


def test_managed_upstreams_never_serve_passthrough_models():
    from aicl_gateway.main import models_from_policy
    served = models_from_policy(load_policy(POLICY).raw, {})
    assert "qwen3.5:2b-q4_K_M" in served and "gpt-4o-mini" in served
    assert not any(t.startswith("claude-") or t.startswith("gpt-5") for t in served)


# ---- clients ------------------------------------------------------------------------------------

def test_client_identity_first_match_wins_and_unknown_falls_back():
    raw = load_policy(POLICY).raw
    c = I.client_for(raw, "10.77.0.9", "ab12cd34", "claude-cli/2.1.289")
    assert c["principal"] == "demo-dev" and c["matched"] and I.model_allowed(c["models"], "claude-opus-5-5")
    assert not I.model_allowed(c["models"], "gpt-oss:120b-cloud")
    u = I.client_for(raw, "192.168.1.5", None, None)
    assert u["principal"] == "unknown-client" and not u["matched"] and u["action"] == "ALLOW"


def test_client_match_on_key_prefix_and_user_agent_glob(pdir):
    pol = load_policy(_with(pdir, """
clients:
  - {match: {key_sha256_prefix: "3F2A", user_agent: "codex*"}, principal: alice, team: data}
  - {match: {any: true}, principal: everyone}
"""))
    assert I.client_for(pol.raw, "1.2.3.4", "3f2a9c1b", "codex_cli_rs/0.40")["principal"] == "alice"
    assert I.client_for(pol.raw, "1.2.3.4", "3f2a9c1b", "claude-cli/2")["principal"] == "everyone"
    assert I.client_for(pol.raw, "1.2.3.4", None, "codex_cli_rs/0.40")["principal"] == "everyone"


# ---- validation: a bad edit keeps the last good policy -------------------------------------------

@pytest.mark.parametrize("bad, msg", [
    ("interception: {mode: sniff}", "interception.mode"),
    ("interception: {credentials: steal}", "interception.credentials"),
    ("interception: {providers: {x: {hosts: [], protocol: anthropic_messages}}}", "hosts"),
    ("interception: {providers: {x: {hosts: [a.example], protocol: grpc}}}", "protocol"),
    ("interception: {providers: {x: {hosts: [api.anthropic.com], protocol: openai_chat, inspect: [/v1/x]}}}",
     "already belongs"),
    ("interception: {block_style: {anthropic_messages: {hard: http_403}}}", "block_style"),
    ("interception: {dns: {gateway_ip: not-an-ip}}", "gateway_ip"),
    ("interception: {max_body_kb: 0}", "max_body_kb"),
    ("interception: {unknown_client: {action: PRAY}}", "unknown_client"),
    ("clients: [{match: {cidr: 10.0.0.0/33}, principal: x}]", "cidr"),
    ("clients: [{match: {ip: 1.2.3.4}, principal: x}]", "match"),
    ("clients: [{match: {any: true}}]", "principal"),
])
def test_invalid_interception_edits_are_rejected(pdir, bad, msg):
    with pytest.raises(PolicyError, match=msg):
        load_policy(_with(pdir, bad))


def test_invalid_edit_keeps_last_good_and_valid_edit_applies_live(pdir):
    store = PolicyStore(pdir / "policy.yaml")
    v0 = store.current.version
    _with(pdir, "interception: {mode: sniff}")
    store.refresh(force=True)
    assert store.error and store.current.version == v0
    _with(pdir, "interception: {mode: base_url, proxy_other_paths: false}")
    assert store.refresh(force=True) and store.error is None
    assert store.current.interception()["mode"] == "base_url"
    assert store.current.interception()["proxy_other_paths"] is False


def test_policy_without_interception_block_means_off(pdir):
    pol = load_policy(_with(pdir, "interception: null\nclients: null\n"))
    assert pol.interception()["mode"] == "off" and I.intercepted_hosts(pol.interception()) == []
    assert Engine(pdir / "policy.yaml").policy.version


# ---- review findings (fresh-session review of T-013) --------------------------------------------

@pytest.mark.parametrize("bad, msg", [
    ("interception: {proxy_other_path: false}", "unknown key"),
    ("interception: {unknown_client: {actoin: BLOCK}}", "unknown key"),
    ("interception: {providers: {anthropic: {inspct: [/v1/messages]}}}", "unknown key"),
    ("interception: {providers: {anthropic: {inspect: []}}}", "inspect"),
    ("interception: {providers: {anthropic: {inspect: ['/v1//messages']}}}", "plain absolute path"),
    ("interception: {dns: {log_queries: maybe}}", "log_queries"),
    ("clients: [{match: {any: 'no'}, principal: x}]", "any"),
    ("clients: [{match: {key_sha256_prefix: ''}, principal: x}]", "key_sha256_prefix"),
    ("clients: [{match: {key_sha256_prefix: 1234567}, principal: x}]", "key_sha256_prefix"),
    ("clients: [{match: {key_sha256_prefix: '0123456789'}, principal: x}]", "key_sha256_prefix"),
    ("clients: [{match: {any: true}, principal: x, model: [claude-*]}]", "unknown key"),
    ("clients: [{match: {any: true}, principal: x, profile: yolo}]", "profile"),
])
def test_review_typos_and_weak_shapes_fail_the_load(pdir, bad, msg):
    with pytest.raises(PolicyError, match=msg):
        load_policy(_with(pdir, bad))


def test_ipv4_mapped_client_address_matches_its_cidr():
    raw = load_policy(POLICY).raw
    assert I.client_for(raw, "::ffff:10.77.0.5", None, None)["principal"] == "demo-dev"


def test_key_prefix_is_case_insensitive(pdir):
    pol = load_policy(_with(pdir, "clients: [{match: {key_sha256_prefix: 'AB12'}, principal: alice}]"))
    assert I.client_for(pol.raw, None, "AB12CD34", None)["principal"] == "alice"


@pytest.mark.parametrize("path", ["/v1//messages", "/v1/%6Dessages", "/v1/./messages", "/v1/messages;x",
                                  "/v1/x/../messages", "/v1/messages/"])
def test_non_canonical_spellings_are_still_inspected_and_flagged(path):
    prov = I.provider_for_host(load_policy(POLICY).interception(), "api.anthropic.com")[1]
    assert I.is_inspected(prov, path)
    assert I.is_canonical(path) == (path == "/v1/messages/")


def test_current_opus_models_are_priced():
    models = load_policy(POLICY).raw["destinations"]["models"]
    for v in ("claude-opus-4-7", "claude-opus-4-6", "claude-opus-4-5"):
        assert models[v]["price"] == {"in_usd_per_mtok": 5.0, "out_usd_per_mtok": 25.0}


def test_null_block_in_the_main_file_is_a_validation_error_not_a_crash():
    with pytest.raises(ValueError, match="block_style"):
        I.validate({"interception": {"block_style": None}})

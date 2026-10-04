"""v4 transparent interception (research/14 s.4, s.6): the `interception:` and `clients:` policy blocks.

`interception_cfg(raw)` returns the block with every default filled in, `validate(raw)` raises ValueError on
a bad shape (the policy loader turns it into a PolicyError, so the last good policy stays), `provider_for_host`
maps a Host / SNI name to its provider, and `client_for` maps a passthrough request to a principal.
"""
from __future__ import annotations

import copy
import fnmatch
import ipaddress
import re
from typing import Any

from aicl_contracts import PROTOCOLS

MODES = ("off", "base_url", "transparent")
CREDENTIALS = ("passthrough", "managed")
BLOCK_KINDS = ("hard", "soft", "budget")
BLOCK_STYLES = ("http_400", "http_402", "http_429", "assistant_text", "refusal", "verify")
MATCH_KEYS = ("cidr", "key_sha256_prefix", "user_agent", "any")

DEFAULTS: dict[str, Any] = {
    "mode": "off",
    "credentials": "passthrough",
    "providers": {},
    "proxy_other_paths": True,
    "max_body_kb": 4096,
    "unknown_client": {"action": "ALLOW", "principal": "unknown-client", "profile": None},
    "dns": {"listen": "0.0.0.0:53", "gateway_ip": "127.0.0.1", "upstream": ["1.1.1.1"], "doh_sinkhole": [],
            "log_queries": True},
    "tls": {"ca_cert": "data/ca/aicl-ca.pem", "ca_key": "data/ca/aicl-ca.key", "leaf_days": 30},
    "block_style": {
        "anthropic_messages": {"hard": "http_400", "soft": "assistant_text", "budget": "http_402"},
        "openai_responses": {"hard": "http_400", "soft": "assistant_text", "budget": "http_429"},
        "openai_chat": {"hard": "http_400", "soft": "refusal", "budget": "http_429"},
    },
}


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else copy.deepcopy(v)
    return out


def interception_cfg(raw: dict) -> dict:
    """The interception block of a raw policy with defaults filled in (no block = mode off)."""
    block = raw.get("interception")
    return _merge(DEFAULTS, block if isinstance(block, dict) else {})


def _str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) and x for x in v)


KEYS = {
    "interception": {"mode", "credentials", "providers", "proxy_other_paths", "max_body_kb", "unknown_client", "dns",
                     "tls", "block_style"},
    "provider": {"hosts", "protocol", "upstream", "inspect", "raw_paths"},
    "unknown_client": {"action", "principal", "profile"},
    "dns": {"listen", "gateway_ip", "upstream", "doh_sinkhole", "log_queries"},
    "tls": {"ca_cert", "ca_key", "leaf_days"},
    "client": {"match", "principal", "team", "profile", "models", "tools"},
}
PROFILES = ("strict", "balanced", "permissive")
_HEX = re.compile(r"^[0-9a-f]{1,8}$")


def _keys(d: dict, kind: str, where: str) -> None:
    """A misspelt key must fail the load: it would otherwise fall back to a weaker default silently."""
    bad = sorted(set(map(str, d)) - KEYS[kind])
    if bad:
        raise ValueError(f"{where}: unknown key(s) {', '.join(bad)}; allowed: {', '.join(sorted(KEYS[kind]))}")


def _profile(v: Any, where: str) -> None:
    if v is not None and v not in PROFILES:
        raise ValueError(f"{where}.profile must be {'|'.join(PROFILES)}")


def validate(raw: dict) -> None:
    """Shape checks for interception: and clients:. A typo must fail the load, never weaken interception."""
    block = raw.get("interception")
    if block is not None and not isinstance(block, dict):
        raise ValueError("interception must be a mapping")
    if isinstance(block, dict):
        _keys(block, "interception", "interception")
        for k, kind in (("unknown_client", "unknown_client"), ("dns", "dns"), ("tls", "tls")):
            if k in block and not isinstance(block[k], dict):
                raise ValueError(f"interception.{k} must be a mapping")
            if isinstance(block.get(k), dict):
                _keys(block[k], kind, f"interception.{k}")
        for k in ("providers", "block_style"):
            if k in block and not isinstance(block[k], dict):
                raise ValueError(f"interception.{k} must be a mapping")
    cfg = interception_cfg(raw)
    if cfg["mode"] not in MODES:
        raise ValueError(f"interception.mode must be {'|'.join(MODES)}")
    if cfg["credentials"] not in CREDENTIALS:
        raise ValueError(f"interception.credentials must be {'|'.join(CREDENTIALS)}")
    if not isinstance(cfg["proxy_other_paths"], bool):
        raise ValueError("interception.proxy_other_paths must be true or false")
    kb = cfg["max_body_kb"]
    if isinstance(kb, bool) or not isinstance(kb, int) or kb <= 0:
        raise ValueError("interception.max_body_kb must be a positive integer")
    provs = cfg["providers"]
    seen: dict[str, str] = {}
    for name, p in provs.items():
        where = f"interception.providers.{name}"
        if not isinstance(p, dict):
            raise ValueError(f"{where} must be a mapping")
        _keys(p, "provider", where)
        if not _str_list(p.get("hosts")) or not p["hosts"]:
            raise ValueError(f"{where}.hosts must be a non-empty list of host names")
        if p.get("protocol") not in PROTOCOLS:
            raise ValueError(f"{where}.protocol must be {'|'.join(PROTOCOLS)}")
        if not _str_list(p.get("inspect")) or not p["inspect"]:      # nothing inspected = everything unchecked
            raise ValueError(f"{where}.inspect must be a non-empty list of paths")
        for x in p["inspect"]:
            if not x.startswith("/") or canonical_path(x) != x.rstrip("/"):
                raise ValueError(f"{where}.inspect: {x!r} must be a plain absolute path")
        if "raw_paths" in p and not (isinstance(p["raw_paths"], list) and all(isinstance(x, str) and x.startswith("/")
                                                                          for x in p["raw_paths"])):
            raise ValueError(f"{where}.raw_paths must be a list of absolute path globs")
        if "upstream" in p and not (isinstance(p["upstream"], str) and p["upstream"].startswith(("http://", "https://"))):
            raise ValueError(f"{where}.upstream must be an http(s) URL")
        for h in p["hosts"]:
            h = h.lower().rstrip(".")
            if h in seen:
                raise ValueError(f"{where}: host {h} already belongs to provider {seen[h]}")
            seen[h] = str(name)
    uc = cfg["unknown_client"]
    if str(uc.get("action", "ALLOW")).upper() not in ("ALLOW", "LOG", "WARN", "BLOCK"):
        raise ValueError("interception.unknown_client.action must be ALLOW|LOG|WARN|BLOCK")
    _profile(uc.get("profile"), "interception.unknown_client")
    dns = cfg["dns"]
    try:
        ipaddress.ip_address(str(dns.get("gateway_ip")))
    except ValueError as e:
        raise ValueError(f"interception.dns.gateway_ip: {e}") from e
    if not _str_list(dns.get("upstream")) or not dns["upstream"]:
        raise ValueError("interception.dns.upstream must be a non-empty list of resolver addresses")
    if not isinstance(dns.get("doh_sinkhole"), list) or not all(isinstance(x, str) for x in dns["doh_sinkhole"]):
        raise ValueError("interception.dns.doh_sinkhole must be a list of host names")
    if not isinstance(dns.get("log_queries"), bool):
        raise ValueError("interception.dns.log_queries must be true or false")
    tls = cfg["tls"]
    if not all(isinstance(tls.get(k), str) for k in ("ca_cert", "ca_key")):
        raise ValueError("interception.tls needs ca_cert and ca_key paths")
    for proto, styles in cfg["block_style"].items():
        if proto not in PROTOCOLS or not isinstance(styles, dict):
            raise ValueError(f"interception.block_style.{proto}: unknown protocol or not a mapping")
        for kind, style in styles.items():
            if kind not in BLOCK_KINDS or style not in BLOCK_STYLES:
                raise ValueError(f"interception.block_style.{proto}.{kind}: {style!r} is not one of "
                                 f"{'|'.join(BLOCK_STYLES)}")
    clients = raw.get("clients", [])
    if clients is None:
        return
    if not isinstance(clients, list):
        raise ValueError("clients must be a list")
    for i, c in enumerate(clients):
        where = f"clients[{i}]"
        if not isinstance(c, dict) or not isinstance(c.get("principal"), str) or not c["principal"]:
            raise ValueError(f"{where} needs a principal")
        _keys(c, "client", where)
        _profile(c.get("profile"), where)
        m = c.get("match")
        if not isinstance(m, dict) or not m or any(k not in MATCH_KEYS for k in m):
            raise ValueError(f"{where}.match must use {'|'.join(MATCH_KEYS)}")
        if "cidr" in m:
            try:
                ipaddress.ip_network(str(m["cidr"]), strict=False)
            except ValueError as e:
                raise ValueError(f"{where}.match.cidr: {e}") from e
        if "any" in m and not isinstance(m["any"], bool):
            raise ValueError(f"{where}.match.any must be true or false")
        if "key_sha256_prefix" in m and not (isinstance(m["key_sha256_prefix"], str)
                                             and _HEX.match(m["key_sha256_prefix"].lower())):
            raise ValueError(f"{where}.match.key_sha256_prefix must be a quoted hex string of 1-8 characters")
        if "user_agent" in m and not (isinstance(m["user_agent"], str) and m["user_agent"]):
            raise ValueError(f"{where}.match.user_agent must be a non-empty glob")
        if "models" in c and c["models"] is not None and not _str_list(c["models"]):
            raise ValueError(f"{where}.models must be a list of model globs")
        if "tools" in c and c["tools"] is not None and not _str_list(c["tools"]):
            raise ValueError(f"{where}.tools must be a list of tool-name globs")


def normalize_host(host: str | None) -> str:
    """Host header / SNI -> bare lower-case name (port and trailing dot removed)."""
    h = (host or "").strip().lower()
    if h.startswith("["):                       # [v6]:port
        return h[1:h.find("]")] if "]" in h else h
    if h.count(":") == 1:
        h = h.split(":", 1)[0]
    return h.rstrip(".")


def provider_for_host(cfg: dict, host: str | None) -> tuple[str, dict] | None:
    """(provider name, provider entry) for an intercepted host, else None."""
    h = normalize_host(host)
    for name, p in (cfg.get("providers") or {}).items():
        if any(h == x.lower().rstrip(".") for x in p.get("hosts") or []):
            return str(name), p
    return None


def intercepted_hosts(cfg: dict) -> list[str]:
    return sorted({h.lower().rstrip(".") for p in (cfg.get("providers") or {}).values() for h in p.get("hosts") or []})


def canonical_path(path: str) -> str:
    """Path without query, percent-decoded, `;params` dropped, `//` collapsed, `.` / `..` resolved, no trailing /.
    The gateway refuses a request whose path is not already canonical (research/14 s.3), so `/v1//messages` or
    `/v1/%6Dessages` can never slip past inspection to a lenient upstream."""
    from urllib.parse import unquote
    p = unquote(path.split("?", 1)[0])
    out: list[str] = []
    for seg in p.split("/"):
        seg = seg.split(";", 1)[0]
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return "/" + "/".join(out)


def is_canonical(path: str) -> bool:
    """Plain lower-case path: no percent-encoding, no //, no dot segments, no ;params, no whitespace.
    Provider API paths are all lower-case, and a lenient upstream must never see a spelling we did not inspect."""
    raw = path.split("?", 1)[0]
    if raw != raw.lower() or any(c in raw for c in "%; \t\\"):
        return False
    return raw == canonical_path(raw) or raw == canonical_path(raw) + "/"


def path_matches(globs: list[str], path: str) -> bool:
    p = canonical_path(path)
    return any(fnmatch.fnmatchcase(p, g) for g in globs)


def is_inspected(provider: dict, path: str) -> bool:
    """True when the request path (query string ignored) is one the adapter parses and decides on."""
    p = canonical_path(path)
    return any(p == canonical_path(x) for x in provider.get("inspect") or [])


def client_for(raw: dict, client_ip: str | None, credential_hash: str | None,
               user_agent: str | None) -> dict:
    """First clients: entry whose every match key fits -> {principal, team, profile, models, matched};
    no match -> interception.unknown_client (matched False)."""
    for c in raw.get("clients") or []:
        m = c.get("match") or {}
        ok = True
        if "cidr" in m:
            try:
                ip = ipaddress.ip_address(client_ip) if client_ip else None
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:   # dual-stack listener
                    ip = ip.ipv4_mapped
                ok = ip is not None and ip in ipaddress.ip_network(str(m["cidr"]), strict=False)
            except ValueError:
                ok = False
        if ok and "key_sha256_prefix" in m:
            pre = str(m["key_sha256_prefix"]).lower()
            ok = bool(credential_hash) and bool(pre) and str(credential_hash).lower().startswith(pre)
        if ok and "user_agent" in m:
            ok = bool(user_agent) and fnmatch.fnmatchcase(user_agent.lower(), str(m["user_agent"]).lower())
        if ok and "any" in m:
            ok = m["any"] is True
        if ok:
            return {"principal": c["principal"], "team": c.get("team"), "profile": c.get("profile"),
                    "models": c.get("models"), "tools": c.get("tools"), "matched": True}
    uc = interception_cfg(raw)["unknown_client"]
    return {"principal": str(uc.get("principal") or "unknown-client"), "team": None, "profile": uc.get("profile"),
            "models": None, "tools": None, "matched": False, "action": str(uc.get("action", "ALLOW")).upper()}


def model_allowed(models: list[str] | None, model: str) -> bool:
    """None = no restriction; otherwise exact tag or glob."""
    return models is None or any(model == m or fnmatch.fnmatchcase(model, m) for m in models)

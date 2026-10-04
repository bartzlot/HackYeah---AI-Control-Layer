"""T-116 runtime mode: what this process really serves, not what the policy's interception.mode says.

The console header chip reads GET /console/api/status, built here from the live listeners:
  http   the plain listener (serve.py: its uvicorn.Server; uvicorn --factory: the one serving the request)
  tls    the transparent listener (AICL_TLS_PORT), live once uvicorn has bound it
  dns    the AICL resolver (AICL_DNS_LISTEN), live while its server threads run
  ca     the root CA certificate file under AICL_CA_ROOT
  upstream_overrides   AICL_UPSTREAM_<PROVIDER> (offline demo: the provider is the local mock)
Mode = off when interception.mode is off, transparent when the TLS listener runs, else base_url. Mode B (explicit
HTTPS_PROXY) has no CONNECT handler yet (BACKLOG, v4 parked), so this process never reports proxy.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from aicl_core.interception import interception_cfg, intercepted_hosts


class Runtime:
    """Filled by serve.build(); a bare create_app_from_env() (uvicorn --factory) leaves TLS and DNS off."""

    def __init__(self, env: dict):
        self.ca_root = Path(env.get("AICL_CA_ROOT") or ".")
        self.http = None          # uvicorn.Server of the plain listener (serve.py only)
        self.tls = None           # uvicorn.Server of the TLS listener
        self.dns = None           # dns.Dns


def _server(s: Any) -> dict:
    cfg = s.config
    # uvicorn never resets started after shutdown: a listener told to exit is off
    return {"on": bool(getattr(s, "started", False)) and not s.should_exit, "bind": cfg.host, "port": cfg.port}


def _alive(d: Any) -> bool:
    try:
        # Dns.stop() closes the socket synchronously; the server thread may still be winding down
        return d.udp.isAlive() and d.tcp.isAlive() and d.udp.server.socket.fileno() != -1
    except Exception:  # noqa: BLE001 - not started yet / already stopped
        return False


def _clean_url(u: str) -> str:
    """No credentials or query strings on the console (an override URL may carry user:pass@)."""
    p = urlsplit(u)
    host = p.hostname or ""
    if p.port:
        host += f":{p.port}"
    return urlunsplit((p.scheme, host, p.path, "", ""))


def status(rt: Runtime, raw: dict, served: tuple | None = None) -> dict:
    """-> {mode, policy_mode, passthrough, listeners, ca, upstream_overrides, warnings, notes}. `served` = the
    (host, port) of the listener that answered this console request (ASGI scope["server"])."""
    cfg = interception_cfg(raw or {})
    pmode = cfg["mode"]
    if rt.http is not None:
        http = _server(rt.http)
    else:
        http = {"on": True, "bind": served[0] if served else None, "port": served[1] if served else None}
    tls = _server(rt.tls) if rt.tls is not None else {"on": False, "bind": None, "port": None}
    if rt.dns is not None:
        h, p = rt.dns.udp.server.server_address[:2]
        dns = {"on": _alive(rt.dns), "bind": h, "port": p}
    else:
        dns = {"on": False, "bind": None, "port": None}
    ca_path = rt.ca_root / cfg["tls"]["ca_cert"]
    ca = {"present": ca_path.is_file(), "path": str(cfg["tls"]["ca_cert"])}
    # same source as passthrough.Passthrough.client(): the process environment
    overrides = {name: _clean_url(os.environ[f"AICL_UPSTREAM_{name.upper()}"])
                 for name in sorted(cfg.get("providers") or {}) if os.environ.get(f"AICL_UPSTREAM_{name.upper()}")}
    passthrough = pmode != "off"
    # interception.mode off disables every passthrough route (Passthrough.route), only the managed API stays
    mode = "off" if not passthrough else "transparent" if tls["on"] else "base_url"

    warnings: list[str] = []
    if pmode == "transparent" and not tls["on"]:
        warnings.append("policy says transparent but no TLS listener runs (AICL_TLS_PORT): only clients with a "
                        "base URL pointing at AICL are inspected")
    if pmode == "transparent" and not dns["on"]:
        warnings.append("policy says transparent but the AICL DNS resolver is not running (AICL_DNS_LISTEN): "
                        "clients reach the TLS listener only if another DNS or a hosts file points provider names at it")
    if pmode == "off" and (tls["on"] or dns["on"]):
        warnings.append("interception.mode is off: TLS / DNS listeners run but passthrough is disabled, provider "
                        "traffic is not inspected")
    if tls["on"] and not ca["present"]:
        warnings.append(f"TLS listener runs but the CA certificate {ca['path']} is missing")
    if dns["on"] and str(cfg["dns"]["gateway_ip"]).startswith("127."):
        warnings.append(f"DNS answers intercepted hosts with {cfg['dns']['gateway_ip']}: clients on other machines "
                        "are sent to themselves (set interception.dns.gateway_ip)")
    # an override is a deliberate setup (offline demo), so it is a note on the chip, not a warning
    notes = [f"{name} upstream is {url} (AICL_UPSTREAM_{name.upper()}), not the real provider"
             for name, url in overrides.items()]

    return {"mode": mode, "policy_mode": pmode, "passthrough": passthrough,
            "listeners": {"http": http, "tls": tls, "dns": dns},
            "intercepted_hosts": intercepted_hosts(cfg) if tls["on"] or dns["on"] else [],
            "ca": ca, "upstream_overrides": overrides, "warnings": warnings, "notes": notes}

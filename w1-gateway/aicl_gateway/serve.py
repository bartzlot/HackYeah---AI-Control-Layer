"""One AICL process, three listeners sharing ONE app (one budget ledger, one audit log, one policy engine):

  HTTP   AICL_HTTP_PORT  (default 18080)  managed gateway, console, base-URL passthrough (mode A)
  HTTPS  AICL_TLS_PORT   (default 0=off)  transparent passthrough (mode C): leaf from the AICL CA for every
                                          intercepted host, issued / refreshed at start (research/14 s.5)
  DNS    AICL_DNS_LISTEN (default off)    the AICL resolver, e.g. 0.0.0.0:53 (research/14 s.5)

    python -m aicl_gateway.serve
Bind address: AICL_BIND (default 127.0.0.1). Everything else as in main.py (.env.example).
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import uvicorn

from aicl_core.interception import interception_cfg, intercepted_hosts

from . import ca
from .dns import AiclResolver, BypassWatch, Dns
from .main import create_app_from_env

log = logging.getLogger("aicl.serve")


def refresh_leaf(ssl_ctx, raw: dict, root: Path, tls: dict | None = None) -> list[str]:
    """A policy change that alters the intercepted hosts reissues the leaf (new SAN) and loads it into the
    running listener: new handshakes get it at once, no restart (T-115). `tls` = the CA paths fixed at start."""
    cfg = interception_cfg(raw)
    hosts = intercepted_hosts(cfg)
    try:
        cert, key = ca.ensure(tls or cfg["tls"], hosts, [cfg["dns"]["gateway_ip"]], root=root)
        if ssl_ctx is not None:
            ssl_ctx.load_cert_chain(str(cert), str(key))
    except Exception:
        log.exception("TLS leaf refresh failed: TLS keeps the previous certificate (hosts %s)", hosts)
        raise
    return hosts


def build(env: dict | None = None):
    env = dict(os.environ) if env is None else dict(env)
    app = create_app_from_env(env)
    engine = app.state.engine
    policy = lambda: engine.policy.raw          # noqa: E731 - live policy for DNS and the leaf
    bind = env.get("AICL_BIND", "127.0.0.1")
    servers = [uvicorn.Server(uvicorn.Config(app, host=bind, port=int(env.get("AICL_HTTP_PORT", "18080")),
                                             log_level="info", lifespan="on"))]
    rt = app.state.runtime                       # console status: the listeners this process really runs (T-116)
    rt.http = servers[0]
    tls_port = int(env.get("AICL_TLS_PORT", "0") or 0)
    if tls_port:
        cfg = interception_cfg(engine.policy.raw)
        root = Path(env.get("AICL_CA_ROOT", "."))
        cert, key = ca.ensure(cfg["tls"], intercepted_hosts(cfg), [cfg["dns"]["gateway_ip"]], root=root)
        if env.get("AICL_CA_PUBLISH"):    # the root CERT only (never the key) for clients to trust
            ca.publish(root / cfg["tls"]["ca_cert"], Path(env["AICL_CA_PUBLISH"]))
        tls_cfg = uvicorn.Config(app, host=bind, port=tls_port, ssl_certfile=str(cert), ssl_keyfile=str(key),
                                 log_level="info", lifespan="off")
        tls_cfg.load()                                   # builds the SSLContext now, so a reload can swap its cert
        servers.append(uvicorn.Server(tls_cfg))
        rt.tls = servers[-1]
        fixed_tls = dict(cfg["tls"])                  # CA paths are fixed at start: a policy edit cannot move the CA
        engine.store.on_change.append(lambda pol: refresh_leaf(tls_cfg.ssl, pol.raw, root, fixed_tls))
        log.info("TLS :%d for %s", tls_port, ", ".join(intercepted_hosts(cfg)))
    dns = None
    if env.get("AICL_DNS_LISTEN"):
        watch = BypassWatch(float(env.get("AICL_NET01_WINDOW_S", "30")))
        dns = Dns(AiclResolver(policy, audit=app.state.audit, watch=watch), env["AICL_DNS_LISTEN"])
        app.state.dns = dns.resolver
        app.state.passthrough.watch = watch          # requests through the gateway clear the pending lookup
        rt.dns = dns
    return app, servers, dns


async def run(env: dict | None = None) -> None:
    app, servers, dns = build(env)
    if dns:
        dns.start()
        log.info("DNS on %s", (env or os.environ).get("AICL_DNS_LISTEN"))
    try:
        await asyncio.gather(*(s.serve() for s in servers))
    finally:
        if dns:
            dns.stop()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())


if __name__ == "__main__":
    main()

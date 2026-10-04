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
from .dns import AiclResolver, Dns
from .main import create_app_from_env

log = logging.getLogger("aicl.serve")


def build(env: dict | None = None):
    env = dict(os.environ) if env is None else dict(env)
    app = create_app_from_env(env)
    engine = app.state.engine
    policy = lambda: engine.policy.raw          # noqa: E731 - live policy for DNS and the leaf
    bind = env.get("AICL_BIND", "127.0.0.1")
    servers = [uvicorn.Server(uvicorn.Config(app, host=bind, port=int(env.get("AICL_HTTP_PORT", "18080")),
                                             log_level="info", lifespan="on"))]
    tls_port = int(env.get("AICL_TLS_PORT", "0") or 0)
    if tls_port:
        cfg = interception_cfg(engine.policy.raw)
        root = Path(env.get("AICL_CA_ROOT", "."))
        cert, key = ca.ensure(cfg["tls"], intercepted_hosts(cfg), [cfg["dns"]["gateway_ip"]], root=root)
        if env.get("AICL_CA_PUBLISH"):    # the root CERT only (never the key) for clients to trust
            ca.publish(root / cfg["tls"]["ca_cert"], Path(env["AICL_CA_PUBLISH"]))
        servers.append(uvicorn.Server(uvicorn.Config(app, host=bind, port=tls_port, ssl_certfile=str(cert),
                                                     ssl_keyfile=str(key), log_level="info", lifespan="off")))
        log.info("TLS :%d for %s", tls_port, ", ".join(intercepted_hosts(cfg)))
    dns = None
    if env.get("AICL_DNS_LISTEN"):
        dns = Dns(AiclResolver(policy, audit=app.state.audit), env["AICL_DNS_LISTEN"])
        app.state.dns = dns.resolver
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

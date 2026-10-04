"""AICL DNS resolver (research/14 s.5): the name server DHCP hands to clients, and NET-01 bypass detection.

  intercepted provider host (interception.providers.*.hosts)  -> A interception.dns.gateway_ip, AAAA empty
  interception.dns.doh_sinkhole names (DNS-over-HTTPS)         -> NXDOMAIN + BYPASS_SUSPECTED audit record
  everything else                                              -> forwarded to interception.dns.upstream

The policy is read on every query, so a live edit of the host list applies to the next lookup. Every
intercepted / sinkholed query is one audit record; other queries too when interception.dns.log_queries is true.
"""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Callable

from dnslib import QTYPE, RCODE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSLogger, DNSServer

from aicl_contracts import Action, AuditRecord, DestKind, Stage
from aicl_core import interception as icpt


def _split(hostport: str, default_port: int = 53) -> tuple[str, int]:
    if hostport.count(":") == 1:
        h, p = hostport.rsplit(":", 1)
        return h, int(p)
    return hostport, default_port


class BypassWatch:
    """NET-01 (research/14 s.1): a client that resolved an intercepted host but never sent a request through
    the gateway within `window_s` may be talking to a hard-coded provider address. The resolver notes lookups,
    the passthrough PEP notes requests (same client address + host), sweep() returns the stale lookups."""

    def __init__(self, window_s: float = 30.0, clock: Callable[[], float] = time.monotonic):
        self.window_s, self._clock = window_s, clock
        self._pending: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def note_lookup(self, client: str | None, host: str) -> None:
        if client:
            with self._lock:
                self._pending.setdefault((client, host), self._clock())

    def note_request(self, client: str | None, host: str | None) -> None:
        if client and host:
            with self._lock:
                self._pending.pop((client, host), None)

    def sweep(self) -> list[tuple[str, str, float]]:
        now = self._clock()
        with self._lock:
            stale = [(c, h, now - t) for (c, h), t in self._pending.items() if now - t >= self.window_s]
            for c, h, _ in stale:
                self._pending.pop((c, h), None)
        return stale


class AiclResolver(BaseResolver):
    def __init__(self, policy: Callable[[], dict | None], audit=None, ttl: int = 30, timeout: float = 3.0,
                 watch: BypassWatch | None = None):
        self.policy, self.audit, self.ttl, self.timeout = policy, audit, ttl, timeout
        self.watch = watch
        self.stats = {"queries": 0, "intercepted": 0, "sinkholed": 0, "forwarded": 0, "failed": 0}
        self._lock = threading.Lock()

    def _count(self, k: str) -> None:
        with self._lock:
            self.stats[k] += 1

    def resolve(self, request: DNSRecord, handler):
        raw = self.policy() or {}
        cfg = icpt.interception_cfg(raw)
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]
        client = handler.client_address[0] if handler is not None else None
        self._count("queries")
        reply = request.reply()
        hosts = set(icpt.intercepted_hosts(cfg)) if cfg["mode"] == "transparent" else set()
        sink = {h.lower().rstrip(".") for h in cfg["dns"].get("doh_sinkhole") or []}
        if qname in hosts:
            self._count("intercepted")
            if qtype in ("A", "ANY"):
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(cfg["dns"]["gateway_ip"]), ttl=self.ttl))
            # AAAA and others: NOERROR with no answer, so IPv6 cannot route around the gateway
            self._log(raw, client, qname, qtype, f"intercepted -> {cfg['dns']['gateway_ip']}", "DNS_QUERY", qname)
            if self.watch is not None and qtype in ("A", "ANY"):
                self.watch.note_lookup(client, qname)
            return reply
        if qname in sink or any(qname.endswith("." + s) for s in sink):
            self._count("sinkholed")
            reply.header.rcode = RCODE.NXDOMAIN
            self._log(raw, client, qname, qtype, "DNS-over-HTTPS resolver sinkholed (bypass attempt)",
                      "BYPASS_SUSPECTED", None, Action.WARN)
            return reply
        for up in cfg["dns"]["upstream"]:
            host, port = _split(up)
            try:
                ans = DNSRecord.parse(request.send(host, port, timeout=self.timeout))
                self._count("forwarded")
                if cfg["dns"].get("log_queries"):
                    self._log(raw, client, qname, qtype, f"forwarded to {up}", "DNS_QUERY", None)
                return ans
            except Exception:  # noqa: BLE001 - try the next upstream
                continue
        self._count("failed")
        reply.header.rcode = RCODE.SERVFAIL
        return reply

    def _log(self, raw: dict, client: str | None, qname: str, qtype: str, what: str, etype: str,
             upstream_host: str | None, action: Action = Action.ALLOW) -> None:
        if self.audit is None:
            return
        who = icpt.client_for(raw, client, None, None)
        try:
            self.audit.emit(AuditRecord(
                ts=datetime.now(timezone.utc).isoformat(), event_id=uuid.uuid4().hex[:16], event_type=etype,
                severity="medium" if action >= Action.WARN else "info", decision=action, stage=Stage.DNS,
                channel="dns", agent_id=who["principal"], destination=DestKind.EXTERNAL if upstream_host
                else DestKind.UNKNOWN, client_ip=client, upstream_host=upstream_host,
                explain=[f"dns {qtype} {qname}: {what}"]))
        except Exception:  # noqa: BLE001 - logging must never break name resolution
            pass


def report_stale(resolver: "AiclResolver") -> int:
    """Emit one BYPASS_SUSPECTED record per stale lookup (NET-01); returns how many."""
    if resolver.watch is None:
        return 0
    raw = resolver.policy() or {}
    n = 0
    for client, host, age in resolver.watch.sweep():
        resolver._log(raw, client, host, "A", f"resolved {host} but sent nothing through AICL for {age:.0f} s: "
                      "possible direct connection to a hard-coded provider address (NET-01)", "BYPASS_SUSPECTED",
                      host, Action.WARN)
        n += 1
    return n


class Dns:
    """UDP + TCP servers on interception.dns.listen (or an explicit address for tests)."""

    def __init__(self, resolver: AiclResolver, listen: str):
        host, port = _split(listen)
        quiet = DNSLogger(log="-request,-reply,-truncated,-error,-recv,-send,-data", prefix=False)
        self.udp = DNSServer(resolver, address=host, port=port, logger=quiet)
        self.tcp = DNSServer(resolver, address=host, port=port, tcp=True, logger=quiet)
        self.resolver = resolver

    def start(self, sweep_s: float = 5.0) -> "Dns":
        self.udp.start_thread()
        self.tcp.start_thread()
        if self.resolver.watch is not None:
            self._stop = threading.Event()

            def loop():
                while not self._stop.wait(sweep_s):
                    report_stale(self.resolver)
            threading.Thread(target=loop, name="net01-sweep", daemon=True).start()
        return self

    @property
    def port(self) -> int:
        return self.udp.server.server_address[1]

    def stop(self) -> None:
        if getattr(self, "_stop", None) is not None:
            self._stop.set()
        for s in (self.udp, self.tcp):
            try:
                s.stop()
                s.server.server_close()
            except Exception:  # noqa: BLE001
                pass


def wait_ready(port: int, host: str = "127.0.0.1", tries: int = 50) -> None:
    for _ in range(tries):
        try:
            DNSRecord.question("aicl.ready.invalid").send(host, port, timeout=0.2)
            return
        except Exception:  # noqa: BLE001
            time.sleep(0.05)

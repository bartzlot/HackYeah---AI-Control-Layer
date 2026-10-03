"""TOOL-01: tool firewall for tool calls (model proposals and MCP tools/call).

Per call, strongest wins (BLOCK > REQUIRE_APPROVAL (enforced as BLOCK) > ALLOW):
  1. agent allowlist: agents.<id>.tools (glob); a tool outside it is denied
  2. TOOL-01.rules: rules whose `tool` glob matches and whose `when` holds; if the tool has ALLOW rules
     (they describe its permitted shapes) but none holds, TOOL-01.default applies (default deny); a tool
     with only deny rules or no rules is decided by step 1
  3. argument rules: every policy rule of an exploit category (code_exec, unsafe_deserialization,
     model_supply_chain, tool_abuse) over the arguments rendered as `key=value` lines, at its
     untrusted action (curl | sh, rm -rf, pickle.loads, trust_remote_code=True, foreign model pull ...)
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from aicl_contracts import Action, Ctx, Event, Finding, Stage

from ..engine import register
from ..policy import to_action
from ..util import normalized_view

EXPLOIT_CATEGORIES = {"code_exec", "unsafe_deserialization", "model_supply_chain", "tool_abuse"}


def render_args(args: Any, prefix: str = "") -> list[str]:
    """Leaves as `key=value` lines (bools as True / False so `trust_remote_code=True` matches)."""
    if isinstance(args, dict):
        return [x for k, v in args.items() for x in render_args(v, f"{prefix}.{k}" if prefix else str(k))]
    if isinstance(args, (list, tuple)):
        return [x for v in args for x in render_args(v, prefix)]
    key = prefix.rsplit(".", 1)[-1]
    return [f"{key}={args}" if key else str(args)]


def arg_value(args: dict, path: str) -> Any:
    cur: Any = args
    for k in path.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


# ---------------------------------------------------------------- `when` predicates

_SQL_DENY = re.compile(r"(?i)\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|merge|replace|exec|execute|"
                       r"call|attach|copy|pg_read_file|lo_import|xp_cmdshell|load_file|into\s+outfile)\b")


def sql_select_only(q: Any) -> bool:
    if not isinstance(q, str):
        return False
    if "/*!" in q:
        return False
    body = re.sub(r"--[^\n]*|/\*.*?\*/", " ", q, flags=re.S)
    stmts = [s.strip() for s in body.split(";") if s.strip()]
    return len(stmts) == 1 and re.match(r"(?i)^(select|with)\b", stmts[0]) is not None and not _SQL_DENY.search(stmts[0])


def _domains(v: Any) -> list[str]:
    vals = v if isinstance(v, list) else [v]
    out = []
    for x in vals:
        if isinstance(x, str):
            out += [a.strip().rsplit("@", 1)[-1].lower().rstrip(">") for a in re.split(r"[,;]", x) if a.strip()]
    return out


def _in_domains(d: str, allowed: list[str]) -> bool:
    return any(d == a.lower() or d.endswith("." + a.lower()) for a in allowed)


_PRIVATE_NAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data", "host.docker.internal"}


def url_is_private(u: Any) -> bool:
    """Literal-address check, no DNS (offline): loopback, RFC 1918, link-local (cloud metadata), ULA, CGNAT,
    integer / hex encoded IPv4, IPv4-mapped IPv6, internal names. Unparseable URLs count as private (deny)."""
    if not isinstance(u, str):
        return True
    try:
        host = (urlsplit(u if "://" in u else "http://" + u).hostname or "").lower().rstrip(".")
    except ValueError:
        return True
    if not host:
        return True
    if host in _PRIVATE_NAMES or host.endswith((".internal", ".local", ".localhost")):
        return True
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            if re.fullmatch(r"0x[0-9a-f]+|\d+", host):
                ip = ipaddress.ip_address(int(host, 16 if host.startswith("0x") else 10))
        except ValueError:
            return True
    if ip is None:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    cgnat = isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10")
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified or cgnat


def when_holds(when: dict | None, args: dict) -> bool:
    for path, cond in (when or {}).items():
        v = arg_value(args, path[5:] if path.startswith("args.") else path)
        for op, want in (cond or {}).items():
            if op == "sql" and want == "select_only":
                ok = sql_select_only(v)
            elif op == "domain_in":
                ds = _domains(v)
                ok = bool(ds) and all(_in_domains(d, want) for d in ds)
            elif op == "domain_not_in":
                ds = _domains(v)
                ok = any(not _in_domains(d, want) for d in ds)
            elif op == "resolves_to_private":
                ok = url_is_private(v) == bool(want)
            elif op == "eq":
                ok = v == want
            elif op == "in":
                ok = v in (want or [])
            elif op == "regex":
                ok = isinstance(v, str) and re.search(str(want), v) is not None
            else:
                ok = False                       # unknown operator: never satisfied (rule does not apply)
            if not ok:
                return False
    return True


def _glob(name: str, pats: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in pats)


class ToolFirewall:
    control_id = "TOOL-01"
    stages = (Stage.TOOL_ARGS,)

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        pol, p = ctx.params["_policy"], ctx.params
        agent = pol.agent(event.agent_id) or {}
        allowed = list(agent.get("tools") or [])
        rules = list(p.get("rules") or [])
        default = to_action(p.get("default", "BLOCK"))
        exploit = [r for r in pol.rules if r.category in EXPLOIT_CATEGORIES]
        out: list[Finding] = []
        for n, tc in enumerate(event.tool_calls):
            name = tc.name if not tc.server or "." in tc.name else f"{tc.server}.{tc.name}"

            def add(rule_id: str, act_appr: tuple[Action, bool], why: str, category: str = "tool_abuse") -> None:
                act, appr = act_appr
                out.append(Finding(control_id=self.control_id, rule_id=rule_id, category=category, action=act,
                                   reason_code=f"{name}: {why}" + (" (REQUIRE_APPROVAL enforced as BLOCK)" if appr else ""),
                                   detail={"tool": name, "call": n, "approval": appr,
                                           "event_type": "TOOL_CALL_BLOCKED" if act == Action.BLOCK else "TOOL_CALL_ALLOWED"}))

            if not _glob(name, allowed):
                add("tool.not_allowed", (Action.BLOCK, False), f"not in agents.{event.agent_id}.tools")
            mine = [r for r in rules if _glob(name, [str(r.get("tool", ""))])]
            if mine:
                hits = [r for r in mine if when_holds(r.get("when"), tc.arguments)]
                if hits:
                    best = max(hits, key=lambda r: (to_action(r["action"])[0], to_action(r["action"])[1]))
                    act = to_action(best["action"])
                    if act[0] > Action.ALLOW:
                        add(str(best.get("id", "tool.rule")), act, str(best.get("reason", "policy rule")))
                elif default[0] > Action.ALLOW and any(to_action(r["action"])[0] == Action.ALLOW for r in mine):
                    add("tool.default", default, "no allow rule condition holds (default deny)")
            # same normalized view as INJ-03 (format chars, homoglyph-ish NFKC, whitespace runs), one line per leaf
            text = "\n".join(normalized_view(line)[0] for line in render_args(tc.arguments))
            for r in exploit:
                if r.pattern.search(text) and r.action_untrusted > Action.ALLOW:
                    add(r.id, (r.action_untrusted, False), f"argument matches {r.name or r.id}", r.category)
        return out


register(ToolFirewall())

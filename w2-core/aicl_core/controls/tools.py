"""TOOL-01: tool firewall for tool calls (model proposals and MCP tools/call).

Tool name: `<server>.<tool>` whenever the MCP server is known (a server can never borrow another
server's name); names and globs compare case-insensitively.
Per call, strongest wins (BLOCK > REQUIRE_APPROVAL (enforced as BLOCK) > ALLOW):
  1. agent allowlist: agents.<id>.tools (glob); a tool outside it is denied
  2. TOOL-01.rules: rules whose `tool` glob matches and whose `when` holds; if the tool has ALLOW rules
     (they describe its permitted shapes) but none holds, TOOL-01.default applies (default deny); a tool
     with only deny rules or no rules is decided by step 1
  3. argument rules: every policy rule of an exploit category (code_exec, unsafe_deserialization,
     model_supply_chain, tool_abuse) whose optional `tools` scope matches, over the arguments rendered
     as `key=value` lines, at its untrusted action (curl | sh, rm -rf, pickle.loads,
     trust_remote_code=True, foreign model pull ...)
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
import socket
import unicodedata
from typing import Any
from urllib.parse import urlsplit

from aicl_contracts import Action, Ctx, Event, Finding, Stage

from .. import interception
from ..engine import register
from ..policy import WHEN_OPS, to_action
from ..util import normalized_view

EXPLOIT_CATEGORIES = {"code_exec", "unsafe_deserialization", "model_supply_chain", "tool_abuse"}
_TRUTHY = {"1", "yes", "on", "true"}
_BOOL_KEYS = {"trust_remote_code", "allow_pickle"}

assert {"sql", "domain_in", "domain_not_in", "resolves_to_private", "eq", "in", "regex"} == set(WHEN_OPS)


def tool_name(name: str, server: str | None) -> str:
    if server and not name.casefold().startswith(server.casefold() + "."):
        return f"{server}.{name}"
    return name


def render_args(args: Any, prefix: str = "") -> list[str]:
    """Leaves as `key=value` lines. A list of scalars also renders joined (argv: rm -rf /); truthy values of
    boolean flags render as True (trust_remote_code: 1 -> trust_remote_code=True)."""
    key = prefix.rsplit(".", 1)[-1]
    if isinstance(args, dict):
        return [x for k, v in args.items() for x in render_args(v, f"{prefix}.{k}" if prefix else str(k))]
    if isinstance(args, (list, tuple)):
        out = [x for v in args for x in render_args(v, prefix)]
        scalars = [str(v) for v in args if not isinstance(v, (dict, list, tuple))]
        if len(scalars) > 1:
            out.append(f"{key}={' '.join(scalars)}" if key else " ".join(scalars))
        return out
    if key in _BOOL_KEYS and str(args).strip().lower() in _TRUTHY:
        args = True
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
                       r"call|attach|copy|into|outfile|dumpfile|pg_read_file|pg_write_file|pg_ls_dir|lo_import|"
                       r"lo_export|xp_cmdshell|load_file|dblink\w*|pg_sleep|sleep|benchmark)\b")
_SQL_LITERALS = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"")


def sql_select_only(q: Any) -> bool:
    """One SELECT / WITH statement, no writes, no dangerous functions. String literals are blanked first so
    a comment marker or `;` inside quotes cannot hide a stacked statement; an unbalanced quote is rejected."""
    if not isinstance(q, str) or "/*!" in q:
        return False
    body = _SQL_LITERALS.sub("''", q)
    if "'" in body.replace("''", "") or '"' in body:
        return False
    body = re.sub(r"--[^\n]*|/\*.*?\*/", " ", body, flags=re.S)
    if "/*" in body:
        return False
    stmts = [s.strip() for s in body.split(";") if s.strip()]
    return len(stmts) == 1 and re.match(r"(?i)^(select|with)\b", stmts[0]) is not None and not _SQL_DENY.search(stmts[0])


_ADDR = re.compile(r"[^\s@,;<>\"'()]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def _domains(v: Any) -> list[str]:
    vals = v if isinstance(v, list) else [v]
    return [m.group(1).lower() for x in vals if isinstance(x, str) for m in _ADDR.finditer(x)]


def _in_domains(d: str, allowed: list[str]) -> bool:
    return any(d == a.lower() or d.endswith("." + a.lower()) for a in allowed)


_PRIVATE_NAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data", "host.docker.internal"}
_REBIND_SUFFIXES = (".nip.io", ".sslip.io", ".xip.io", ".localtest.me", ".lvh.me")


def url_is_private(u: Any) -> bool:
    """Literal-address check, no DNS (offline, so this does not RESOLVE names): loopback, RFC 1918, link-local
    (cloud metadata), ULA, CGNAT, integer / hex / octal / short IPv4 forms (inet_aton), fullwidth digits,
    IPv4-mapped IPv6, internal names, wildcard-DNS rebinding services. Unparseable URLs and a backslash in the
    authority count as private (deny)."""
    if not isinstance(u, str):
        return True
    u = unicodedata.normalize("NFKC", u).strip()
    authority = re.sub(r"^[a-zA-Z][\w+.-]*://", "", u).split("/", 1)[0]
    if "\\" in authority:
        return True
    try:
        host = (urlsplit(u if "://" in u else "http://" + u).hostname or "").lower().rstrip(".")
    except ValueError:
        return True
    if not host:
        return True
    if host in _PRIVATE_NAMES or host.endswith((".internal", ".local", ".localhost") + _REBIND_SUFFIXES):
        return True
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host):   # 0177.0.0.1, 127.1, 0x7f.1
            try:
                ip = ipaddress.ip_address(socket.inet_aton(host))
            except OSError:
                return True
    if ip is None:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    cgnat = isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10")
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified or cgnat


def when_holds(when: dict | None, args: dict) -> bool:
    for path, cond in (when or {}).items():
        p = path[5:] if path.startswith("args.") else path
        v = arg_value(args, p)
        for op, want in (cond or {}).items():
            if op == "sql" and want == "select_only":
                ok = sql_select_only(v)
            elif op in ("domain_in", "domain_not_in"):
                # recipients: the named field plus its cc / bcc / reply_to siblings
                parent = p.rsplit(".", 1)[0] if "." in p else ""
                sib = arg_value(args, parent) if parent else args
                vals = [v] + ([sib.get(k) for k in ("cc", "bcc", "reply_to")] if isinstance(sib, dict) else [])
                ds = [d for x in vals for d in _domains(x)]
                if op == "domain_in":
                    ok = bool(ds) and all(_in_domains(d, want) for d in ds)
                else:
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
                ok = False                       # unreachable: operators are validated at policy load
            if not ok:
                return False
    return True


def _glob(name: str, pats: list[str]) -> bool:
    n = name.casefold()
    return any(fnmatch.fnmatchcase(n, str(p).casefold()) for p in pats)


class ToolFirewall:
    control_id = "TOOL-01"
    stages = (Stage.TOOL_ARGS,)

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        pol, p = ctx.params["_policy"], ctx.params
        if event.upstream_host:     # v4 passthrough client: clients[].tools (globs), none listed = every tool
            who = interception.client_for(pol.raw, event.client_ip, event.credential_hash, event.user_agent)
            allowed, where = list(who.get("tools") or ["*"]), f"clients[{event.agent_id}].tools"
        else:
            agent = pol.agent(event.agent_id) or {}
            allowed, where = list(agent.get("tools") or []), f"agents.{event.agent_id}.tools"
        rules = list(p.get("rules") or [])
        default = to_action(p.get("default", "BLOCK"))
        exploit = [r for r in pol.rules if r.category in EXPLOIT_CATEGORIES]
        out: list[Finding] = []
        for n, tc in enumerate(event.tool_calls):
            name = tool_name(tc.name, tc.server)

            def add(rule_id: str, act_appr: tuple[Action, bool], why: str, category: str = "tool_abuse") -> None:
                act, appr = act_appr
                out.append(Finding(control_id=self.control_id, rule_id=rule_id, category=category, action=act,
                                   reason_code=f"{name}: {why}" + (" (REQUIRE_APPROVAL enforced as BLOCK)" if appr else ""),
                                   detail={"tool": name, "call": n, "approval": appr,
                                           "event_type": "TOOL_CALL_BLOCKED" if act == Action.BLOCK else "TOOL_CALL_ALLOWED"}))

            if not _glob(name, allowed):
                add("tool.not_allowed", (Action.BLOCK, False), f"not in {where}")
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
            # same normalized view as INJ-03 (format chars, NFKC, whitespace runs), one line per leaf
            text = "\n".join(normalized_view(line)[0] for line in render_args(tc.arguments))
            for r in exploit:
                if r.tools and not _glob(name, r.tools):
                    continue
                if r.pattern.search(text) and r.action_untrusted > Action.ALLOW:
                    add(r.id, (r.action_untrusted, False), f"argument matches {r.name or r.id}", r.category)
        return out


register(ToolFirewall())

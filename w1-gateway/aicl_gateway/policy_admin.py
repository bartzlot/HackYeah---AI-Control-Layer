"""T-107: live policy and budget editing from the console (the judges' "change the config and watch it apply").

write_policy(text): the candidate is validated by the real loader NEXT TO the live file (same local.d/ and
rules/), then atomically replaces it and the engine reloads at once; an invalid edit returns the loader's
error and the live file is untouched. patch_budgets(body): a ruamel round-trip edit of budgets.agents /
budgets.org, so comments and layout of policy.yaml are kept, then the same write path.
seed_policy(env): AICL_POLICY_SEED copies a seed policy directory to the writable AICL_POLICY location on the
first start (Cloud Run, read-only images).
"""
from __future__ import annotations

import io
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from aicl_core.policy import PolicyError, load_policy

PERIODS = ("minute", "hour", "day", "month")
MAX_POLICY_BYTES = 512 * 1024


class PolicyWriteError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def write_policy(path: Path, text: str, engine) -> dict[str, Any]:
    if not isinstance(text, str) or not text.strip():
        raise PolicyWriteError(422, "empty policy")
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyWriteError(413, f"policy over {MAX_POLICY_BYTES // 1024} KB")
    cand = path.with_name(f".policy.candidate.{uuid.uuid4().hex[:8]}.yaml")
    try:
        cand.write_text(text, encoding="utf-8")
    except OSError as e:
        raise PolicyWriteError(409, f"policy directory is read-only ({type(e).__name__}); set AICL_POLICY to a "
                                    "writable path, e.g. with AICL_POLICY_SEED") from e
    try:
        load_policy(cand)                       # same loader, same local.d/ and rules/ as the live file
    except PolicyError as e:
        cand.unlink(missing_ok=True)
        raise PolicyWriteError(422, str(e).replace(str(cand), path.name)) from e
    except Exception as e:  # noqa: BLE001
        cand.unlink(missing_ok=True)
        raise PolicyWriteError(422, f"{type(e).__name__}: {e}") from e
    os.replace(cand, path)                      # atomic on the same filesystem
    engine.store.refresh(force=True)
    return {"ok": True, "version": engine.policy.version, "error": engine.store.error}


def _num(v: Any, where: str, integer: bool) -> int | float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
        raise PolicyWriteError(422, f"{where} must be a non-negative number")
    return int(v) if integer else float(v)


# ---- line-surgical YAML edits: only the touched line changes (comments and column alignment kept) ----------

_KEY = re.compile(r"^(?P<ind> *)(?P<q>[\"']?)(?P<key>[^\"':#]+)(?P=q):(?P<rest>.*)$")


def _split_comment(rest: str) -> tuple[str, str]:
    """' {a: 1}   # note' -> (' {a: 1}', '   # note'); a # inside quotes or braces is not a comment."""
    depth, quote = 0, None
    for i, ch in enumerate(rest):
        if quote:
            quote = None if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        elif ch == "#" and depth == 0 and (i == 0 or rest[i - 1] in " \t"):
            j = i
            while j > 0 and rest[j - 1] in " \t":
                j -= 1
            return rest[:j], rest[j:]
    return rest, ""


def _find(lines: list[str], path: list[str]) -> tuple[int, int, int]:
    """(line index of the last key in path, its indent, end index of its block) or -1 when missing."""
    lo, hi, indent = 0, len(lines), -1
    idx = -1
    for key in path:
        idx = -1
        for i in range(lo, hi):
            m = _KEY.match(lines[i])
            if m and len(m["ind"]) > indent and m["key"].strip() == key:
                if indent >= 0 and len(m["ind"]) != child_indent(lines, lo, hi, indent):
                    continue
                idx, ind = i, len(m["ind"])
                break
        if idx < 0:
            return -1, -1, -1
        lo, indent = idx + 1, ind
        hi = _block_end(lines, idx, ind)
    return idx, indent, hi


def child_indent(lines: list[str], lo: int, hi: int, parent: int) -> int:
    for i in range(lo, hi):
        t = lines[i]
        if t.strip() and not t.lstrip().startswith("#"):
            n = len(t) - len(t.lstrip(" "))
            if n > parent:
                return n
    return -1


def _block_end(lines: list[str], idx: int, indent: int) -> int:
    for j in range(idx + 1, len(lines)):
        t = lines[j]
        if t.strip() and not t.lstrip().startswith("#") and len(t) - len(t.lstrip(" ")) <= indent:
            return j
    return len(lines)


def _scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return repr(round(v, 6))
    return str(v)


def _flow(d: dict) -> str:
    return "{" + ", ".join(f"{k}: {_scalar(v)}" for k, v in d.items()) + "}"


def _load_flow(text: str) -> Any:
    y = YAML(typ="safe")
    return y.load(text) if text.strip() else None


def _set_value(lines: list[str], i: int, value: str) -> None:
    m = _KEY.match(lines[i])
    body, comment = _split_comment(m["rest"])
    lead = body[: len(body) - len(body.lstrip(" "))] or " "
    q = m["q"]
    lines[i] = f"{m['ind']}{q}{m['key']}{q}:{lead}{value}{comment}"


def patch_budgets(path: Path, body: dict, engine) -> dict[str, Any]:
    """body: {"agents": {id: {tokens?, usd?, period?} | null}, "org": {tokens?, usd?, period?}}; null removes.
    Each budget is one flow-style line in policy.yaml; only the touched lines change."""
    if not isinstance(body, dict):
        raise PolicyWriteError(422, "body must be a JSON object")

    def clean(lim: dict, where: str) -> dict:
        out = {}
        for k, v in lim.items():
            if k == "tokens":
                out[k] = _num(v, f"{where}.tokens", True)
            elif k == "usd":
                out[k] = _num(v, f"{where}.usd", False)
            elif k == "period":
                if v not in PERIODS:
                    raise PolicyWriteError(422, f"{where}.period must be {'|'.join(PERIODS)}")
                out[k] = v
            else:
                raise PolicyWriteError(422, f"{where}: unknown key {k!r}")
        return out

    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    a_idx, a_ind, a_end = _find(lines, ["budgets", "agents"])
    if a_idx < 0:
        raise PolicyWriteError(422, "policy.yaml has no budgets.agents section")
    for aid, lim in (body.get("agents") or {}).items():
        if not isinstance(aid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", aid):
            raise PolicyWriteError(422, "agent ids must be short [A-Za-z0-9_.-] strings")
        i, ind, end = _find(lines, ["budgets", "agents", aid])
        if lim is None:
            if i >= 0:
                del lines[i:end]
            continue
        if not isinstance(lim, dict):
            raise PolicyWriteError(422, f"budgets.agents.{aid} must be an object")
        upd = clean(lim, f"budgets.agents.{aid}")
        if i >= 0:
            cur = _load_flow(_split_comment(_KEY.match(lines[i])["rest"])[0]) or {}
            if not isinstance(cur, dict):
                raise PolicyWriteError(422, f"budgets.agents.{aid} is not a one-line mapping; edit policy.yaml")
            _set_value(lines, i, _flow({**cur, **upd}))
        else:
            a_idx, a_ind, a_end = _find(lines, ["budgets", "agents"])
            child = child_indent(lines, a_idx + 1, a_end, a_ind)
            pad = " " * (child if child > 0 else a_ind + 2)
            ins = a_end
            while ins - 1 > a_idx and not lines[ins - 1].strip():
                ins -= 1
            lines.insert(ins, f"{pad}{aid}: {_flow(upd)}")
    if body.get("org") is not None:
        if not isinstance(body["org"], dict):
            raise PolicyWriteError(422, "budgets.org must be an object")
        i, _, _ = _find(lines, ["budgets", "org"])
        upd = clean(body["org"], "budgets.org")
        cur = (_load_flow(_split_comment(_KEY.match(lines[i])["rest"])[0]) or {}) if i >= 0 else None
        if i < 0 or not isinstance(cur, dict):
            raise PolicyWriteError(422, "budgets.org must be a one-line mapping in policy.yaml")
        _set_value(lines, i, _flow({**cur, **upd}))
    return write_policy(path, "\n".join(lines), engine)


MODES = ("enforce", "shadow", "off")
PROFILES = ("strict", "balanced", "permissive")
LOCKED = ("KILL-01", "ACCESS-01")       # the emergency stop and identity cannot be switched off from the UI


def set_control_mode(path: Path, cid: str, body: dict, engine) -> dict[str, Any]:
    """body: {"mode": enforce|shadow|off, "profile": optional strict|balanced|permissive}. Changes ONLY the line
    that holds controls.<cid>.mode (per-profile map when a profile is given or already used)."""
    if not isinstance(body, dict) or body.get("mode") not in MODES:
        raise PolicyWriteError(422, f"mode must be {'|'.join(MODES)}")
    mode, profile = body["mode"], body.get("profile")
    if profile is not None and profile not in PROFILES:
        raise PolicyWriteError(422, f"profile must be {'|'.join(PROFILES)}")
    if cid in LOCKED and mode == "off":
        raise PolicyWriteError(422, f"{cid} cannot be switched off from the console (edit policy.yaml to do it)")
    lines = path.read_text(encoding="utf-8").split("\n")
    i, ind, end = _find(lines, ["controls", cid])
    if i < 0:
        raise PolicyWriteError(404, f"control {cid} is not in policy.yaml")

    def merged(old: Any) -> Any:
        if profile is None and not isinstance(old, dict):
            return mode
        cur = dict(old) if isinstance(old, dict) else {p: old for p in PROFILES}
        for p in ([profile] if profile else PROFILES):
            cur[p] = mode
        return cur

    def render(v: Any) -> str:
        return _flow(v) if isinstance(v, dict) else str(v)

    inline_body, _ = _split_comment(_KEY.match(lines[i])["rest"])
    if inline_body.strip().startswith("{"):                     # KILL-01: {mode: enforce}
        cur = _load_flow(inline_body) or {}
        old = cur.get("mode", "enforce")
        new = merged(old)
        _set_value(lines, i, _flow({**cur, "mode": new}) if not isinstance(new, dict)
                   else "{" + ", ".join(f"{k}: {render(new) if k == 'mode' else _scalar(v)}"
                                        for k, v in {**cur, "mode": new}.items()) + "}")
    else:
        mi = next((j for j in range(i + 1, end) if (m := _KEY.match(lines[j])) and m["key"].strip() == "mode"
                   and len(m["ind"]) > ind), -1)
        if mi >= 0:
            old = _load_flow(_split_comment(_KEY.match(lines[mi])["rest"])[0])
            new = merged(old if old is not None else "enforce")
            _set_value(lines, mi, render(new))
        else:
            old = "enforce"
            new = merged(old)
            child = child_indent(lines, i + 1, end, ind)
            lines.insert(i + 1, " " * (child if child > 0 else ind + 2) + f"mode: {render(new)}")
    res = write_policy(path, "\n".join(lines), engine)
    res.update(control=cid, old=old, new=new)
    return res


DEFAULT_INSPECT = {"anthropic_messages": ["/v1/messages"], "openai_responses": ["/v1/responses", "/v1/chat/completions"],
                   "openai_chat": ["/v1/chat/completions"]}
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _yaml_str(v: str) -> str:
    return v if re.fullmatch(r"[A-Za-z0-9_.-]+", v) else '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _render_provider(p: dict) -> str:
    parts = []
    for k, v in p.items():
        if isinstance(v, list):
            parts.append(f"{k}: [" + ", ".join(_yaml_str(str(x)) for x in v) + "]")
        else:
            parts.append(f"{k}: {_yaml_str(str(v))}")
    return "{" + ", ".join(parts) + "}"


def interception_providers(raw: dict) -> list[dict]:
    from aicl_core.interception import interception_cfg
    cfg = interception_cfg(raw)
    return [{"name": n, **p} for n, p in (cfg.get("providers") or {}).items()]


def edit_interception(path: Path, body: dict, engine) -> dict[str, Any]:
    """body (one of): {"add_host": {"provider", "host"}} | {"remove_host": {"provider", "host"}} |
    {"add_provider": {"name", "host", "protocol", "upstream"?, "inspect"?}}. The providers block of policy.yaml
    is rewritten one provider per line (the rest of the file is untouched); interception.validate runs on the
    candidate through the loader; DNS answers and the TLS leaf follow the reload."""
    from aicl_core.interception import interception_cfg, intercepted_hosts
    if not isinstance(body, dict) or len(body) != 1:
        raise PolicyWriteError(422, "send exactly one of add_host, remove_host, add_provider")
    op, arg = next(iter(body.items()))
    if not isinstance(arg, dict):
        raise PolicyWriteError(422, f"{op} needs an object")
    raw = engine.policy.raw
    cfg = interception_cfg(raw)
    providers = {n: dict(p) for n, p in (raw.get("interception") or {}).get("providers", {}).items()}
    sink = {h.lower().rstrip(".") for h in cfg["dns"].get("doh_sinkhole") or []}

    def check_host(h: Any) -> str:
        h = str(h or "").strip().lower().rstrip(".")
        if "*" in h:
            raise PolicyWriteError(422, "wildcards are not allowed: list each API host")
        if not _HOST.match(h):
            raise PolicyWriteError(422, f"{h!r} is not a valid host name")
        if h in sink:
            raise PolicyWriteError(422, f"{h} is a DNS-over-HTTPS resolver (dns.doh_sinkhole): it is never intercepted")
        if h in intercepted_hosts(cfg) and op != "remove_host":
            raise PolicyWriteError(422, f"{h} is already intercepted")
        return h

    if op == "add_host":
        name = arg.get("provider")
        if name not in providers:
            raise PolicyWriteError(404, f"provider {name!r} does not exist")
        providers[name]["hosts"] = list(providers[name].get("hosts") or []) + [check_host(arg.get("host"))]
        what = f"interception: + host {providers[name]['hosts'][-1]} on {name}"
    elif op == "remove_host":
        name, h = arg.get("provider"), str(arg.get("host") or "").lower().rstrip(".")
        if name not in providers or h not in (providers[name].get("hosts") or []):
            raise PolicyWriteError(404, f"{h!r} is not a host of {name!r}")
        if len(providers[name]["hosts"]) == 1:
            raise PolicyWriteError(422, f"{name} would have no host left; a provider needs at least one")
        providers[name]["hosts"] = [x for x in providers[name]["hosts"] if x != h]
        what = f"interception: - host {h} from {name}"
    elif op == "add_provider":
        name = str(arg.get("name") or "")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{1,31}", name) or name in providers:
            raise PolicyWriteError(422, "provider name must be new, lower-case, 2-32 of [a-z0-9_-]")
        proto = arg.get("protocol")
        if proto not in DEFAULT_INSPECT:
            raise PolicyWriteError(422, f"protocol must be {'|'.join(DEFAULT_INSPECT)}")
        host = check_host(arg.get("host"))
        up = str(arg.get("upstream") or f"https://{host}")
        if not up.startswith("https://"):
            raise PolicyWriteError(422, "upstream must be an https URL")
        providers[name] = {"hosts": [host], "protocol": proto, "upstream": up,
                           "inspect": list(arg.get("inspect") or DEFAULT_INSPECT[proto])}
        what = f"interception: + provider {name} ({proto}, {host})"
    else:
        raise PolicyWriteError(422, f"unknown operation {op!r}")

    lines = path.read_text(encoding="utf-8").split("\n")
    i, ind, end = _find(lines, ["interception", "providers"])
    if i < 0:
        raise PolicyWriteError(422, "policy.yaml has no interception.providers section")
    child = child_indent(lines, i + 1, end, ind)
    pad = " " * (child if child > 0 else ind + 2)
    w = max(len(n) for n in providers) + 1
    block = [f"{pad}{(n + ':').ljust(w)} {_render_provider(p)}" for n, p in providers.items()]
    j = end
    while j - 1 > i and not lines[j - 1].strip():
        j -= 1
    lines[i + 1:j] = block
    res = write_policy(path, "\n".join(lines), engine)
    res["what"] = what
    res["hosts"] = intercepted_hosts(interception_cfg(engine.policy.raw))
    return res


def seed_policy(env: dict) -> None:
    """AICL_POLICY_SEED=<dir with policy.yaml>: copy it to the AICL_POLICY directory once (never overwrite)."""
    seed, target = env.get("AICL_POLICY_SEED"), env.get("AICL_POLICY")
    if not seed or not target:
        return
    dst = Path(target)
    if dst.exists():
        return
    src = Path(seed)
    if not (src / "policy.yaml").is_file():
        raise FileNotFoundError(f"AICL_POLICY_SEED {seed} has no policy.yaml")
    shutil.copytree(src, dst.parent, dirs_exist_ok=True)
    if dst.name != "policy.yaml" and not dst.exists():
        shutil.copy2(src / "policy.yaml", dst)

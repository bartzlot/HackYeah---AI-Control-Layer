"""Policy loader: YAML 1.2 (ruamel, so `off` stays a string), pydantic validation, local.d overlays,
canonical version hash, polling reload with last-good on invalid edits."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator
from ruamel.yaml import YAML

from aicl_contracts import Action

from . import interception

PROFILES = ("strict", "balanced", "permissive")
MODES = ("enforce", "shadow", "off")
FAILS = ("closed", "open", "degrade")
WHEN_OPS = ("sql", "domain_in", "domain_not_in", "resolves_to_private", "eq", "in", "regex")
_ACTION_WORDS = {a.name for a in Action} | {"REQUIRE_APPROVAL"}


class PolicyError(ValueError):
    pass


def to_action(word: "str | Action") -> tuple[Action, bool]:
    """Policy action word -> (lattice action, approval flag). The MVP has no approval queue:
    REQUIRE_APPROVAL is enforced as BLOCK and flagged so the explain trace says so."""
    if isinstance(word, Action):
        return word, False
    w = str(word).strip().upper()
    if w == "REQUIRE_APPROVAL":
        return Action.BLOCK, True
    return Action.parse(w), False


def _yaml_load(text: str) -> Any:
    return YAML(typ="safe").load(text)


def _plain(x: Any) -> Any:
    if isinstance(x, dict):
        return {str(k): _plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_plain(v) for v in x]
    return x


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if v is None:
            out.pop(k, None)
        elif isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _str_list(v: Any) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _check_action(v: Any, where: str) -> None:
    if not isinstance(v, str) or v.upper() not in _ACTION_WORDS:
        raise ValueError(f"{where}: bad action {v!r}")


class PolicyDoc(BaseModel):
    """Structural validation; unknown keys are tolerated (the file is a living document)."""
    model_config = ConfigDict(extra="allow")
    version: str
    defaults: dict[str, Any]
    profiles: dict[str, dict[str, Any]]
    agents: dict[str, dict[str, Any]] = {}
    destination_matrix: dict[str, dict[str, Any]] = {}
    destinations: dict[str, Any] = {}
    classification: dict[str, str] = {}
    controls: dict[str, dict[str, Any]] = {}
    emergency: dict[str, Any] = {}

    @field_validator("version")
    @classmethod
    def _v(cls, v: str) -> str:
        if not v.startswith("aicl-policy/"):
            raise ValueError("version must be aicl-policy/<n>")
        return v

    @model_validator(mode="after")
    def _semantic(self) -> "PolicyDoc":
        for p in PROFILES:
            if p not in self.profiles:
                raise ValueError(f"profiles.{p} missing")
        dp = self.defaults.get("profile", "balanced")
        if dp not in self.profiles:
            raise ValueError(f"defaults.profile {dp!r} unknown")
        if self.defaults.get("mode", "enforce") not in MODES:
            raise ValueError("defaults.mode must be enforce|shadow|off")
        if self.defaults.get("fail", "closed") not in FAILS:
            raise ValueError("defaults.fail must be closed|open|degrade")
        em = self.emergency
        if not isinstance(em, dict) or not isinstance(em.get("kill_switch", False), bool):
            raise ValueError("emergency.kill_switch must be true or false")
        for k in ("killed_agents", "killed_sessions"):
            if not _str_list(em.get(k, [])):
                raise ValueError(f"emergency.{k} must be a list of strings")
        for aid, a in self.agents.items():
            if not isinstance(a, dict):
                raise ValueError(f"agents.{aid} must be a mapping")
            if a.get("profile", dp) not in self.profiles:
                raise ValueError(f"agents.{aid}.profile unknown")
            for k in ("models", "tools"):
                if k in a and a[k] is not None and not _str_list(a[k]):
                    raise ValueError(f"agents.{aid}.{k} must be a list of strings")
        for tag, e in ((self.destinations.get("models") or {}) if isinstance(self.destinations, dict) else {}).items():
            if not isinstance(e, dict) or str(e.get("class", "unknown")) not in ("local", "external", "unknown"):
                raise ValueError(f"destinations.models.{tag} needs class local|external|unknown")
        for lvl, row in self.destination_matrix.items():
            for dest, cell in row.items():
                for c in (cell.values() if isinstance(cell, dict) else [cell]):
                    _check_action(c, f"destination_matrix.{lvl}.{dest}")
        for pname, p in self.profiles.items():
            inj = p.get("injection") or {}
            lo, hi = inj.get("judge_low", 0.0), inj.get("block", 1.0)
            if not (isinstance(lo, (int, float)) and isinstance(hi, (int, float)) and 0 <= lo <= hi <= 1):
                raise ValueError(f"profiles.{pname}.injection: need 0 <= judge_low <= block <= 1")
            for k, v in (p.get("pii") or {}).items():
                _check_action(v, f"profiles.{pname}.pii.{k}")
            if "secrets" in p:
                _check_action(p["secrets"], f"profiles.{pname}.secrets")
        for cid, c in self.controls.items():
            if not isinstance(c, dict):
                raise ValueError(f"controls.{cid} must be a mapping")
            m = c.get("mode", "enforce")
            for mv in (m.values() if isinstance(m, dict) else [m]):
                if mv not in MODES:
                    raise ValueError(f"controls.{cid}.mode {mv!r} must be enforce|shadow|off")
            if c.get("fail", "closed") not in FAILS:
                raise ValueError(f"controls.{cid}.fail must be closed|open|degrade")
            act = c.get("action")
            if isinstance(act, dict):
                for k, v in act.items():
                    _check_action(v, f"controls.{cid}.action.{k}")
            elif act is not None:
                _check_action(act, f"controls.{cid}.action")
            if "default" in c:
                _check_action(c["default"], f"controls.{cid}.default")
            for i, r in enumerate(c.get("rules") or []):
                if not isinstance(r, dict) or "action" not in r:
                    raise ValueError(f"controls.{cid}.rules[{i}] needs an action")
                _check_action(r["action"], f"controls.{cid}.rules[{i}].action")
                when = r.get("when") or {}
                if not isinstance(when, dict):
                    raise ValueError(f"controls.{cid}.rules[{i}].when must be a mapping")
                for path, cond in when.items():
                    if not isinstance(cond, dict) or not cond:
                        raise ValueError(f"controls.{cid}.rules[{i}].when.{path} must map operator -> value")
                    for op in cond:
                        if op not in WHEN_OPS:   # a typo must not silently disable a deny rule
                            raise ValueError(f"controls.{cid}.rules[{i}].when.{path}: unknown operator {op!r}, "
                                             f"use one of {', '.join(WHEN_OPS)}")
        interception.validate(self.model_dump())   # v4 interception: + clients: (research/14 s.4)
        return self


@dataclass
class Rule:
    id: str
    category: str
    pattern: "re.Pattern[str]"
    action_user: Action
    action_untrusted: Action
    severity: str = "medium"
    name: str = ""
    source: str = "policy"
    match: list[str] = field(default_factory=list)
    no_match: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)      # TOOL-01 scope (tool-name globs); empty = every tool
    scope: str = "all"                                  # all | tool_args (TOOL-01 only, never INJ-03 text)


def _scope(v: Any) -> str:
    if v not in ("all", "tool_args"):
        raise ValueError(f"scope must be all|tool_args, not {v!r}")
    return v


def load_rule_file(path: Path, source: str = "policy") -> list[Rule]:
    doc = _plain(_yaml_load(path.read_text(encoding="utf-8")) or {})
    if not str(doc.get("version", "")).startswith("aicl-rules/"):
        raise PolicyError(f"{path}: version must be aicl-rules/<n>")
    out = []
    for r in doc.get("rules", []):
        try:
            out.append(Rule(
                id=r["id"], category=r.get("category", "injection"),
                pattern=re.compile(r["pattern"], re.IGNORECASE),
                action_user=to_action(r.get("action_user", "WARN"))[0],
                action_untrusted=to_action(r.get("action_untrusted", "BLOCK"))[0],
                severity=r.get("severity", "medium"), name=r.get("name", ""), source=source,
                match=list(r.get("match", [])), no_match=list(r.get("no_match", [])),
                tools=[str(t) for t in (r.get("tools") or [])], scope=_scope(r.get("scope", "all"))))
        except (KeyError, re.error, ValueError, TypeError) as e:
            raise PolicyError(f"{path}: rule {r.get('id', '?') if isinstance(r, dict) else '?'}: {e}") from e
    for rule in out:  # inline tests: a rule that fails its own examples never goes live
        for t in rule.match:
            if not rule.pattern.search(t):
                raise PolicyError(f"{path}: rule {rule.id}: inline test must match: {t!r}")
        for t in rule.no_match:
            if rule.pattern.search(t):
                raise PolicyError(f"{path}: rule {rule.id}: inline test must not match: {t!r}")
    return out


class Policy:
    """Validated, merged, versioned policy. Immutable by convention."""

    def __init__(self, raw: dict, version: str, root: Path, rules: list[Rule], files: list[Path]):
        self.raw, self.version, self.root, self.rules, self.files = raw, version, root, rules, files
        self.doc = PolicyDoc.model_validate(raw)

    def control(self, cid: str) -> dict | None:
        return self.raw.get("controls", {}).get(cid)

    def profile_for(self, agent_id: str, explicit: str | None) -> str:
        """Agent profile (else defaults.profile); a per-request profile may only make it stricter."""
        a = self.raw.get("agents", {}).get(agent_id) or {}
        base = a.get("profile") or self.raw["defaults"].get("profile", "balanced")
        if explicit in PROFILES and base in PROFILES and PROFILES.index(explicit) < PROFILES.index(base):
            return explicit  # type: ignore[return-value]
        return base

    def model_allowlist(self, agent_id: str) -> list[str]:
        a = self.raw.get("agents", {}).get(agent_id) or {}
        if a.get("models") is not None:
            return list(a["models"])
        return list(((self.raw.get("destinations") or {}).get("model_allowlist") or {}).get("default") or [])

    def mode_for(self, cid: str, profile: str) -> str:
        c = self.control(cid)
        if c is None:
            return "off"
        m = c.get("mode", self.raw["defaults"].get("mode", "enforce"))
        if isinstance(m, dict):
            m = m.get(profile, "enforce")
        return m

    def fail_for(self, cid: str) -> str:
        """closed unless the policy says exactly open or degrade (a typo never fails open)."""
        c = self.control(cid) or {}
        f = c.get("fail", self.raw["defaults"].get("fail", "closed"))
        return f if f in ("open", "degrade") else "closed"

    def profile_cfg(self, profile: str) -> dict:
        return self.raw["profiles"].get(profile, {})

    def agent(self, agent_id: str) -> dict | None:
        return self.raw.get("agents", {}).get(agent_id)

    def interception(self) -> dict:
        """The interception: block with defaults (mode off when the policy has none)."""
        return interception.interception_cfg(self.raw)

    def derive(self, overrides: dict) -> "Policy":
        """A new validated policy = this one deep-merged with overrides (simulation, tests, what-if)."""
        raw = deep_merge(self.raw, _plain(overrides or {}))
        h = hashlib.sha256(_canon(raw))
        for rp in self.files:
            if rp.parent.name == "rules":
                h.update(rp.read_bytes())
        try:
            return Policy(raw, h.hexdigest(), self.root, self.rules, self.files)
        except ValidationError as e:
            raise PolicyError(f"derived policy: {e}") from e


def _canon(raw: dict) -> bytes:
    return json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode()


def load_policy(path: str | Path) -> Policy:
    try:
        return _load_policy(Path(path))
    except PolicyError:
        raise
    except Exception as e:  # noqa: BLE001 - wrong shapes (list where a mapping belongs, ...) are policy errors
        raise PolicyError(f"{path}: {type(e).__name__}: {e}") from e


def _load_policy(path: Path) -> Policy:
    try:
        base = _plain(_yaml_load(path.read_text(encoding="utf-8")))
    except Exception as e:
        raise PolicyError(f"{path}: {e}") from e
    if not isinstance(base, dict):
        raise PolicyError(f"{path}: top level must be a mapping")
    files = [path]
    local = path.parent / "local.d"
    if local.is_dir():
        for f in sorted(local.glob("*.yaml")):
            try:
                ov = _plain(_yaml_load(f.read_text(encoding="utf-8")) or {})
            except Exception as e:
                raise PolicyError(f"{f}: {e}") from e
            if not isinstance(ov, dict):
                raise PolicyError(f"{f}: top level must be a mapping")
            base = deep_merge(base, ov)
            files.append(f)
    root = path.parent.parent
    rule_paths: dict[Path, None] = {}
    rdir = path.parent / "rules"
    if rdir.is_dir():
        for f in sorted(rdir.glob("*.yaml")):
            rule_paths[f.resolve()] = None
    inj = (base.get("controls") or {}).get("INJ-03") or {}
    for rf in inj.get("rule_files", []) or []:
        rp = root / rf
        if not rp.is_file():
            raise PolicyError(f"INJ-03 rule file missing: {rf}")
        rule_paths[rp.resolve()] = None
    rules: list[Rule] = []
    h = hashlib.sha256(_canon(base))
    seen: set[str] = set()
    for rp in rule_paths:
        for r in load_rule_file(rp, source="feed" if rp.name.startswith("feed") else "policy"):
            if r.id in seen:
                raise PolicyError(f"duplicate rule id {r.id}")
            seen.add(r.id)
            rules.append(r)
        h.update(rp.read_bytes())
        files.append(rp)
    try:
        return Policy(base, h.hexdigest(), root, rules, files)
    except ValidationError as e:
        raise PolicyError(f"{path}: {e}") from e


class PolicyStore:
    """Holds the current policy; reloads when any source file changes (1 s polling).
    An invalid edit keeps the last good policy and sets `error`."""

    def __init__(self, path: str | Path, interval: float = 1.0):
        self.path = Path(path)
        self.interval = interval
        self.error: str | None = None
        self._last_check = 0.0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.on_change: list = []
        self.current: Policy = load_policy(self.path)  # the first load must be valid
        self._sig = self._signature(self.current)

    def _signature(self, pol: Policy | None) -> tuple:
        paths = set(pol.files) if pol else set()
        paths.add(self.path)
        for sub in ("local.d", "rules"):
            d = self.path.parent / sub
            if d.is_dir():
                paths.update(d.glob("*.yaml"))
        sig = []
        for p in sorted(paths):
            try:
                st = p.stat()
                sig.append((str(p), st.st_mtime_ns, st.st_size))
            except OSError:
                sig.append((str(p), 0, -1))
        return tuple(sig)

    def refresh(self, force: bool = False) -> bool:
        """Check sources now; True if a new policy became current."""
        with self._lock:
            sig = self._signature(self.current)
            if sig == self._sig and not force:
                return False
            self._sig = sig
            try:
                new = load_policy(self.path)
            except Exception as e:  # noqa: BLE001 - any bad edit keeps the last good policy
                self.error = str(e) if isinstance(e, PolicyError) else f"{self.path}: {type(e).__name__}: {e}"
                return False
            self.error = None
            changed = new.version != self.current.version
            self.current = new
        if changed:
            for cb in self.on_change:
                try:
                    cb(new)
                except Exception:
                    pass
        return changed

    def maybe_refresh(self) -> None:
        """Cheap throttled check for callers that do not run the background thread."""
        if self._thread is None:
            now = time.monotonic()
            if now - self._last_check >= self.interval:
                self._last_check = now
                self.refresh()

    def start(self) -> "PolicyStore":
        if self._thread is None:
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="policy-reload", daemon=True)
            self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.refresh()
            except Exception as e:  # noqa: BLE001 - the reload thread must never die
                self.error = f"reload: {type(e).__name__}: {e}"

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

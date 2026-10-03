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

PROFILES = ("strict", "balanced", "permissive")
MODES = ("enforce", "shadow", "off")
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
        for aid, a in self.agents.items():
            if a.get("profile", dp) not in self.profiles:
                raise ValueError(f"agents.{aid}.profile unknown")
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
                match=list(r.get("match", [])), no_match=list(r.get("no_match", []))))
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
        if explicit in self.raw["profiles"]:
            return explicit  # type: ignore[return-value]
        a = self.raw.get("agents", {}).get(agent_id, {})
        return a.get("profile") or self.raw["defaults"].get("profile", "balanced")

    def mode_for(self, cid: str, profile: str) -> str:
        c = self.control(cid)
        if c is None:
            return "off"
        m = c.get("mode", self.raw["defaults"].get("mode", "enforce"))
        if isinstance(m, dict):
            m = m.get(profile, "enforce")
        return m

    def fail_for(self, cid: str) -> str:
        c = self.control(cid) or {}
        return c.get("fail", self.raw["defaults"].get("fail", "closed"))

    def profile_cfg(self, profile: str) -> dict:
        return self.raw["profiles"].get(profile, {})

    def agent(self, agent_id: str) -> dict | None:
        return self.raw.get("agents", {}).get(agent_id)

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
    path = Path(path)
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
        for r in load_rule_file(rp):
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
            except PolicyError as e:
                self.error = str(e)
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
            self.refresh()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

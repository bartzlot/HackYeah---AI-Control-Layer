"""decide(): the one policy decision point for every PEP (LLM gateway, MCP proxy, SDK guard).

Flow per event: current policy snapshot -> profile -> destination class -> every registered control
whose mode is not `off` (in registry order, a failing control applies its fail mode) -> lattice
(enforced findings decide `action`, shadow findings only `would_action`) -> redactions for REDACT
spans -> explain trace (one line per finding: control, rule, span) -> Decision.

Gateway usage (T-901):
    from aicl_core import decide          # Event -> Decision, policy from $AICL_POLICY or ./policy/policy.yaml
    app = create_app(decide, config)
"""
from __future__ import annotations

import fnmatch
import os
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aicl_contracts import Action, Control, Ctx, Decision, DestKind, Event, Finding, Stage

from .policy import Policy, PolicyStore, to_action
from .redact import build_redactions

_DEST_ORDER = {DestKind.LOCAL: 0, DestKind.EXTERNAL: 1, DestKind.UNKNOWN: 2}

# ---------------------------------------------------------------- registry

REGISTRY: dict[str, Control] = {}
BUILTIN: set[str] = set()      # controls that run even when policy.yaml has no block for them


def register(control: Control, builtin: bool = False) -> Control:
    """Add a control to the registry (registration order = evaluation order)."""
    REGISTRY[control.control_id] = control
    if builtin:
        BUILTIN.add(control.control_id)
    return control


def registered() -> list[str]:
    _load_controls()
    return list(REGISTRY)


_controls_loaded = False
_controls_lock = threading.Lock()


def _load_controls() -> None:
    global _controls_loaded
    if _controls_loaded:
        return
    with _controls_lock:
        if not _controls_loaded:
            from . import controls  # noqa: F401  (side effect: registers every control; raises = no engine)
            _controls_loaded = True


# ---------------------------------------------------------------- helpers

def resolve_destination(policy: Policy, event: Event) -> DestKind:
    """Trust by model tag (policy destinations.models, glob keys); never weaker than what the PEP said."""
    dest = event.destination
    if event.model:
        models = (policy.raw.get("destinations") or {}).get("models") or {}
        entry = models.get(event.model)
        if entry is None:
            for pat, e in models.items():
                if pat != "*" and any(c in pat for c in "*?[") and fnmatch.fnmatchcase(event.model, pat):
                    entry = e
                    break
        if entry is None:
            entry = models.get("*", {"class": "unknown"})
        try:
            pol = DestKind(str(entry.get("class", "unknown")))
        except ValueError:
            pol = DestKind.UNKNOWN
        if _DEST_ORDER[pol] > _DEST_ORDER[dest]:
            dest = pol
    return dest


def matrix_cell(policy: Policy, level: str, dest: DestKind, profile: str) -> tuple[Action, bool]:
    """destination_matrix[level][dest] for the profile; missing cells fail closed (BLOCK)."""
    row = (policy.raw.get("destination_matrix") or {}).get(level)
    if row is None:
        return Action.BLOCK, False
    cell = row.get(dest.value, "BLOCK")
    if isinstance(cell, dict):
        cell = cell.get(profile, "BLOCK")
    return to_action(cell)


def _fmt_span(f: Finding) -> str:
    if not f.spans:
        return ""
    s = f.spans[0]
    where = f"part {s.part}" if s.part >= 0 else f"tool_call {-s.part - 1}"
    more = f" (+{len(f.spans) - 1} more)" if len(f.spans) > 1 else ""
    return f" at {where} [{s.start}:{s.end}] {s.type}{more}"


def _explain_line(f: Finding, mode: str) -> str:
    tag = " (shadow: not enforced)" if mode == "shadow" else ""
    why = f" - {f.reason_code}" if f.reason_code else ""
    return f"{f.control_id} rule {f.rule_id}: {f.action.name}{_fmt_span(f)}{why}{tag}"


# ---------------------------------------------------------------- engine

class Engine:
    """Holds the policy store and evaluates events. Thread-safe: each call reads one immutable snapshot."""

    def __init__(self, policy_path: str | Path | None = None, *, interval: float = 1.0, start: bool = False):
        _load_controls()
        self.store = PolicyStore(policy_path or default_policy_path(), interval=interval)
        if start:
            self.store.start()

    @property
    def policy(self) -> Policy:
        return self.store.current

    def decide(self, event: Event, policy: Policy | None = None) -> Decision:
        """Never raises: an internal error yields BLOCK (fail closed) with degraded=True."""
        t0 = time.perf_counter_ns()
        try:
            if policy is None:
                self.store.maybe_refresh()
                policy = self.store.current
            return self._decide(event, policy, t0)
        except Exception as e:  # noqa: BLE001
            return Decision(action=Action.BLOCK, would_action=Action.BLOCK, degraded=True,
                            policy_version=getattr(policy, "version", ""), decision_id=uuid.uuid4().hex[:16],
                            explain=[f"engine error {type(e).__name__}: {e}", "decision BLOCK (fail closed)"],
                            latency_us={"total": (time.perf_counter_ns() - t0) // 1000})

    def _decide(self, event: Event, policy: Policy, t0: int) -> Decision:
        profile = policy.profile_for(event.agent_id, event.profile)
        dest = resolve_destination(policy, event)
        ev = event if dest == event.destination else event.model_copy(update={"destination": dest})
        analysis: dict[str, Any] = {}
        enforced: list[Finding] = []
        shadow: list[Finding] = []
        lines: list[tuple[Action, str]] = []
        latency: dict[str, int] = {}
        degraded = False

        for cid, control in tuple(REGISTRY.items()):
            if ev.stage not in control.stages:
                continue
            block = policy.control(cid)
            if block is None and cid not in BUILTIN:
                continue                       # removed from policy.yaml -> the control stops running
            mode = policy.mode_for(cid, profile) if block is not None else "enforce"
            if mode == "off":
                continue
            params = {k: v for k, v in (block or {}).items() if k != "mode"}
            params.update(_policy=policy, _dest=dest, _analysis=analysis, _prior=list(enforced) + list(shadow))
            ctx = Ctx(profile=profile, mode=mode, params=params)
            c0 = time.perf_counter_ns()
            try:
                found = list(control.evaluate(ev, ctx))
            except Exception as e:  # noqa: BLE001 - any detector bug falls to the fail mode
                fail = policy.fail_for(cid)        # anything but open / degrade is closed
                if fail == "closed":
                    found = [Finding(control_id=cid, rule_id="CONTROL_ERROR", category="engine",
                                     action=Action.BLOCK, reason_code=f"fail closed: {type(e).__name__}")]
                else:
                    found = []
                    degraded = True
                    lines.append((Action.LOG, f"{cid}: error {type(e).__name__}, fail {fail}: skipped"))
            latency[cid] = (time.perf_counter_ns() - c0) // 1000
            for f in found:
                if not isinstance(f, Finding):
                    raise TypeError(f"{cid} returned {type(f).__name__}, not Finding")
                f = _effective(f, ev)
                (shadow if mode == "shadow" else enforced).append(f)
                lines.append((f.action, _explain_line(f, mode)))

        action = max((f.action for f in enforced), default=Action.ALLOW)
        redactions = build_redactions(enforced, ev) if action == Action.REDACT else []
        if action == Action.REDACT and not redactions:   # nothing could be redacted in place: fail closed
            action = Action.BLOCK
            lines.append((Action.BLOCK, "REDACT without redactable spans -> BLOCK"))
        would = max([action] + [f.action for f in shadow])
        lines.sort(key=lambda x: x[0])                 # strongest last: PEPs show explain[-2:]
        top = max(enforced, key=lambda f: f.action, default=None)
        head = (f"policy {policy.version[:12]} profile={profile} stage={ev.stage.value} "
                f"agent={ev.agent_id} dest={dest.value}" + (f" model={ev.model}" if ev.model else ""))
        final = f"decision {action.name}" + (f" by {top.control_id}/{top.rule_id}" if top and action > Action.ALLOW else "")
        if would != action:
            final += f" (would be {would.name} without shadow mode)"
        latency["total"] = (time.perf_counter_ns() - t0) // 1000
        return Decision(action=action, would_action=would, findings=enforced + shadow, redactions=redactions,
                        explain=[head] + [line for _, line in lines] + [final], policy_version=policy.version,
                        degraded=degraded, latency_us=latency, decision_id=uuid.uuid4().hex[:16])

    def status(self, profile: str | None = None) -> dict:
        """For the dashboard: policy hash, reload error, per-control mode and posture (% enforced)."""
        pol = self.store.current
        prof = profile or pol.raw["defaults"].get("profile", "balanced")
        rows = []
        for cid in sorted(set(pol.raw.get("controls", {})) | set(REGISTRY)):
            in_pol = pol.control(cid) is not None
            mode = pol.mode_for(cid, prof) if in_pol else ("enforce" if cid in BUILTIN else "off")
            rows.append({"control_id": cid, "mode": mode, "implemented": cid in REGISTRY, "in_policy": in_pol})
        live = [r for r in rows if r["in_policy"]]
        enforced = sum(r["mode"] == "enforce" for r in live)
        return {"policy_version": pol.version, "error": self.store.error, "profile": prof, "controls": rows,
                "posture_pct": round(100.0 * enforced / len(live), 1) if live else 0.0}


def _effective(f: Finding, ev: Event) -> Finding:
    """A REDACT finding whose spans cannot be rewritten in place (tool-call arguments, bad offsets) becomes BLOCK."""
    def ok(s) -> bool:
        return 0 <= s.part < len(ev.parts) and 0 <= s.start < s.end <= len(ev.parts[s.part].text)
    if f.action == Action.REDACT and (not f.spans or not all(ok(s) for s in f.spans)):
        return f.model_copy(update={"action": Action.BLOCK,
                                    "reason_code": (f.reason_code + "; " if f.reason_code else "")
                                    + "cannot redact tool arguments in place -> BLOCK"})
    return f


def default_policy_path() -> Path:
    env = os.environ.get("AICL_POLICY")
    if env:
        return Path(env)
    for base in (Path.cwd(), *Path.cwd().parents, Path(__file__).resolve().parent, *Path(__file__).resolve().parents):
        cand = base / "policy" / "policy.yaml"
        if cand.is_file():
            return cand
    raise FileNotFoundError("policy/policy.yaml not found; set AICL_POLICY")


_engine: Engine | None = None
_engine_lock = threading.Lock()


def get_engine() -> Engine:
    """Process-wide engine with the 1 s background reload thread."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = Engine(start=True)
    return _engine


def decide(event: Event) -> Decision:
    """Event -> Decision with the process-wide engine (the callable the gateway's create_app() takes)."""
    return get_engine().decide(event)


def make_decide(policy_path: str | Path, *, start: bool = True) -> Callable[[Event], Decision]:
    """A decide() bound to a specific policy file (tests, simulation)."""
    return Engine(policy_path, start=start).decide


__all__ = ["Engine", "decide", "get_engine", "make_decide", "register", "registered", "REGISTRY",
           "resolve_destination", "matrix_cell", "default_policy_path", "Stage"]

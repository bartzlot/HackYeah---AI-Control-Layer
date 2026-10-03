"""aicl-case/1 runner core: load <piece>/cases/<control>.yaml, build Events, check Decisions.

Case fields (see contracts/case.example.yaml):
  id, kind (positive | negative), path (llm | output | tool | mcp | memory), profile,
  setup: {agent, destination (model tag) | destination_class (local | external | unknown), session, policy (overrides)}
  input: {messages: [{role, content}]} | {response: str} | {tool_calls: [{name, arguments}]} | {tool_result: str}
  expect: {decision, would_decision, rule_ids, controls, findings: [] , redacted_contains, redacted_not_contains,
           upstream_* (gateway path only, ignored here)}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any

from ruamel.yaml import YAML

from aicl_contracts import SCHEMA_CASE, Action, Decision, DestKind, Event, Part, Stage, ToolCall

from .policy import Policy, _plain
from .redact import apply_redactions

DEFAULT_AGENT = "analyst-agent"
# auto = decide() when the control is registered there, plus the gateway when the input is routable;
# decide = decide() only; gateway = the real gateway only (gateway-enforced controls such as BUD-01);
# judge-fake = the gateway with the INJ-04 judge installed over a fake Ollama (setup.judge pins its answer)
RUNNERS = ("auto", "decide", "gateway", "judge-fake")
# every expect key either runner understands; anything else is a typo and fails the case
EXPECT_KEYS = frozenset({"decision", "would_decision", "rule_ids", "controls", "findings", "events",
                         "redacted_contains", "redacted_not_contains", "http_status", "upstream_called", "retry_after",
                         "upstream_body_contains", "upstream_body_not_contains", "judge_called", "degraded"})   # allowed both the local and the external model in policy.yaml


@dataclass
class Case:
    control: str
    id: str
    kind: str
    path: str
    raw: dict
    file: Path
    profile: str | None = None
    setup: dict = field(default_factory=dict)
    input: dict = field(default_factory=dict)
    expect: dict = field(default_factory=dict)
    runner: str = "auto"      # auto | decide | gateway | judge-fake (file-level `runner:`, a case may override)

    @property
    def name(self) -> str:
        return f"{self.control}:{self.id}"


def load_case_file(path: Path) -> list[Case]:
    doc = _plain(YAML(typ="safe").load(path.read_text(encoding="utf-8")) or {})
    if doc.get("schema") != SCHEMA_CASE:
        raise ValueError(f"{path}: schema must be {SCHEMA_CASE}")
    control = doc.get("control")
    if not control:
        raise ValueError(f"{path}: control missing")
    file_runner = doc.get("runner", "auto")
    out = []
    for c in doc.get("cases") or []:
        if c.get("kind") not in ("positive", "negative"):
            raise ValueError(f"{path}: case {c.get('id')}: kind must be positive|negative")
        runner = c.get("runner", file_runner)
        if runner not in RUNNERS:
            raise ValueError(f"{path}: case {c.get('id')}: runner must be one of {', '.join(RUNNERS)}")
        out.append(Case(control=c.get("control", control), id=str(c["id"]), kind=c["kind"], path=c.get("path", "llm"),
                        raw=c, file=path, profile=c.get("profile"), setup=c.get("setup") or {},
                        input=c.get("input") or {}, expect=c.get("expect") or {}, runner=runner))
    return out


def collect_cases(repo_root: Path) -> list[Case]:
    cases = []
    for f in sorted(repo_root.glob("*/cases/*.yaml")):
        cases.extend(load_case_file(f))
    return cases


def case_policy(base: Policy, case: Case, extra: dict | None = None) -> Policy:
    over = dict(case.setup.get("policy") or {})
    pol = base.derive(over) if over else base
    return pol.derive(extra) if extra else pol


_MACRO = re.compile(r"\{\{(zw|tags):?([^}]*)\}\}")


def expand(text: str) -> str:
    """Fixture macros keep invisible characters out of reviewable source:
    {{zw}} -> U+200B zero-width space; {{tags:abc}} -> abc as Unicode tag characters (U+E0000 + ord)."""
    def sub(m: re.Match) -> str:
        if m.group(1) == "zw":
            return chr(0x200B)
        return "".join(chr(0xE0000 + ord(c)) for c in m.group(2))
    return _MACRO.sub(sub, text)


def build_event(case: Case) -> Event:
    s, inp = case.setup, case.input
    model = s.get("destination")
    # default = local; with a model tag the policy resolves the real class (never weaker than this)
    dest = DestKind(s.get("destination_class", "local"))
    common = dict(agent_id=s.get("agent", DEFAULT_AGENT), session_id=s.get("session"), model=model,
                  destination=dest, profile=case.profile, request_id=f"case-{case.control}-{case.id}")
    if "messages" in inp:
        parts = [Part(role=m.get("role", "user"), text=expand(str(m.get("content", ""))),
                      trusted=m.get("trusted", m.get("role", "user") != "tool")) for m in inp.get("messages", [])]
        return Event(stage=Stage.PROMPT, channel="llm", parts=parts, **common)
    if case.path == "output" or "response" in inp:
        return Event(stage=Stage.RESPONSE, channel="llm", parts=[Part(role="assistant", text=str(inp.get("response", "")))],
                     **common)
    if "tool_calls" in inp:
        tcs = [ToolCall(name=t["name"], arguments=t.get("arguments") or {}, server=t.get("server"))
               for t in inp["tool_calls"]]
        return Event(stage=Stage.TOOL_ARGS, channel="tool" if case.path == "tool" else "mcp", tool_calls=tcs, **common)
    if "tool_result" in inp:
        ch = case.path if case.path in ("tool", "mcp", "memory") else "tool"
        return Event(stage=Stage.TOOL_RESULT, channel=ch, parts=[Part(role="tool", text=expand(str(inp["tool_result"])),
                                                                       trusted=False)], **common)
    raise ValueError(f"{case.name}: no usable input")


def check(case: Case, event: Event, d: Decision) -> list[str]:
    """Return the list of failed expectations (empty = case passes)."""
    e, errs = case.expect, []
    unknown = set(e) - EXPECT_KEYS
    if unknown:
        errs.append(f"unknown expect keys {sorted(unknown)}")
    if "decision" in e and d.action != Action.parse(e["decision"]):
        errs.append(f"decision {d.action.name} != {e['decision']}")
    if "would_decision" in e and d.would_action != Action.parse(e["would_decision"]):
        errs.append(f"would_decision {d.would_action.name} != {e['would_decision']}")
    rules = {f.rule_id for f in d.findings}
    for r in e.get("rule_ids") or []:
        if r not in rules:
            errs.append(f"rule {r} not in findings {sorted(rules)}")
    ctrls = {f.control_id for f in d.findings}
    for c in e.get("controls") or []:
        if c not in ctrls:
            errs.append(f"control {c} not in findings {sorted(ctrls)}")
    evs = {f.detail.get("event_type") for f in d.findings if d.action > Action.ALLOW or f.action > Action.ALLOW}
    for ev_type in e.get("events") or []:
        if ev_type not in evs:
            errs.append(f"event {ev_type} not in {sorted(x for x in evs if x)}")
    if "findings" in e and e["findings"] == [] and d.findings:
        errs.append(f"expected no findings, got {[f.control_id + '/' + f.rule_id for f in d.findings]}")
    if "redacted_contains" in e or "redacted_not_contains" in e:
        text = "\n".join(apply_redactions([p.text for p in event.parts], d.redactions))
        for s in _as_list(e.get("redacted_contains")):
            if s not in text:
                errs.append(f"redacted text lacks {s!r}: {text!r}")
        for s in _as_list(e.get("redacted_not_contains")):
            if s in text:
                errs.append(f"redacted text still has {s!r}")
    if case.kind == "negative" and d.would_action <= Action.WARN and "decision" not in e:
        errs.append("negative case was not blocked or redacted")
    return errs


def _as_list(x: Any) -> list:
    return [] if x is None else (x if isinstance(x, list) else [x])


def enabled_controls(policy: Policy) -> list[str]:
    """Controls of policy.yaml whose mode is not `off` for at least one profile."""
    out = []
    for cid, block in (policy.raw.get("controls") or {}).items():
        modes = (block or {}).get("mode", "enforce")
        modes = modes.values() if isinstance(modes, dict) else [modes]
        if any(m != "off" for m in modes):
            out.append(cid)
    return sorted(out)


def coverage_gaps(cases: list[Case], controls: list[str]) -> dict[str, list[str]]:
    """control -> missing case kinds (meta-test: every control needs a positive AND a negative case)."""
    have: dict[str, set[str]] = {}
    for c in cases:
        have.setdefault(c.control, set()).add(c.kind)
    return {cid: sorted({"positive", "negative"} - have.get(cid, set())) for cid in controls
            if {"positive", "negative"} - have.get(cid, set())}

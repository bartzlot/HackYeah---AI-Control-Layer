"""T-119 explain drawer: one request's decide() timeline from its audit records.

Stages in pipeline order: identity -> model + budget -> DLP-01 / DLP-02 / DLP-05 -> INJ-03 -> INJ-04 judge ->
TOOL-01 -> final action on the lattice ALLOW < LOG < WARN < REDACT < BLOCK. Per-stage latency is the sum of
the per-control latency_us of every decision of the request (prompt, response, tool_args), in the syntax of the
Server-Timing entries the gateway sends (`stage_timing`; the header only covers decisions made before the
response headers left, so a streamed answer's response stage is in this view, not in its header). Matched spans
leave here as type, position, sha256_8 and the redaction token only: audit records never hold raw text.
Shadow-mode findings (explain line "... (shadow: not enforced)") are shown but never set a stage action.
"""
from __future__ import annotations

from typing import Any, Iterable

from aicl_contracts import Action, Event, Finding, Part
from aicl_core.redact import build_redactions

from .names import layer_of

STAGES: list[tuple[str, str, tuple[str, ...]]] = [
    ("identity", "Identity", ("KILL-01", "ACCESS-01")),
    ("model_budget", "Model + budget", ("BUD-01",)),
    ("dlp", "Data loss: DLP-01 / DLP-02 / DLP-05", ("DLP-01", "DLP-02", "DLP-05")),
    ("inj03", "Injection signatures: INJ-03", ("INJ-03",)),
    ("inj04", "Local judge: INJ-04", ("INJ-04",)),
    ("tool", "Tool firewall: TOOL-01", ("TOOL-01",)),
]
OTHER = ("other", "Other controls")
STAGE_OF = {cid: sid for sid, _, cids in STAGES for cid in cids}
LATTICE = [a.name for a in sorted(Action)]
# audit.denied() records carry no control finding: map the event type to the stage that refused
DENIED = {"MODEL_DENIED": ("model_budget", "ACCESS-01"), "BUDGET_EXCEEDED": ("model_budget", "BUD-01"),
          "AGENT_DENIED": ("identity", "ACCESS-01")}


def stage_of(cid: str) -> str:
    return STAGE_OF.get(cid, OTHER[0])


def _name(a: Any) -> str:
    try:
        return Action(int(a)).name
    except (TypeError, ValueError):
        try:
            return Action.parse(str(a)).name
        except Exception:  # noqa: BLE001
            return str(a)


def _rank(a: Any) -> int:
    try:
        return LATTICE.index(_name(a))
    except ValueError:
        return 0


# ---- Server-Timing (gateway responses) -----------------------------------------------------------

def add_latency(acc: dict[str, int], latency_us: dict[str, int] | None) -> None:
    """Accumulate one decision's per-control latency into per-stage microseconds (total is skipped)."""
    for cid, us in (latency_us or {}).items():
        if cid != "total" and isinstance(us, (int, float)):
            sid = stage_of(cid)
            acc[sid] = acc.get(sid, 0) + int(us)


def stage_timing(acc: dict[str, int] | None) -> str:
    """Server-Timing entries per stage in pipeline order, e.g. 'identity;dur=0.01, dlp;dur=0.31' (ms)."""
    acc = acc or {}
    order = [sid for sid, _, _ in STAGES] + [OTHER[0]]
    return ", ".join(f"{sid};dur={acc[sid] / 1000:.2f}" for sid in order if sid in acc)


# ---- timeline ------------------------------------------------------------------------------------

def _shadow(rec: dict) -> set[tuple[str, str]]:
    """(control, rule) of the findings the engine logged as shadow (engine._explain_line)."""
    out = set()
    for line in rec.get("explain") or []:
        if str(line).endswith("(shadow: not enforced)") and " rule " in str(line):
            cid, rest = str(line).split(" rule ", 1)
            out.add((cid, rest.split(":", 1)[0]))
    return out


def _redactions(rec: dict, shadow: set[tuple[str, str]]) -> list:
    """The replacements the client really got: the engine's own build_redactions over the record's enforced
    findings (same merging and numbering), on blank texts long enough for the spans. Only a REDACT record
    replaced anything (a BLOCK, or a REDACT escalated to BLOCK, forwarded nothing)."""
    if _name(rec.get("decision")) != "REDACT":
        return []
    found, ends = [], {}
    for f in rec.get("findings") or []:
        if (f.get("control_id"), f.get("rule_id")) in shadow:
            continue
        try:
            found.append(Finding.model_validate(f))
        except Exception:  # noqa: BLE001 - an odd record must not break the drawer
            continue
        for s in f.get("spans") or []:
            ends[int(s.get("part", 0))] = max(ends.get(int(s.get("part", 0)), 0), int(s.get("end") or 0))
    if not ends:
        return []
    parts = [Part(text=" " * ends.get(i, 0)) for i in range(max(ends) + 1)]
    try:
        return build_redactions(found, Event(parts=parts))
    except Exception:  # noqa: BLE001
        return []


def _spans(f: dict, reds: list) -> list[dict]:
    """Position, type, hash and the token that replaced the span (None when nothing was replaced)."""
    out = []
    for s in f.get("spans") or []:
        part, start, end = s.get("part", 0), s.get("start"), s.get("end")
        token = next((r.replacement for r in reds if r.part == part and isinstance(start, int) and isinstance(end, int)
                      and r.start <= start and end <= r.end), None)
        out.append({"part": part, "start": start, "end": end, "type": s.get("type"), "sha256_8": s.get("sha256_8"),
                    "token": token})
    return out


def _finding(f: dict, rec: dict, shadow: set[tuple[str, str]], reds: list) -> dict:
    d = f.get("detail") or {}
    is_shadow = (f.get("control_id"), f.get("rule_id")) in shadow
    out = {"control_id": f.get("control_id"), "rule_id": f.get("rule_id"), "category": f.get("category"),
           "action": _name(f.get("action")), "reason_code": f.get("reason_code") or "", "score": f.get("score"),
           "threshold": f.get("threshold"), "rule_source": f.get("rule_source"), "record_stage": rec.get("stage"),
           "shadow": is_shadow, "spans": _spans(f, [] if is_shadow else reds), "detection_layer": layer_of(f.get("control_id"))}
    if f.get("control_id") == "INJ-04":
        out["judge"] = {"model": d.get("model"), "verdict": str(f.get("rule_id") or "").removeprefix("judge."),
                        "cached": bool(d.get("cached")), "eval_ms": d.get("eval_ms"),
                        "degraded": bool(d.get("degraded"))}
    return out


def timeline(records: Iterable[dict]) -> dict[str, Any]:
    """Records of one request (any order) -> stages with controls, findings, latency, and the final action."""
    recs = sorted((r for r in records if isinstance(r, dict)), key=lambda r: str(r.get("ts") or ""))
    if not recs:
        return {"records": 0, "stages": [], "final": None}
    stages: dict[str, dict] = {}
    for sid, label, cids in STAGES + [(OTHER[0], OTHER[1], ())]:
        stages[sid] = {"id": sid, "label": label, "controls": list(cids), "ran": [], "latency_ms": 0.0,
                       "action": "ALLOW", "findings": []}
    total_us = 0
    for r in recs:
        lat = r.get("latency_us") or {}
        total_us += int(lat.get("total") or 0)
        for cid, us in lat.items():
            if cid == "total" or not isinstance(us, (int, float)):
                continue
            st = stages[stage_of(cid)]
            st["latency_ms"] += us / 1000
            if cid not in st["ran"]:
                st["ran"].append(cid)
            if cid not in st["controls"]:
                st["controls"].append(cid)
        shadow = _shadow(r)
        reds = _redactions(r, shadow)
        for f in r.get("findings") or []:
            cid = str(f.get("control_id") or "")
            st = stages[stage_of(cid)]
            fo = _finding(f, r, shadow, reds)
            st["findings"].append(fo)
            if cid and cid not in st["controls"]:
                st["controls"].append(cid)
            if not fo["shadow"] and _rank(f.get("action")) > _rank(st["action"]):
                st["action"] = _name(f.get("action"))
        et = r.get("event_type")
        if et in DENIED and not r.get("findings"):
            sid, cid = DENIED[et]
            st = stages[sid]
            st["findings"].append({"control_id": cid, "rule_id": et, "category": "access", "action": "BLOCK",
                                   "reason_code": (r.get("explain") or [""])[0], "score": None, "threshold": None,
                                   "rule_source": "builtin", "record_stage": r.get("stage"), "shadow": False,
                                   "spans": []})
            st["action"] = "BLOCK"
    for st in stages.values():
        st["latency_ms"] = round(st["latency_ms"], 3)
        st["note"] = None
    mb = stages["model_budget"]
    if not mb["ran"] and not mb["findings"] and any(r.get("model") for r in recs):
        # the model allowlist and the budget ledger run in the gateway before decide(): no per-control latency
        mb["note"] = "model allowlist and budget ledger checked by the gateway before decide()"
    out = [s for s in stages.values() if s["id"] != OTHER[0] or s["ran"] or s["findings"]]

    final = max(recs, key=lambda r: _rank(r.get("decision")))
    action = _name(final.get("decision"))
    top = None
    for s in out:
        for f in s["findings"]:
            if f["action"] == action and not f["shadow"] and action not in ("ALLOW", "LOG"):
                top = {"control_id": f["control_id"], "rule_id": f["rule_id"], "stage": s["id"]}
                break
        if top:
            break
    would = max((r.get("would_decision") for r in recs if r.get("would_decision") is not None),
                key=_rank, default=final.get("decision"))
    first = recs[0]
    acc: dict[str, int] = {}
    for r in recs:
        add_latency(acc, r.get("latency_us"))
    return {
        "request_id": first.get("request_id"), "records": len(recs),
        "record_stages": [r.get("stage") for r in recs],
        "identity": {"principal": first.get("agent_id"), "client_ip": first.get("client_ip"),
                     "credential_hash": first.get("credential_hash"), "user_agent": first.get("user_agent")},
        "model": {"model": first.get("model"), "destination": first.get("destination"),
                  "protocol": first.get("protocol"), "upstream_host": first.get("upstream_host")},
        "stages": out,
        "final": {"action": action, "would": _name(would), "by": top, "lattice": LATTICE,
                  "degraded": any(r.get("degraded") for r in recs), "event_type": final.get("event_type")},
        "latency_ms": {"decide_total": round(total_us / 1000, 3)},
        "server_timing": ", ".join(x for x in (stage_timing(acc), f"decide;dur={total_us / 1000:.2f}") if x),
        "policy_version": first.get("policy_version"),
    }

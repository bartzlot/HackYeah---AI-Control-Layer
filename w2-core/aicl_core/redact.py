"""Span redaction: enforced REDACT findings -> non-overlapping Redactions with placeholders.

Placeholders: typed for secrets (`[REDACTED_AWS_KEY]`, irreversible) or numbered for PII
(`[PL_PESEL_1]`: the same value gets the same number within one event). A finding chooses with
detail["placeholder"] = "typed" | "numbered" and may pass detail["tag"] (format with {type}).
Overlaps: merged into their union, placeholder from the highest priority (detail["priority"], default 50).
"""
from __future__ import annotations

from aicl_contracts import Action, Event, Finding, Redaction


def placeholder_for(f: Finding, typ: str, number: int | None) -> str:
    tag = f.detail.get("tag")
    if tag:
        try:
            return str(tag).format(type=typ, n=number or 1)
        except (KeyError, IndexError, ValueError):
            return f"[REDACTED_{typ}]"
    if f.detail.get("placeholder") == "numbered":
        return f"[{typ}_{number or 1}]"
    return f"[REDACTED_{typ}]"


def build_redactions(findings: list[Finding], event: Event) -> list[Redaction]:
    """Overlapping spans are merged into their union (no character of any span stays in clear text);
    the union takes the placeholder of its highest-priority, then longest, member."""
    cands = []
    for f in findings:
        if f.action != Action.REDACT:
            continue
        try:
            prio = int(f.detail.get("priority", 50))
        except (TypeError, ValueError):
            prio = 50
        for s in f.spans:
            if 0 <= s.part < len(event.parts) and 0 <= s.start < s.end <= len(event.parts[s.part].text):
                cands.append((s.part, s.start, s.end, prio, f, s))
    cands.sort(key=lambda c: (c[0], c[1], -c[2]))
    groups: list[list] = []          # [part, start, end, best_key, finding, span]
    for part, start, end, prio, f, s in cands:
        key = (prio, end - start)
        g = groups[-1] if groups else None
        if g is not None and g[0] == part and start < g[2]:
            g[2] = max(g[2], end)
            if key > g[3]:
                g[3], g[4], g[5] = key, f, s
        else:
            groups.append([part, start, end, key, f, s])
    numbers: dict[tuple[str, str], int] = {}
    counters: dict[str, int] = {}
    out = []
    for part, start, end, _, f, s in groups:     # reading order: the first PESEL in the text is _1
        n = None
        if f.detail.get("placeholder") == "numbered" and not f.detail.get("tag"):
            key = (s.type, s.sha256_8 or f"{s.part}:{s.start}")
            if key not in numbers:
                counters[s.type] = counters.get(s.type, 0) + 1
                numbers[key] = counters[s.type]
            n = numbers[key]
        out.append(Redaction(part=part, start=start, end=end, replacement=placeholder_for(f, s.type, n)))
    return out


def apply_redactions(texts: list[str], redactions: list[Redaction]) -> list[str]:
    """Reference applier (the gateway has its own): replace right-to-left so offsets stay valid."""
    out = list(texts)
    for r in sorted(redactions, key=lambda r: (r.part, r.start), reverse=True):
        if 0 <= r.part < len(out):
            t = out[r.part]
            out[r.part] = t[:r.start] + r.replacement + t[r.end:]
    return out

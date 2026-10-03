"""Span redaction: enforced REDACT findings -> non-overlapping Redactions with placeholders.

Placeholders: typed for secrets (`[REDACTED_AWS_KEY]`, irreversible) or numbered for PII
(`[PL_PESEL_1]`: the same value gets the same number within one event). A finding chooses with
detail["placeholder"] = "typed" | "numbered" and may pass detail["tag"] (format with {type}).
Overlaps: higher priority wins (detail["priority"], default 50), then the longer span.
"""
from __future__ import annotations

from aicl_contracts import Action, Event, Finding, Redaction


def placeholder_for(f: Finding, typ: str, number: int | None) -> str:
    tag = f.detail.get("tag")
    if tag:
        return str(tag).format(type=typ, n=number or 1)
    if f.detail.get("placeholder") == "numbered":
        return f"[{typ}_{number or 1}]"
    return f"[REDACTED_{typ}]"


def build_redactions(findings: list[Finding], event: Event) -> list[Redaction]:
    cands = []
    for f in findings:
        if f.action != Action.REDACT:
            continue
        prio = int(f.detail.get("priority", 50))
        for s in f.spans:
            if 0 <= s.part < len(event.parts) and 0 <= s.start < s.end <= len(event.parts[s.part].text):
                cands.append((prio, s.end - s.start, f, s))
    cands.sort(key=lambda c: (-c[0], -c[1], c[3].part, c[3].start))
    taken: dict[int, list[tuple[int, int]]] = {}
    numbers: dict[tuple[str, str], int] = {}
    counters: dict[str, int] = {}
    chosen = []
    for _, _, f, s in cands:
        if any(s.start < e and b < s.end for b, e in taken.get(s.part, [])):
            continue
        taken.setdefault(s.part, []).append((s.start, s.end))
        chosen.append((f, s))
    out = []
    # number placeholders in reading order, so the first PESEL in the text is _1
    for f, s in sorted(chosen, key=lambda c: (c[1].part, c[1].start)):
        n = None
        if f.detail.get("placeholder") == "numbered":
            key = (s.type, s.sha256_8 or f"{s.part}:{s.start}")
            if key not in numbers:
                counters[s.type] = counters.get(s.type, 0) + 1
                numbers[key] = counters[s.type]
            n = numbers[key]
        out.append(Redaction(part=s.part, start=s.start, end=s.end, replacement=placeholder_for(f, s.type, n)))
    return out


def apply_redactions(texts: list[str], redactions: list[Redaction]) -> list[str]:
    """Reference applier (the gateway has its own): replace right-to-left so offsets stay valid."""
    out = list(texts)
    for r in sorted(redactions, key=lambda r: (r.part, r.start), reverse=True):
        if 0 <= r.part < len(out):
            t = out[r.part]
            out[r.part] = t[:r.start] + r.replacement + t[r.end:]
    return out

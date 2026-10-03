"""INJ-03: signature rules (policy/rules/*.yaml, EN + PL) over a normalized view with an offset map.

Channel trust decides: untrusted parts (tool results, RAG, MCP, memory) -> rule.action_untrusted;
user parts -> rule.action_user, raised to BLOCK for injection-family rules whose severity score
reaches profiles.<p>.injection.block (the strictness dial). Mention exception: a quoted phrase in an
educational question ("Explain the phrase '...'") is logged, not blocked (user parts only).
"""
from __future__ import annotations

import re
import unicodedata

from aicl_contracts import Action, Ctx, Event, Finding, Span, Stage

from ..engine import register
from ..util import is_untrusted, sha8

SEVERITY_SCORE = {"low": 0.40, "medium": 0.65, "high": 0.80, "critical": 0.95}
INJECTION_FAMILY = {"injection", "prompt_extraction", "jailbreak"}
_ZW = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD}
_L_STROKE = {0x0141: "L", 0x0142: "l"}
_QUOTES = "\"'`" + "".join(map(chr, (0x2018, 0x2019, 0x201C, 0x201D, 0x201E, 0x00AB, 0x00BB)))
_CUES = re.compile(r"(?i)\b(explain|example|what does|what is|meaning of|the phrase|definition|how do .{0,30}defend|"
                   r"wyjasnij|przyklad|co znaczy|co oznacza|fraza|zwrot)\b")


def normalized_view(text: str) -> tuple[str, list[int]]:
    """NFKC + zero-width strip + diacritic fold + Unicode tag chars decoded; omap[j] = original index."""
    out: list[str] = []
    omap: list[int] = []
    in_tags = False
    for i, c in enumerate(text):
        o = ord(c)
        if o in _ZW:
            continue
        tag = 0xE0020 <= o <= 0xE007E
        if tag != in_tags and out:               # a hidden tag run is its own word: separate it
            out.append(" ")
            omap.append(i)
        in_tags = tag
        if tag:                                  # Unicode tag smuggling: decode to ASCII
            n = chr(o - 0xE0000)
        elif o in _L_STROKE:
            n = _L_STROKE[o]
        else:
            n = "".join(ch for ch in unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", c))
                        if not unicodedata.combining(ch))
        for ch in n:
            out.append(ch)
            omap.append(i)
    return "".join(out), omap


def _mention(text: str, s: int, e: int) -> bool:
    if not _CUES.search(text):
        return False
    before, after = text[max(0, s - 3):s], text[e:e + 3]
    return any(q in before for q in _QUOTES) and any(q in after for q in _QUOTES)


class Injection:
    control_id = "INJ-03"
    stages = (Stage.PROMPT, Stage.RESPONSE, Stage.TOOL_RESULT)

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        pol, p = ctx.params["_policy"], ctx.params
        block_at = float(((pol.profile_cfg(ctx.profile).get("injection") or {}).get("block", 0.6)))
        mentions = bool(p.get("mention_exceptions", True))
        out: list[Finding] = []
        for idx, part in enumerate(event.parts):
            if event.stage == Stage.RESPONSE:
                continue                                  # model output: output filters are a later control
            view, omap = normalized_view(part.text)
            untrusted = is_untrusted(event, idx)
            for rule in pol.rules:
                m = rule.pattern.search(view)
                if not m:
                    continue
                s = omap[m.start()] if m.start() < len(omap) else len(part.text)
                e = omap[m.end() - 1] + 1 if m.end() > 0 else s
                score = SEVERITY_SCORE.get(rule.severity, 0.65)
                if untrusted:
                    act, why = rule.action_untrusted, "untrusted channel"
                else:
                    act, why = rule.action_user, "user turn"
                    if rule.category in INJECTION_FAMILY and score >= block_at:
                        act, why = Action.BLOCK, f"user turn, score {score:.2f} >= {ctx.profile} block {block_at:.2f}"
                    if mentions and _mention(part.text, s, e):
                        act, why = Action.LOG, "quoted mention in an educational question"
                out.append(Finding(control_id=self.control_id, rule_id=rule.id, category=rule.category, action=act,
                                   score=score, threshold=block_at, reason_code=f"{rule.name or rule.id}: {why}",
                                   rule_source="local" if rule.source == "local" else "policy",
                                   spans=[Span(part=idx, start=s, end=e, type=rule.category,
                                               sha256_8=sha8(part.text[s:e]))],
                                   detail={"severity": rule.severity, "untrusted": untrusted,
                                           "event_type": "INJECTION_BLOCKED" if act == Action.BLOCK else None}))
        return out


register(Injection())

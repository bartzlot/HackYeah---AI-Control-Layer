"""INJ-03: signature rules (policy/rules/*.yaml, EN + PL) over a normalized view with an offset map.

Channel trust decides: untrusted parts (tool results, RAG, MCP, memory) -> rule.action_untrusted;
user turns -> rule.action_user, raised to BLOCK for injection-family rules whose severity score reaches
profiles.<p>.injection.block (the strictness dial); earlier assistant turns -> rule.action_user without
that escalation; system parts (the operator's own prompt) are not scanned.
Mention exception (user turns only): an educational question quoting the phrase ("Explain the phrase
'ignore previous instructions'") is LOG when the rule no longer matches once quoted text is removed, a cue
word stands shortly before the quote, nothing asks to act on it, and the rule's own user action is not BLOCK.
"""
from __future__ import annotations

import re

from aicl_contracts import Action, Ctx, Event, Finding, Span, Stage

from ..engine import register
from ..util import is_untrusted, normalized_view, sha8, view_span

SEVERITY_SCORE = {"low": 0.40, "medium": 0.65, "high": 0.80, "critical": 0.95}
INJECTION_FAMILY = {"injection", "prompt_extraction", "jailbreak"}
_CUES = re.compile(r"(?i)\b(explain|example|for instance|what does|what is|meaning of|phrase|definition|classify|"
                   r"detect|recogni[sz]e|wyjasnij|przyklad|co znaczy|co oznacza|fraza|zwrot)\b")
_ACT_ON_IT = re.compile(r"(?i)\b(now do|do (exactly )?(that|it|this|so)|then do|follow (it|that|them|those)|execute (it|that)|"
                        r"and (then )?(also )?(reveal|print|ignore|disregard|send|run)|teraz to zrob|zrob to|wykonaj (to|je))\b")
_QUOTED = re.compile("\"[^\"\\n]{1,300}\"|(?<![A-Za-z0-9])'[^'\\n]{1,300}'(?![A-Za-z0-9])|`[^`\\n]{1,300}`|"
                     + chr(0x201C) + "[^" + chr(0x201D) + "\\n]{1,300}" + chr(0x201D) + "|"
                     + chr(0x201E) + "[^" + chr(0x201D) + "\\n]{1,300}" + chr(0x201D) + "|"
                     + chr(0x2018) + "[^" + chr(0x2019) + "\\n]{1,300}" + chr(0x2019))


def _mention(view: str, rule, m: re.Match) -> bool:
    quotes = list(_QUOTED.finditer(view))
    inside = [q for q in quotes if q.start() <= m.start() < q.end()]
    if not inside:
        return False
    q = inside[0]
    if not _CUES.search(view[max(0, q.start() - 60):q.start()]):
        return False
    if _ACT_ON_IT.search(view):
        return False
    stripped = _QUOTED.sub(" ", view)
    return rule.pattern.search(stripped) is None


class Injection:
    control_id = "INJ-03"
    stages = (Stage.PROMPT, Stage.TOOL_RESULT)

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        pol, p = ctx.params["_policy"], ctx.params
        block_at = float(((pol.profile_cfg(ctx.profile).get("injection") or {}).get("block", 0.6)))
        mentions = bool(p.get("mention_exceptions", True))
        out: list[Finding] = []
        for idx, part in enumerate(event.parts):
            untrusted = is_untrusted(event, idx)
            if part.role == "system" and not untrusted:
                continue                                  # the operator's own system prompt
            view, omap = normalized_view(part.text)
            for rule in pol.rules:
                m = rule.pattern.search(view)
                if not m:
                    continue
                s, e = view_span(omap, m.start(), m.end(), len(part.text))
                score = SEVERITY_SCORE.get(rule.severity, 0.65)
                if untrusted:
                    act, why = rule.action_untrusted, "untrusted channel"
                else:
                    act, why = rule.action_user, f"{part.role} turn"
                    if part.role == "user" and rule.category in INJECTION_FAMILY and score >= block_at:
                        act, why = Action.BLOCK, f"user turn, score {score:.2f} >= {ctx.profile} block {block_at:.2f}"
                    if (mentions and part.role == "user" and rule.action_user < Action.BLOCK
                            and _mention(view, rule, m)):
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

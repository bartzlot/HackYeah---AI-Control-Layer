"""DLP-01 secrets, DLP-02 PII (validated), DLP-05 destination matrix (markings, dictionaries, data class)."""
from __future__ import annotations

from aicl_contracts import Action, Ctx, Event, Finding, Stage

from ..detect import Hit, find_pii, find_secrets, find_terms
from ..engine import matrix_cell, register
from ..policy import to_action
from ..util import iter_texts, span

_ALL = (Stage.PROMPT, Stage.RESPONSE, Stage.TOOL_ARGS, Stage.TOOL_RESULT)
_LEVELS = ("public", "internal", "confidential", "restricted")

CLASS_KEY = {"PL_PESEL": "pii.pesel", "IBAN": "pii.iban", "CREDIT_CARD": "pii.card", "EMAIL": "pii.email",
             "PHONE": "pii.phone", "MARKING": "marking.confidential", "CUSTOMER": "dictionary.customer",
             "CODENAME": "dictionary.project_codename"}
PROFILE_PII_KEY = {"EMAIL": "email", "PHONE": "phone"}


def _cached(ctx: Ctx, key: str, fn):
    a = ctx.params["_analysis"]
    if key not in a:
        a[key] = fn()
    return a[key]


def secrets_of(event: Event, ctx: Ctx, crc: str = "prefer") -> list[tuple[int, Hit]]:
    return _cached(ctx, f"secrets:{crc}", lambda: [(i, h) for i, t in iter_texts(event) for h in find_secrets(t, crc)])


def pii_of(event: Event, ctx: Ctx, own: tuple = ()) -> list[tuple[int, Hit]]:
    return _cached(ctx, f"pii:{','.join(own)}", lambda: [(i, h) for i, t in iter_texts(event) for h in find_pii(t, own)])


def level_of(policy, typ: str) -> str:
    cls = policy.raw.get("classification") or {}
    key = "secret.any" if typ not in CLASS_KEY else CLASS_KEY[typ]
    lvl = cls.get(key, "restricted" if key == "secret.any" else "confidential")
    return lvl if lvl in _LEVELS else "restricted"


def _stage_key(stage: Stage) -> str:
    return {Stage.PROMPT: "prompt", Stage.RESPONSE: "response", Stage.TOOL_ARGS: "tool_args",
            Stage.TOOL_RESULT: "prompt"}.get(stage, "prompt")


class Secrets:
    control_id = "DLP-01"
    stages = _ALL

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        p = ctx.params
        hits = secrets_of(event, ctx, str(p.get("github_crc", "prefer")))
        if not hits:
            return []
        act_map = p.get("action") or {}
        base = act_map.get(_stage_key(event.stage), "REDACT") if isinstance(act_map, dict) else act_map
        act = max(to_action(base)[0], to_action(p["_policy"].profile_cfg(ctx.profile).get("secrets", "REDACT"))[0])
        tag = str(p.get("redaction_tag", "[REDACTED_{type}]"))
        out: dict[str, Finding] = {}
        for i, h in hits:
            f = out.get(h.type)
            if f is None:
                f = out[h.type] = Finding(control_id=self.control_id, rule_id=h.type, category="secret", action=act,
                                          score=h.score, reason_code=f"{h.type} detected",
                                          detail={"priority": h.meta.get("priority", 90), "tag": tag,
                                                  "event_type": "SECRET_DETECTED"})
            f.spans.append(span(i, h.start, h.end, h.type, h.value))
        return list(out.values())


class Pii:
    """Action = profiles.<p>.pii (per entity, else default) when the data is not cleared for where it goes:
    prompt -> destination matrix cell (ALLOW cell = LOG only); response / tool -> agent max_data_level."""
    control_id = "DLP-02"
    stages = _ALL

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        p, pol = ctx.params, ctx.params["_policy"]
        ents = p.get("entities") or {}
        own = tuple((ents.get("EMAIL") or {}).get("own_domains") or ())
        hits = pii_of(event, ctx, own)
        if not hits:
            return []
        prof = pol.profile_cfg(ctx.profile).get("pii") or {}
        agent = pol.agent(event.agent_id) or {}
        clearance = agent.get("max_data_level", "internal")
        out: dict[str, Finding] = {}
        for i, h in hits:
            ent = ents.get(h.type, {})
            if h.type not in ents:
                continue                                   # entity removed from policy = not detected
            lvl = level_of(pol, h.type)
            word = ent.get("action", "profile")
            if word == "profile":
                word = prof.get(PROFILE_PII_KEY.get(h.type, "default"), prof.get("default", "REDACT"))
            act = to_action(word)[0]
            why = f"{h.type} ({lvl})"
            if h.meta.get("own_domain"):
                act, why = Action.LOG, f"{h.type} in own domain"
            elif event.stage == Stage.PROMPT:
                cell, _ = matrix_cell(pol, lvl, ctx.params["_dest"], ctx.profile)
                if cell == Action.ALLOW:
                    act, why = Action.LOG, f"{h.type} ({lvl}) allowed to {ctx.params['_dest'].value}"
            elif _LEVELS.index(lvl) <= _LEVELS.index(clearance if clearance in _LEVELS else "internal"):
                act, why = Action.LOG, f"{h.type} ({lvl}) within agent clearance {clearance}"
            key = f"{h.type}:{act.name}"
            f = out.get(key)
            if f is None:
                f = out[key] = Finding(control_id=self.control_id, rule_id=h.type, category="pii", action=act,
                                       score=h.score, reason_code=why,
                                       detail={"placeholder": "numbered", "priority": 60, "level": lvl,
                                               "event_type": "PII_REDACTED"})
            f.spans.append(span(i, h.start, h.end, h.type, h.value))
        return list(out.values())


class Destination:
    """data level of each detected item x destination class -> matrix action (prompt stage only)."""
    control_id = "DLP-05"
    stages = (Stage.PROMPT,)

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        p, pol, dest = ctx.params, ctx.params["_policy"], ctx.params["_dest"]
        dlp02 = pol.control("DLP-02") or {}
        own = tuple(((dlp02.get("entities") or {}).get("EMAIL") or {}).get("own_domains") or ())
        dlp01 = pol.control("DLP-01") or {}
        items = list(secrets_of(event, ctx, str(dlp01.get("github_crc", "prefer"))))
        items += [(i, h) for i, h in pii_of(event, ctx, own) if not h.meta.get("own_domain")]
        dicts = p.get("dictionaries") or {}
        for i, t in iter_texts(event, include_tool_args=False):
            items += [(i, h) for h in find_terms(t, list(p.get("markings") or []), "MARKING", case_sensitive=True)]
            items += [(i, h) for h in find_terms(t, list(dicts.get("customer") or []), "CUSTOMER")]
            items += [(i, h) for h in find_terms(t, list(dicts.get("project_codename") or []), "CODENAME")]
        groups: dict[tuple[str, Action], Finding] = {}
        for i, h in items:
            lvl = level_of(pol, h.type)
            act, approval = matrix_cell(pol, lvl, dest, ctx.profile)
            if act == Action.ALLOW:
                continue
            if act == Action.REDACT and h.type == "MARKING":
                act = Action.BLOCK                     # a marked document cannot be made safe by hiding the marking
            key = (lvl, act)
            f = groups.get(key)
            if f is None:
                f = groups[key] = Finding(
                    control_id=self.control_id, rule_id=f"matrix.{lvl}.{dest.value}", category="destination",
                    action=act, reason_code=f"{lvl} data to {dest.value} destination: {act.name}"
                    + (" (REQUIRE_APPROVAL enforced as BLOCK)" if approval else ""),
                    detail={"placeholder": "numbered", "priority": 55, "level": lvl,
                            "event_type": "DESTINATION_BLOCKED" if act == Action.BLOCK else "PII_REDACTED"})
            f.spans.append(span(i, h.start, h.end, h.type, h.value))
        return list(groups.values())


register(Secrets())
register(Pii())
register(Destination())

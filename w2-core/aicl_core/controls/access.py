"""KILL-01 (emergency stop) and ACCESS-01 (known agent, model allowlist)."""
from __future__ import annotations

from aicl_contracts import Action, Ctx, Event, Finding, Stage

from ..engine import register
from ..policy import to_action

_ALL = (Stage.PROMPT, Stage.RESPONSE, Stage.TOOL_ARGS, Stage.TOOL_RESULT)


class KillSwitch:
    control_id = "KILL-01"
    stages = _ALL

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        em = ctx.params["_policy"].raw.get("emergency") or {}
        if em.get("kill_switch"):
            rule, why = "kill.global", "global kill switch is on"
        elif event.agent_id in (em.get("killed_agents") or []):
            rule, why = "kill.agent", f"agent {event.agent_id} is killed"
        elif event.session_id and event.session_id in (em.get("killed_sessions") or []):
            rule, why = "kill.session", f"session {event.session_id} is killed"
        else:
            return []
        return [Finding(control_id=self.control_id, rule_id=rule, category="access", action=Action.BLOCK,
                        reason_code=why)]


class Access:
    """Identity comes from the PEP (API key -> agent_id). Unknown agents and models outside the
    agent's allowlist are denied (policy: unknown_agent, agents.<id>.models)."""
    control_id = "ACCESS-01"
    stages = _ALL

    def evaluate(self, event: Event, ctx: Ctx) -> list[Finding]:
        pol = ctx.params["_policy"]
        agent = pol.agent(event.agent_id)
        if agent is None:
            act, _ = to_action((pol.raw.get("unknown_agent") or {}).get("action", "BLOCK"))
            return [Finding(control_id=self.control_id, rule_id="agent.unknown", category="access", action=act,
                            reason_code=f"agent {event.agent_id!r} is not in policy.agents")]
        models = agent.get("models")
        if event.stage == Stage.PROMPT and event.model and models is not None and event.model not in models:
            return [Finding(control_id=self.control_id, rule_id="model.not_allowed", category="access",
                            action=Action.BLOCK, reason_code=f"model {event.model!r} not allowed for {event.agent_id}",
                            detail={"event_type": "MODEL_DENIED"})]
        return []


register(KillSwitch())
register(Access())

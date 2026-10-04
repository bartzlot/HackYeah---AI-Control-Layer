"""KILL-01 (emergency stop) and ACCESS-01 (known agent, model allowlist)."""
from __future__ import annotations

from aicl_contracts import Action, Ctx, Event, Finding, Stage

from .. import interception
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
        if event.upstream_host:          # v4 passthrough: identity is the clients: map, not agents (research/14 s.6)
            return self._passthrough(event, pol)
        agent = pol.agent(event.agent_id)
        if agent is None:
            act, _ = to_action((pol.raw.get("unknown_agent") or {}).get("action", "BLOCK"))
            return [Finding(control_id=self.control_id, rule_id="agent.unknown", category="access", action=act,
                            reason_code=f"agent {event.agent_id!r} is not in policy.agents")]
        models = pol.model_allowlist(event.agent_id)   # agents.<id>.models, else destinations.model_allowlist.default
        if event.stage == Stage.PROMPT and event.model and event.model not in models:
            return [Finding(control_id=self.control_id, rule_id="model.not_allowed", category="access",
                            action=Action.BLOCK, reason_code=f"model {event.model!r} not allowed for {event.agent_id}",
                            detail={"event_type": "MODEL_DENIED"})]
        return []


    def _passthrough(self, event: Event, pol) -> list[Finding]:
        who = interception.client_for(pol.raw, event.client_ip, event.credential_hash, event.user_agent)
        if who["principal"] != event.agent_id:
            return [Finding(control_id=self.control_id, rule_id="client.mismatch", category="access",
                            action=Action.BLOCK, reason_code=f"PEP principal {event.agent_id!r} != clients: "
                            f"{who['principal']!r}")]
        if not who["matched"]:
            act, _ = to_action(who.get("action", "ALLOW"))
            if act > Action.ALLOW:
                return [Finding(control_id=self.control_id, rule_id="client.unknown", category="access", action=act,
                                reason_code="client not in clients: (interception.unknown_client)")]
        if event.stage == Stage.PROMPT and event.model and not interception.model_allowed(who.get("models"),
                                                                                          event.model):
            return [Finding(control_id=self.control_id, rule_id="model.not_allowed", category="access",
                            action=Action.BLOCK, reason_code=f"model {event.model!r} not allowed for "
                            f"{event.agent_id}", detail={"event_type": "MODEL_DENIED"})]
        return []


# builtin: removing the policy block does not switch them off (only an explicit mode: off does)
register(KillSwitch(), builtin=True)
register(Access(), builtin=True)

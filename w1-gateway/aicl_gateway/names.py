"""T-123 display names + detection layer.

Every control and every rule shows a human-readable name and a one-line description next to its id (ids never
change: the audit stays compatible). Rule names come from three places, in this order: the loaded rule files
(`name:` of policy/rules/*.yaml and the feed), the policy's TOOL-01 rules, and the built-in ids below. An id
nobody named gets a readable fallback, so the UI never shows a bare machine id without text.

Detection layer (who caught it): `deterministic` = regex, checksum, signature, allowlist, tool firewall, ledger
(same text = same verdict, microseconds); `ai` = INJ-04 (local classifier, kNN and judge model). The audit
contract has no field for it yet (lead task), so the console derives it from the findings of a record.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

DETERMINISTIC, AI = "deterministic", "ai"
LAYER_LABEL = {DETERMINISTIC: "DETERMINISTIC", AI: "AI"}
AI_CONTROLS = {"INJ-04"}

# id -> (display name, one-line description)
CONTROLS: dict[str, tuple[str, str]] = {
    "KILL-01": ("Emergency stop", "A global, per-agent or per-session kill switch blocks every request at once."),
    "ACCESS-01": ("Identity and model access", "Only known agents may call, and only with the models allowed for them."),
    "DLP-01": ("Secret leak (API keys, tokens)", "AWS keys, GitHub tokens, private keys and API keys are redacted before they leave."),
    "DLP-02": ("Personal data (PESEL, IBAN, card, e-mail)", "Values proven by checksum (PESEL, IBAN mod 97, Luhn) are redacted or blocked per profile."),
    "DLP-05": ("Data leaving to the wrong place", "Data class against destination (local, external, unknown), markings and customer dictionaries."),
    "INJ-03": ("Prompt injection signatures (EN + PL)", "Signature rules for instruction overrides, jailbreaks, prompt extraction and exploit code."),
    "INJ-04": ("Prompt injection, AI judge", "A local model rates paraphrased attacks that no signature matches (the gray band)."),
    "TOOL-01": ("Tool firewall", "Which tools an agent may call and with which arguments: curl | sh, .env reads, destructive calls."),
    "BUD-01": ("Budgets and loop guard", "Token and USD limits per agent and organisation, rate limits and runaway-loop termination."),
    "NET-01": ("Network bypass detection", "A client that resolves or connects to an AI provider around the gateway raises an alert."),
}

# built-in rule ids (the ones no rule file or policy entry names)
RULES: dict[str, tuple[str, str]] = {
    "kill.global": ("Global kill switch", "The emergency kill switch is on: nothing passes."),
    "kill.agent": ("Agent killed", "This agent was stopped by an operator."),
    "kill.session": ("Session killed", "This session was stopped by an operator or by the loop guard."),
    "agent.unknown": ("Unknown agent", "The API key does not belong to any agent in the policy."),
    "client.unknown": ("Unknown client", "No clients: entry matches this address, key or user agent."),
    "client.mismatch": ("Client mismatch", "The client is not allowed to use this agent identity."),
    "model.not_allowed": ("Model not allowed", "The agent may not use this model."),
    "AWS_KEY": ("AWS access key", "An AWS access key id (documentation example keys included)."),
    "AWS_SECRET": ("AWS secret key", "An AWS secret access key next to a key id."),
    "GITHUB_TOKEN": ("GitHub token", "A GitHub personal or app token (CRC checked when valid)."),
    "PRIVATE_KEY": ("Private key", "A PEM private key block."),
    "API_KEY": ("API key", "A provider or generic API key found by pattern or by entropy in context."),
    "PL_PESEL": ("PESEL number", "A Polish national id with a valid checksum and date."),
    "IBAN": ("IBAN", "A bank account number that passes the mod 97 check."),
    "CREDIT_CARD": ("Payment card number", "A card number that passes the Luhn check."),
    "EMAIL": ("E-mail address", "An e-mail address outside the own domains."),
    "PHONE": ("Phone number", "A phone number."),
    "judge.benign": ("Judge: benign", "The local model cleared the text; the check is documented, nothing is blocked."),
    "judge.suspicious": ("Judge: suspicious", "The local model rates the text as probably an injection attempt."),
    "judge.malicious": ("Judge: malicious", "The local model rates the text as a prompt injection."),
    "judge.unavailable": ("Judge unavailable", "The model timed out or failed; the policy fail action applied."),
    "budget.agent": ("Agent budget exhausted", "The agent used its token or USD allowance for the period."),
    "budget.org": ("Organisation budget exhausted", "The organisation used its USD or token allowance."),
    "budget.request_too_large": ("Request larger than the budget", "A single request could never fit in the agent's limit."),
    "budget.unpriced": ("Model without a price", "An external model with no price cannot be metered, so it is refused."),
    "loop.repeat_identical": ("Runaway loop: identical calls", "The same call repeated until the loop guard ended the session."),
    "loop.repeat_error": ("Runaway loop: repeated errors", "The same error repeated until the loop guard ended the session."),
    "loop.pingpong": ("Runaway loop: ping-pong", "Two calls alternating until the loop guard ended the session."),
    "CONTROL_ERROR": ("Control failed", "A control raised an error; its fail mode decided."),
    "MODEL_DENIED": ("Model denied", "The model is unknown or not in the agent's allowlist."),
    "BUDGET_EXCEEDED": ("Budget exceeded", "A budget refused the request."),
    "AGENT_DENIED": ("Agent denied", "The agent is not known."),
    "tool.not_allowed": ("Tool not allowed for this agent", "The tool is not in the agent's tool list (default deny)."),
    "tool.default": ("Tool arguments rejected", "No allow rule for the tool holds for these arguments (default deny)."),
    "tool.read.ok": ("Read-only SQL", "A SELECT-only query on the database tool is allowed."),
    "tool.notes.ok": ("Notes tools", "The notes server tools are allowed."),
    "tool.deny.destructive": ("Destructive tool", "Dropping or deleting data is never allowed."),
    "tool.mail.internal": ("E-mail to own domain", "Mail to the company domain is allowed."),
    "tool.mail.external": ("E-mail to an outside domain", "Mail outside the company needs a human approval."),
    "tool.shell.deny": ("Shell access", "Running shell commands is not allowed."),
    "tool.fetch.ssrf": ("Fetch of a private address", "A fetch that resolves to a private network address is refused (SSRF)."),
}

_MATRIX = re.compile(r"^matrix\.(public|internal|confidential|restricted)\.(local|external|unknown)$")
_DEST = {"local": "a local model", "external": "an external model", "unknown": "an unknown destination"}


def humanize(rule_id: str) -> str:
    """Readable fallback for an id nobody named: 'tool.mail.external' -> 'Tool mail external'."""
    words = re.sub(r"[._-]+", " ", str(rule_id or "")).strip()
    return words[:1].upper() + words[1:] if words else "-"


def _from_rules(rules: Iterable[Any]) -> dict[str, tuple[str, str]]:
    out = {}
    for r in rules or []:
        rid = getattr(r, "id", None)
        if not rid:
            continue
        cat = str(getattr(r, "category", "") or "").replace("_", " ")
        sev = str(getattr(r, "severity", "") or "")
        name = getattr(r, "name", "") or humanize(rid)
        scope = "tool call arguments" if getattr(r, "scope", "all") == "tool_args" else "text"
        out[rid] = (name, f"{cat} rule on {scope}, severity {sev}".strip(", "))
    return out


def _from_policy_tools(policy_raw: dict[str, Any] | None) -> dict[str, tuple[str, str]]:
    rules = (((policy_raw or {}).get("controls") or {}).get("TOOL-01") or {}).get("rules") or []
    out = {}
    for r in rules:
        if isinstance(r, dict) and r.get("id"):
            tool = r.get("tool", "*")
            act = str(r.get("action", "")).upper()
            known = RULES.get(r["id"])
            out[r["id"]] = known or (humanize(r["id"]), f"{act or 'rule'} for tool {tool}" + (f": {r['reason']}" if r.get("reason") else ""))
    return out


class Catalog:
    """Names for controls and rules. policy: anything with `.rules` and `.raw` (the w2 Policy), or None."""

    def __init__(self, policy: Any = None) -> None:
        self.rules: dict[str, tuple[str, str]] = {}
        self.rules.update(RULES)
        self.rules.update(_from_policy_tools(getattr(policy, "raw", None)))
        self.rules.update(_from_rules(getattr(policy, "rules", None)))
        self.controls = dict(CONTROLS)
        for cid in (((getattr(policy, "raw", None) or {}).get("controls")) or {}):
            self.controls.setdefault(cid, (humanize(cid), "Control from the policy."))

    def control(self, cid: str) -> dict[str, str]:
        name, desc = self.controls.get(cid) or (humanize(cid), "Control from the policy.")
        return {"id": cid, "name": name, "description": desc, "layer": layer_of(cid)}

    def rule(self, rid: str, cid: str = "") -> dict[str, str]:
        hit = self.rules.get(rid)
        if hit is None:
            m = _MATRIX.match(str(rid))
            if m:
                hit = (f"{m.group(1).capitalize()} data to {_DEST[m.group(2)]}",
                       f"Destination matrix: {m.group(1)} data going to {_DEST[m.group(2)]}.")
        if hit is None:
            hit = (humanize(rid), "Rule from the policy.")
        return {"id": rid, "name": hit[0], "description": hit[1], "control": cid, "layer": layer_of(cid)}

    def as_dict(self) -> dict[str, Any]:
        matrix = [f"matrix.{lvl}.{dest}" for lvl in ("public", "internal", "confidential", "restricted") for dest in _DEST]
        return {"controls": {c: self.control(c) for c in self.controls},
                "rules": {r: self.rule(r) for r in [*self.rules, *matrix]}}


def layer_of(control_id: str | None) -> str:
    return AI if control_id in AI_CONTROLS else DETERMINISTIC


# ---- detection layer of an audit record ------------------------------------------------------------

def _rank(v: Any) -> int:
    names = ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"]
    if isinstance(v, bool) or v is None:
        return 0
    if isinstance(v, int):
        return v if 0 <= v < 5 else 0
    return names.index(str(v).upper()) if str(v).upper() in names else 0


def _shadow(rec: dict) -> set[tuple[str, str]]:
    out = set()
    for line in rec.get("explain") or []:
        line = str(line)
        if line.endswith("(shadow: not enforced)") and " rule " in line:
            cid, rest = line.split(" rule ", 1)
            out.add((cid, rest.split(":", 1)[0]))
    return out


def record_layer(rec: dict) -> str | None:
    """Who decided this record: the layer of the enforced finding(s) at the record's action. Deterministic wins
    a tie (it ran first and cost nothing). None = nothing was flagged (a clean request)."""
    shadow = _shadow(rec)
    fs = [f for f in rec.get("findings") or [] if isinstance(f, dict) and (f.get("control_id"), f.get("rule_id")) not in shadow]
    if not fs:
        return DETERMINISTIC if _rank(rec.get("decision")) >= 2 else None   # gateway governors (model allowlist, ledger)
    top = max(_rank(f.get("action")) for f in fs)
    if top == 0:
        return None
    layers = {layer_of(f.get("control_id")) for f in fs if _rank(f.get("action")) == top}
    return DETERMINISTIC if DETERMINISTIC in layers else AI


def enrich(rec: dict) -> dict:
    """Add detection_layer to the record (in place; the audit file stays contract-pure). Findings stay untouched:
    Finding forbids extra keys and the explain drawer validates them; a finding's layer is layer_of(control_id)."""
    rec["detection_layer"] = record_layer(rec)
    return rec

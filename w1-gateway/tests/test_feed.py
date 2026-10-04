"""Signed attack-signature feed: verified, no rollback, self-testing, atomically activated, live in decide()."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aicl_contracts import Event, Part, Stage, ToolCall
from aicl_core.engine import Engine
from aicl_gateway import feed as F

ROOT = Path(__file__).resolve().parents[2]
RULES = r"""version: aicl-rules/1
rules:
  - id: FEED-2026-001
    name: npm install of a typosquatted package from the advisory
    category: tool_abuse
    severity: high
    scope: tool_args
    pattern: '\bnpm\s+(i|install)\b[^\n]*\b(crossenv|electorn|discordi\.js)\b'
    action_untrusted: BLOCK
    action_user: LOG
    match: ['command=npm install crossenv']
    no_match: ['command=npm install cross-env']
"""


@pytest.fixture
def rig(tmp_path):
    shutil.copytree(ROOT / "policy", tmp_path / "policy")
    key = Ed25519PrivateKey.generate()
    pub = F.public_b64(key)
    served = {}
    eng = Engine(tmp_path / "policy" / "policy.yaml")
    poller = F.FeedPoller("https://feed.example/bundle.json", pub, tmp_path / "policy" / "policy.yaml", eng,
                          fetch=lambda url: json.dumps(served["b"]).encode())
    return key, served, poller, eng, tmp_path


def npm(eng):
    return eng.decide(Event(stage=Stage.TOOL_ARGS, agent_id="claude-code",
                            tool_calls=[ToolCall(name="Bash", arguments={"command": "npm install crossenv"})]))


def test_signed_bundle_is_applied_and_enforced_at_once(rig):
    key, served, poller, eng, tmp = rig
    assert npm(eng).action.name == "ALLOW"
    served["b"] = F.sign(RULES, key, 1)
    assert poller.poll_once() == "applied"
    d = npm(eng)
    assert d.action.name == "BLOCK" and any(f.rule_id == "FEED-2026-001" and f.rule_source == "feed" for f in d.findings)
    assert poller.status["version"] == 1 and poller.poll_once() == "unchanged"


def test_tampered_bundle_is_rejected_and_rules_stay(rig):
    key, served, poller, eng, tmp = rig
    b = F.sign(RULES, key, 1)
    b["rules_yaml"] = b["rules_yaml"].replace("BLOCK", "LOG")
    served["b"] = b
    assert poller.poll_once().startswith("rejected: signature")
    assert not (tmp / "policy" / "rules" / "feed.yaml").exists()


def test_bundle_signed_by_another_key_is_rejected(rig):
    key, served, poller, eng, tmp = rig
    served["b"] = F.sign(RULES, Ed25519PrivateKey.generate(), 1)
    assert poller.poll_once().startswith("rejected")


def test_rollback_to_an_older_version_is_ignored(rig):
    key, served, poller, eng, tmp = rig
    served["b"] = F.sign(RULES, key, 5)
    assert poller.poll_once() == "applied"
    served["b"] = F.sign(RULES.replace("crossenv|", ""), key, 4)
    assert poller.poll_once() == "unchanged" and npm(eng).action.name == "BLOCK"


def test_a_rule_failing_its_own_inline_test_never_goes_live(rig):
    key, served, poller, eng, tmp = rig
    served["b"] = F.sign(RULES.replace("match: ['command=npm install crossenv']", "match: ['command=npm ci']"), key, 1)
    assert "inline test" in poller.poll_once()
    assert not (tmp / "policy" / "rules" / "feed.yaml").exists() and npm(eng).action.name == "ALLOW"


def test_unsigned_feed_configuration_is_refused():
    with pytest.raises(ValueError, match="unsigned"):
        F.from_env({"AICL_FEED_URL": "https://feed.example/b.json"}, "policy/policy.yaml", None)


def test_publisher_cli_keygen_and_sign(tmp_path, capsys):
    rules = tmp_path / "r.yaml"
    rules.write_text(RULES, encoding="utf-8")
    assert F.main(["keygen", str(tmp_path / "k.pem")]) == 0
    pub = capsys.readouterr().out.strip()
    assert F.main(["sign", str(rules), str(tmp_path / "k.pem"), "3"]) == 0
    bundle = json.loads(capsys.readouterr().out)
    assert F.verify(bundle, pub) == (3, RULES)

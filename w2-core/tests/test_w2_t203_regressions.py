"""T-203 review regressions: server-name spoofing, SQL quote tricks, SSRF address forms, recipient lists,
argv lists, rule scope false positives, model-registry bypasses, `when` typos, flag / case variants."""
import pytest

from aicl_contracts import Action, Event, Stage, ToolCall
from aicl_core import PolicyError, load_policy
from aicl_core.controls.tools import sql_select_only, url_is_private


def call(engine, name, args, agent="analyst-agent", tools=None, server=None):
    pol = engine.policy.derive({"agents": {agent: {"tools": tools}}}) if tools is not None else engine.policy
    e = Event(stage=Stage.TOOL_ARGS, agent_id=agent, tool_calls=[ToolCall(name=name, arguments=args, server=server)])
    return engine.decide(e, policy=pol)


def tool_rules(d):
    return {f.rule_id for f in d.findings if f.control_id == "TOOL-01"}


@pytest.mark.parametrize("name", ["notes.add", "corp.read_database"])
def test_mcp_server_cannot_borrow_another_servers_name(engine, name):
    d = call(engine, name, {"query": "SELECT 1"}, agent="support-bot", server="evil")
    assert d.action == Action.BLOCK and "tool.not_allowed" in tool_rules(d)
    assert call(engine, "notes.add", {"a": 1}, agent="support-bot", server="notes").action == Action.ALLOW


@pytest.mark.parametrize("q", ["SELECT '/*', 1; DROP TABLE t; -- */", "SELECT '--', 1; DROP TABLE t",
                               "SELECT * INTO backup FROM users", "SELECT 1 INTO DUMPFILE '/tmp/x'",
                               "SELECT lo_export(1, '/tmp/x')", "SELECT 'unbalanced", "SELECT 1 /* open"])
def test_sql_tricks_rejected(q):
    assert not sql_select_only(q)


@pytest.mark.parametrize("q", ["SELECT name FROM t WHERE note = 'a; b -- c'", "SELECT 'it''s' AS x"])
def test_sql_literals_with_markers_still_allowed(q):
    assert sql_select_only(q)


@pytest.mark.parametrize("url", ["http://0177.0.0.1/", "http://127.1/", "http://0x7f.1/",
                                 "http://" + "".join(chr(0xFF10 + int(c)) if c.isdigit() else c for c in "127.0.0.1") + "/",
                                 "http://127.0.0.1\\@evil.example/", "http://10.0.0.1.nip.io/", "http://x.sslip.io/"])
def test_ssrf_address_forms_private(url):
    assert url_is_private(url)


def test_public_hosts_stay_public():
    assert not url_is_private("https://cafe.example/menu") and not url_is_private("https://docs.corp.example/")


@pytest.mark.parametrize("args", [
    {"to": "x@evil.example cfo@corp.example"},
    {"to": "cfo@corp.example\nx@evil.example"},
    {"to": "cfo@corp.example", "bcc": "x@evil.example"},
    {"to": "cfo@corp.example", "cc": ["ok@corp.example", "x@evil.example"]},
])
def test_external_recipient_anywhere_needs_approval(engine, args):
    d = call(engine, "corp.send_email", args, agent="mailer-agent")
    assert d.action == Action.BLOCK and "tool.mail.external" in tool_rules(d)


def test_internal_only_recipients_allowed(engine):
    d = call(engine, "corp.send_email", {"to": "a@corp.example, b@corp.example", "cc": "c@corp.example"},
             agent="mailer-agent")
    assert "tool.mail.external" not in tool_rules(d) and d.action < Action.BLOCK


def test_argv_list_is_checked_as_a_command(engine):
    d = call(engine, "shell.exec", {"argv": ["rm", "-rf", "/"]}, tools=["shell.*"])
    assert d.action == Action.BLOCK and "TOOL-ARG-001" in tool_rules(d)


@pytest.mark.parametrize("args", [{"source": "https://docs.corp.example/handbook"}, {"name": "github.com/acme/repo"},
                                  {"path": "exports/data.bin"}])
def test_model_rules_do_not_fire_on_other_tools(engine, args):
    assert call(engine, "notes.add", args, agent="support-bot").action == Action.ALLOW


@pytest.mark.parametrize("name", ["evil.example:5000/acme/llm", "203.0.113.5/acme/llm",
                                  "https://hf.co@evil.example/acme/llm", "evil.example/acme/llm"])
def test_foreign_model_pull_variants_blocked(engine, name):
    d = call(engine, "ollama.pull", {"name": name}, tools=["ollama.*"])
    assert d.action == Action.BLOCK and "TOOL-ARG-003" in tool_rules(d)


def test_pickle_model_file_blocked_for_model_tools(engine):
    d = call(engine, "model.download", {"repo": "hf.co/acme/x", "file": "pytorch_model.bin"}, tools=["model.*"])
    assert d.action == Action.BLOCK and "TOOL-ARG-002" in tool_rules(d)


def test_when_operator_typo_rejects_reload(policy_dir):
    (policy_dir.parent / "local.d" / "60-typo.yaml").write_text(
        "controls:\n  TOOL-01:\n    rules:\n      - {id: x, tool: web.fetch, action: BLOCK, "
        "when: {args.url: {resolves_to_privat: true}}}\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="unknown operator"):
        load_policy(policy_dir)


def test_mixed_rm_flags_truthy_bool_and_case(engine):
    assert "TOOL-ARG-001" in tool_rules(call(engine, "shell.exec", {"command": "rm -r --force /"}, tools=["shell.*"]))
    assert "HIST-007" in tool_rules(call(engine, "model.load", {"trust_remote_code": 1}, tools=["model.*"]))
    d = call(engine, "corp.Run_Shell", {"command": "id"}, tools=["corp.*"])
    assert d.action == Action.BLOCK and "tool.shell.deny" in tool_rules(d)

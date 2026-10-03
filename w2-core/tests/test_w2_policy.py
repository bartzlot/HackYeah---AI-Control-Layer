import time

import pytest

from aicl_core.policy import PolicyError, PolicyStore, load_policy, to_action
from aicl_contracts import Action


def test_loads_repo_policy_and_reads_off_as_string(policy_dir):
    text = policy_dir.read_text(encoding="utf-8").replace("BUD-01: {mode: enforce", "BUD-01: {mode: off")
    policy_dir.write_text(text, encoding="utf-8")
    pol = load_policy(policy_dir)
    assert pol.mode_for("BUD-01", "balanced") == "off"          # YAML 1.2: bare off is a string, not False
    assert pol.mode_for("INJ-04", "permissive") == "shadow"     # per-profile mode map
    assert pol.mode_for("NOPE-99", "balanced") == "off"         # absent control does not run
    assert len(pol.version) == 64 and pol.rules


def test_version_is_stable_and_changes_with_content(policy_dir):
    v1, v2 = load_policy(policy_dir).version, load_policy(policy_dir).version
    assert v1 == v2
    policy_dir.write_text(policy_dir.read_text(encoding="utf-8").replace("max_body_kb: 512", "max_body_kb: 256"),
                          encoding="utf-8")
    assert load_policy(policy_dir).version != v1


def test_comment_only_edit_keeps_version(policy_dir):
    v1 = load_policy(policy_dir).version
    policy_dir.write_text(policy_dir.read_text(encoding="utf-8") + "\n# just a comment\n", encoding="utf-8")
    assert load_policy(policy_dir).version == v1


@pytest.mark.parametrize("bad, msg", [
    ("controls: [unterminated", None),
    ("defaults: {profile: extreme}", "unknown"),
    ("destination_matrix: {public: {local: MAYBE}}", "bad action"),
    ("controls: {DLP-01: {mode: sometimes}}", "enforce|shadow|off"),
])
def test_invalid_overlay_rejected(policy_dir, bad, msg):
    (policy_dir.parent / "local.d" / "50-bad.yaml").write_text(bad + "\n", encoding="utf-8")
    with pytest.raises(PolicyError, match=msg):
        load_policy(policy_dir)


def test_local_d_overlay_merges(policy_dir):
    (policy_dir.parent / "local.d" / "10-demo.yaml").write_text("controls: {DLP-01: {mode: shadow}}\n", encoding="utf-8")
    pol = load_policy(policy_dir)
    assert pol.mode_for("DLP-01", "balanced") == "shadow"
    assert pol.control("DLP-01")["action"]["tool_args"] == "BLOCK"   # rest of the block kept


def test_rule_inline_tests_gate_the_rule_file(policy_dir):
    rf = policy_dir.parent / "rules" / "historical.yaml"
    rf.write_text(rf.read_text(encoding="utf-8").replace("no_match: ['ast.literal_eval(text)'",
                                                         "no_match: ['eval(input())'"), encoding="utf-8")
    with pytest.raises(PolicyError, match="must not match"):
        load_policy(policy_dir)


def test_store_keeps_last_good_and_recovers(policy_dir):
    store = PolicyStore(policy_dir, interval=0.05)
    good = store.current.version
    original = policy_dir.read_text(encoding="utf-8")
    policy_dir.write_text("controls: [unterminated\n", encoding="utf-8")
    assert store.refresh(force=True) is False
    assert store.current.version == good and store.error
    policy_dir.write_text(original.replace("max_body_kb: 512", "max_body_kb: 128"), encoding="utf-8")
    assert store.refresh(force=True) is True
    assert store.error is None and store.current.version != good


def test_polling_reload_within_two_seconds(policy_dir):
    store = PolicyStore(policy_dir, interval=0.05).start()
    seen = []
    store.on_change.append(lambda p: seen.append(p.version))
    try:
        old = store.current.version
        policy_dir.write_text(policy_dir.read_text(encoding="utf-8").replace("mode: enforce              # enforce",
                                                                             "mode: shadow               # enforce"),
                              encoding="utf-8")
        deadline = time.monotonic() + 2.0
        while store.current.version == old and time.monotonic() < deadline:
            time.sleep(0.02)
        assert store.current.version != old and seen == [store.current.version]
        assert store.current.raw["defaults"]["mode"] == "shadow"
    finally:
        store.stop()


def test_require_approval_maps_to_block():
    assert to_action("REQUIRE_APPROVAL") == (Action.BLOCK, True)
    assert to_action("redact") == (Action.REDACT, False)

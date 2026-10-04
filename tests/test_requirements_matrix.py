"""Traceability: tests/requirements.yaml maps every requirement of the CRIETRIA PDF to tests; this proves the map
is real (each referenced test or case exists), complete (every brief requirement is listed) and balanced (control
requirements carry both allowed and blocked evidence). Plus the documentation checks the map points to."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REQ = yaml.safe_load((ROOT / "tests" / "requirements.yaml").read_text(encoding="utf-8"))
CASE_DIRS = [ROOT / "w2-core" / "cases", ROOT / "w1-gateway" / "cases"]


def _case_kinds() -> dict[tuple[str, str], str]:
    out = {}
    for d in CASE_DIRS:
        for f in d.glob("*.yaml"):
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            for c in doc.get("cases") or []:
                out[(doc["control"], str(c["id"]))] = c.get("kind")
    return out


CASES = _case_kinds()
EVIDENCE = [(r["id"], e) for r in REQ["requirements"] for e in r["evidence"]]


@pytest.mark.parametrize("rid, ev", EVIDENCE, ids=[f"{r}-{e['t'].split('::')[-1][:40]}" for r, e in EVIDENCE])
def test_every_referenced_test_exists(rid, ev):
    t = ev["t"]
    assert ev["kind"] in ("pos", "neg", "live"), t
    if t.startswith("case:"):
        _, control, cid = t.split(":", 2)
        assert (control, cid) in CASES, f"{rid}: case {control}/{cid} not found"
        want = {"pos": "positive", "neg": "negative"}.get(ev["kind"])
        assert want is None or CASES[(control, cid)] == want, f"{rid}: {t} is {CASES[(control, cid)]}"
        return
    path, _, func = t.partition("::")
    src = (ROOT / path).read_text(encoding="utf-8")
    assert re.search(rf"^(async )?def {re.escape(func)}\(", src, re.M), f"{rid}: {t} not found"
    assert (ev["kind"] == "live") == path.startswith("tests/live/"), f"{rid}: live evidence must live in tests/live"


def test_every_brief_requirement_is_traced():
    ids = {r["id"] for r in REQ["requirements"]}
    need = {"R-3.1", "R-3.1b", "R-3.2", "R-3.3", "R-3.4", "R-4.1", "R-4.2.1", "R-4.2.2", "R-4.3", "R-4.4", "R-4.5",
            "R-4.6", "R-6.1", "R-6.2", "R-6.3", "R-8.1"}
    assert need <= ids
    brief = (ROOT / "research" / "brief.md").read_text(encoding="utf-8")
    for sec in ("## 3. Expected Outcome", "## 4. Formal Requirements", "## 6. Testing", "## 8. Evaluation Criteria"):
        assert sec in brief


@pytest.mark.parametrize("req", [r for r in REQ["requirements"] if r.get("control")], ids=lambda r: r["id"])
def test_control_requirements_have_allowed_and_blocked_evidence(req):
    kinds = {e["kind"] for e in req["evidence"]}
    assert {"pos", "neg"} <= kinds, f"{req['id']} needs both an allowed and a blocked / rejected test"


def test_known_gaps_are_stated():
    assert REQ.get("known_gaps"), "be explicit about what is not covered"


# ---- documentation evidence -------------------------------------------------------------------

def test_readme_has_an_architecture_diagram():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "```mermaid" in readme and "flowchart" in readme and "decide()" in readme


def test_policy_is_documented_with_profiles_and_budgets():
    pol = yaml.safe_load((ROOT / "policy" / "policy.yaml").read_text(encoding="utf-8"))
    assert {"strict", "balanced", "permissive"} <= set(pol["profiles"])
    assert pol["budgets"]["agents"] and pol["budgets"]["org"]
    doc = (ROOT / "policy" / "README.md").read_text(encoding="utf-8")
    assert "Live editing" in doc and "interception" in doc


def test_performance_telemetry_is_reproducible():
    bench = (ROOT / "scripts" / "bench.py").read_text(encoding="utf-8")
    assert "server-timing" in bench and "reports" in bench
    assert "bench:" in (ROOT / "Makefile").read_text(encoding="utf-8")


def test_verify_report_fails_on_any_failed_test(tmp_path, monkeypatch):
    """verify.py must never say PASS when a junit file holds a failure, mapped to a requirement or not."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("verify", ROOT / "scripts" / "verify.py")
    v = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v)
    rep = tmp_path / "reports"
    rep.mkdir()
    (rep / "junit-offline.xml").write_text(
        '<testsuites><testsuite><testcase classname="tests.test_x" name="test_unmapped"><failure/></testcase>'
        '</testsuite></testsuites>', encoding="utf-8")
    monkeypatch.setattr(v, "REPORTS", rep)
    monkeypatch.setattr(v.sys, "argv", ["verify.py", "--report"])
    assert v.main() == 1
    assert "ATTENTION NEEDED" in (rep / "requirements_report.md").read_text(encoding="utf-8")

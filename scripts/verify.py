"""Run the test suites and report, requirement by requirement, whether the CRIETRIA PDF is met.

    make verify            offline suite only (852+ tests, no network, about 30 s)
    python scripts/verify.py --report    rebuild the report from the junit files already in reports/
    make verify-live       + live suites: console UI in Chrome, Claude Code base URL, Claude Code transparent,
                             Codex CLI (each skips itself when its prerequisites are not running)
Writes reports/junit-*.xml and reports/requirements_report.md (from tests/requirements.yaml).
"""
from __future__ import annotations

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
LIVE = ["tests/live/test_live_console_ui.py", "tests/live/test_live_claude_code.py",
        "tests/live/test_live_transparent.py", "tests/live/test_live_codex.py"]


def run(args: list[str], junit: Path) -> int:
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={junit}", *args]
    print("$", " ".join(cmd[2:]), flush=True)
    return subprocess.run(cmd, cwd=ROOT, env=os.environ.copy()).returncode


def results(junits: list[Path]) -> dict[tuple[str, str], str]:
    """(module stem, test name incl. params) -> passed | failed | skipped."""
    out: dict[tuple[str, str], str] = {}
    for j in junits:
        if not j.exists():
            continue
        for tc in ET.parse(j).getroot().iter("testcase"):
            stem = tc.get("classname", "").split(".")[-1]
            st = "passed"
            if tc.find("failure") is not None or tc.find("error") is not None:
                st = "failed"
            elif tc.find("skipped") is not None:
                st = "skipped"
            out[(stem, tc.get("name", ""))] = st
    return out


def evidence_status(t: str, res: dict) -> str:
    if t.startswith("case:"):
        _, control, cid = t.split(":", 2)
        hits = [s for (stem, name), s in res.items() if stem in ("test_w2_cases", "test_w2_runner", "test_cases")
                and name.endswith(f"[{control}:{cid}]")]
    else:
        path, _, func = t.partition("::")
        stem = Path(path).stem
        hits = [s for (m, name), s in res.items() if m == stem and (name == func or name.startswith(func + "["))]
    if not hits:
        return "not run"
    if "failed" in hits:
        return "failed"
    if all(h == "skipped" for h in hits):
        return "skipped"
    return "passed"


def main() -> int:
    live = "--live" in sys.argv
    report_only = "--report" in sys.argv          # rebuild the report from the junit files already in reports/
    REPORTS.mkdir(exist_ok=True)
    junits = [REPORTS / "junit-offline.xml"]
    rc = 0 if report_only else run([], junits[0])
    if live or report_only:
        for i, mod in enumerate(LIVE):
            j = REPORTS / f"junit-live-{i}.xml"
            junits.append(j)
            if not report_only:
                run(["-m", "live", mod], j)
    live = live or any(j.exists() for j in junits[1:])
    res = results(junits)
    req = yaml.safe_load((ROOT / "tests" / "requirements.yaml").read_text(encoding="utf-8"))
    lines = ["# Requirements report (CRIETRIA PDF -> tests)", "",
             f"Suites: offline{' + live (console UI, Claude Code base URL, Claude Code transparent, Codex CLI)' if live else ''}. "
             f"Test results: {sum(1 for s in res.values() if s == 'passed')} passed, "
             f"{sum(1 for s in res.values() if s == 'failed')} failed, {sum(1 for s in res.values() if s == 'skipped')} skipped.", "",
             "| Requirement | Allowed / works | Blocked / rejected | Live (real CLI / browser) | Verdict |",
             "|---|---|---|---|---|"]
    ok_all = True
    for r in req["requirements"]:
        cell = {"pos": [], "neg": [], "live": []}
        for e in r["evidence"]:
            cell[e["kind"]].append(evidence_status(e["t"], res))
        offline = cell["pos"] + cell["neg"]
        failed = any(s == "failed" for s in offline + cell["live"])
        missing = any(s == "not run" for s in offline)
        verdict = "FAIL" if failed else ("INCOMPLETE" if missing else "PASS")
        ok_all &= verdict == "PASS"

        def fmt(xs):
            if not xs:
                return "-"
            p = sum(1 for x in xs if x == "passed")
            extra = [f"{sum(1 for x in xs if x == k)} {k}" for k in ("failed", "skipped", "not run") if k in xs]
            return f"{p}/{len(xs)} passed" + (f" ({', '.join(extra)})" if extra else "")
        lines.append(f"| {r['id']} {r['pdf']} | {fmt(cell['pos'])} | {fmt(cell['neg'])} | {fmt(cell['live'])} | **{verdict}** |")
    lines += ["", "Known gaps (stated, not hidden):"] + [f"- {g}" for g in req.get("known_gaps") or []]
    lines += ["", f"Overall: **{'ALL REQUIREMENTS PASS' if ok_all and rc == 0 else 'ATTENTION NEEDED'}**"]
    out = REPORTS / "requirements_report.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwritten {out.relative_to(ROOT)}")
    return 0 if ok_all and rc == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

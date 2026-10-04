"""LIVE UI: the console in a real (headless) Chrome driven by puppeteer-core (tests/e2e_ui/console.e2e.js).

Self-contained: starts its own gateway on a free port with a temporary, writable copy of the policy, then the
script clicks through: highlighted policy, an invalid edit rejected with the loader's reason (live policy
unchanged), a valid edit applied with a new version, a budget saved through the inputs, all 9 pages, the
playground showing a decision, and no JS errors.
    cd tests/e2e_ui && npm install      (once)
    uv run pytest -m live tests/live/test_live_console_ui.py -v
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest
import uvicorn

pytestmark = pytest.mark.live

ROOT = Path(__file__).resolve().parents[2]
E2E = ROOT / "tests" / "e2e_ui"
CHROME = os.environ.get("AICL_CHROME") or next((p for p in (
    r"C:\Program Files\Google\Chrome\Application\chrome.exe", "/usr/bin/google-chrome", "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome") if Path(p).exists()), None)

if not (shutil.which("node") and (E2E / "node_modules" / "puppeteer-core").is_dir() and CHROME):
    pytest.skip("live UI: needs node, `npm install` in tests/e2e_ui and Chrome", allow_module_level=True)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def gateway(tmp_path):
    from aicl_core import engine as eng
    from aicl_gateway.main import create_app_from_env
    shutil.copytree(ROOT / "policy", tmp_path / "policy")
    for f in (tmp_path / "policy" / "local.d").glob("*.yaml"):
        f.unlink()
    env = {"AICL_POLICY": str(tmp_path / "policy" / "policy.yaml"), "AICL_DATA_DIR": str(tmp_path / "d"),
           "AICL_AUDIT_PATH": str(tmp_path / "d" / "a.jsonl"), "AICL_BUDGET_DB": str(tmp_path / "d" / "b.db"),
           "AICL_KEY_DEMO": "aicl_ui_test_key_000001"}
    app = create_app_from_env(env, judge_chat=lambda b, t: {}, reload_interval=0.0, start_reload=False)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}", tmp_path
    server.should_exit = True
    th.join(timeout=5)
    eng.REGISTRY.pop("INJ-04", None)


def test_console_ui_end_to_end_in_a_real_browser(gateway):
    url, tmp = gateway
    env = {**os.environ, "AICL_CHROME": CHROME}
    r = subprocess.run(["node", "console.e2e.js", url, str(tmp)], cwd=E2E, env=env, capture_output=True, text=True,
                       timeout=180)
    out = r.stdout + r.stderr
    lines = [ln for ln in out.splitlines() if ln.startswith(("PASS", "FAIL"))]
    assert len(lines) >= 9 and not any(ln.startswith("FAIL") for ln in lines), out

#!/usr/bin/env bash
# w2-core acceptance check. Exit 0 = piece green. Extend with every task (see TASKS.md).
# Offline and deterministic: no Ollama, no network, no paid API.
#   1. per-task acceptance tests: tests/test_w2_t2NN_*.py (one test per item of the TASKS.md line)
#   2. unit tests (policy loader, reload, last-good, engine, redaction, detectors)
#   3. every */cases/*.yaml through decide() (tests/test_w2_cases.py) and through the real gateway over ASGI
#      with the scripted cloud-sim (tests/test_w2_runner.py), routed by the case file `runner:` field
#      (auto / decide / gateway / judge-fake = INJ-04 judge over a fake Ollama); meta-tests per control
#   4. mutation proof: every negative case must FAIL when its own control is switched off (both drivers)
set -euo pipefail
cd "$(dirname "$0")/.."
uv run pytest -q w2-core/tests

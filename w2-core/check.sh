#!/usr/bin/env bash
# w2-core acceptance check. Exit 0 = piece green. Extend with every task (see TASKS.md).
# Offline and deterministic: no Ollama, no network, no paid API.
#   1. unit tests (policy loader, reload, last-good, engine, redaction)
#   2. every */cases/*.yaml through decide()
#   3. mutation proof: every negative case must FAIL when its own control is switched off
set -euo pipefail
cd "$(dirname "$0")/.."
uv run pytest -q w2-core/tests

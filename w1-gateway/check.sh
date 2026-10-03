#!/usr/bin/env bash
# w1-gateway acceptance check. Exit 0 = piece green. Extend with every task (see TASKS.md).
# Offline and deterministic: no Ollama, no network, no paid API.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run pytest -q w1-gateway/tests

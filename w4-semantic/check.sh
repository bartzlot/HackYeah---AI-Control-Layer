#!/usr/bin/env bash
# w4-semantic acceptance check. Exit 0 = piece green. Extend with every task (see TASKS.md).
# Offline and deterministic: no Ollama, no network, no paid API.
set -euo pipefail
cd "$(dirname "$0")"
echo "PHASE=0: w4-semantic has no checks yet"
exit 1

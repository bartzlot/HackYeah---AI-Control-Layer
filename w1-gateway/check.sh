#!/usr/bin/env bash
# w1-gateway acceptance check. Exit 0 = piece green. Extend with every task (see TASKS.md).
# Offline and deterministic: no Ollama, no network, no paid API.
#   test_cloud_sim.py  T-102 priced mock upstream
#   test_gateway.py    T-103 chat completions, router, audit, bus
#   test_console.py    T-105 console: tiles, controls, SSE + explain, playground destinations, exports
#   test_budget.py     T-104 budget ledger + loop guard
#   test_judge.py      T-106 INJ-04 local judge (fake Ollama): gray band, enum schema, timeout -> WARN + degraded
#   test_skeleton.py   T-901 walking skeleton: demo agent -> main.py entrypoint (policy.yaml, w2 engine) -> fakes
#   test_cases.py      cases/*.yaml through the gateway (+ meta: each negative case fails with its control off)
set -euo pipefail
cd "$(dirname "$0")/.."
required="test_cloud_sim.py test_gateway.py test_console.py test_budget.py test_judge.py test_skeleton.py test_cases.py"
for f in $required; do
  [ -f "w1-gateway/tests/$f" ] || { echo "missing w1-gateway/tests/$f" >&2; exit 1; }
done
ls w1-gateway/cases/*.yaml >/dev/null
uv run pytest -q w1-gateway/tests

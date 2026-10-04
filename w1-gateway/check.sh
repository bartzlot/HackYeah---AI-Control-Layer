#!/usr/bin/env bash
# w1-gateway acceptance check. Exit 0 = piece green. Extend with every task (see TASKS.md).
# Offline and deterministic: no Ollama, no network, no paid API.
#   test_cloud_sim.py  T-102 priced mock upstream
#   test_gateway.py    T-103 chat completions, router, audit, bus
#   test_console.py    T-105 console: tiles, controls, SSE + explain, playground destinations, exports
#                      + T-117 summary.top_rules (rule, control, count, last seen) and the judge endpoint
#   test_budget.py     T-104 budget ledger + loop guard
#   test_judge.py      T-106 INJ-04 local judge (fake Ollama): gray band, enum schema, timeout -> WARN + degraded
#                      + T-117 Judge.state() / GET /console/api/judge (idle, warm, degraded, off, p50, cache counters)
#   test_skeleton.py   T-901 walking skeleton: demo agent -> main.py entrypoint (policy.yaml, w2 engine) -> fakes
#   test_cases.py      cases/*.yaml through the gateway (+ meta: each negative case fails with its control off)
#   test_runtime_status.py  T-116 console runtime mode: live listeners, CA, overrides, transparent warnings
#   test_explain.py    T-119 explain drawer: per-request decide() timeline, stage Server-Timing, spans as hashes
#   test_demo_batch.py T-123 demo batch (11 presets, each caught by a different control, offline: fake Ollama + judge),
#                      control / rule display names, detection_layer (deterministic / ai), console batch endpoint + page
#   test_toasts.py     T-132 live event toasts: a demo batch reaches the live stream, page has the toast panel
set -euo pipefail
cd "$(dirname "$0")/.."
required="test_cloud_sim.py test_gateway.py test_console.py test_budget.py test_judge.py test_skeleton.py test_cases.py test_runtime_status.py test_explain.py test_demo_batch.py test_toasts.py"
for f in $required; do
  [ -f "w1-gateway/tests/$f" ] || { echo "missing w1-gateway/tests/$f" >&2; exit 1; }
done
ls w1-gateway/cases/*.yaml >/dev/null
uv run pytest -q w1-gateway/tests

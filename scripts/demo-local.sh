#!/usr/bin/env bash
# Local demo mode (T-010): host Ollama + docker compose gateway and cloud-sim.
# Checks the host Ollama, pulls the model if missing, warms it with the judge context size, starts the stack,
# waits until healthy and smoke-tests /healthz and /console. Never deletes models (Ollama is shared).
set -euo pipefail
cd "$(dirname "$0")/.."
OLLAMA="${AICL_HOST_OLLAMA:-http://127.0.0.1:11434}"
MODEL="${AICL_OLLAMA_MODEL:-qwen3.5:2b-q4_K_M}"
PORT="${AICL_GATEWAY_PORT:-18080}"
F=(-f docker-compose.yml -f docker-compose.local.yml)

curl -fsS -m 5 "$OLLAMA/api/version" >/dev/null || { echo "no Ollama at $OLLAMA (start it, or use make demo)" >&2; exit 1; }
if ! curl -fsS "$OLLAMA/api/tags" | grep -q "\"$MODEL\""; then
  echo "pulling $MODEL into the host Ollama ..."
  curl -fsS "$OLLAMA/api/pull" -d "{\"model\": \"$MODEL\", \"stream\": false}" >/dev/null
fi
curl -fsS -m 300 "$OLLAMA/api/generate" -d "{\"model\": \"$MODEL\", \"keep_alive\": \"24h\", \"options\": {\"num_ctx\": 4096}}" >/dev/null
echo "warm: $MODEL"
docker compose "${F[@]}" up -d --build
for i in $(seq 1 60); do curl -fsS -m 2 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 2; done
curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null && curl -fsS "http://127.0.0.1:$PORT/console" | grep -q "AI Control Layer"
echo "AICL local demo up: http://127.0.0.1:$PORT/console  (demo agent: uv run python -m aicl_gateway.demo_agent)"

#!/usr/bin/env bash
# Transparent interception demo (research/14 s.9): build + start the corp network in miniature, load the
# judge model, and hand the devbox a Claude credential (never written to disk by this script).
#   scripts/demo-transparent.sh            live: real api.anthropic.com
#   AICL_OFFLINE=1 scripts/demo-transparent.sh   offline: local Anthropic mock, no tokens, no network
# Credential order: CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_API_KEY, else the ACCESS token (not the refresh token)
# of the local Claude Code login (~/.claude/.credentials.json), so the container can never rotate it.
set -euo pipefail
cd "$(dirname "$0")/.."
F=(-f docker-compose.transparent.yml)
MODEL="${AICL_OLLAMA_MODEL:-qwen3.5:2b-q4_K_M}"
docker volume inspect aicl-ollama-models >/dev/null 2>&1 || docker volume create aicl-ollama-models >/dev/null

if [ "${AICL_OFFLINE:-0}" = "1" ]; then
  export AICL_UPSTREAM_ANTHROPIC=http://mock-anthropic:18210 CLAUDE_CODE_OAUTH_TOKEN=offline-demo
  F+=(--profile offline)
elif [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  CRED="${HOME}/.claude/.credentials.json"
  if [ -f "$CRED" ]; then
    CLAUDE_CODE_OAUTH_TOKEN="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["claudeAiOauth"]["accessToken"])' "$CRED")"
    export CLAUDE_CODE_OAUTH_TOKEN
  else
    echo "no Claude credential: set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY, or AICL_OFFLINE=1" >&2; exit 1
  fi
fi

docker compose "${F[@]}" up -d --build
docker compose "${F[@]}" exec -T ollama ollama pull "$MODEL" >/dev/null
docker compose "${F[@]}" exec -T ollama sh -c "ollama run $MODEL 'ok' >/dev/null 2>&1 || true"   # warm
echo
echo "AICL transparent demo up. Console: http://127.0.0.1:18080/console"
echo "Developer laptop (no AICL config, DNS = AICL, CA trusted):"
echo "  docker compose -f docker-compose.transparent.yml exec devbox claude -p 'hello' --model claude-haiku-4-5"
echo "  docker compose -f docker-compose.transparent.yml exec devbox bash     # interactive"

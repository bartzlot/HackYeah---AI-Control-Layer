# AICL Makefile (lead). Targets: demo up down logs models warm test deploy
#   v4: demo-transparent demo-transparent-offline live live-transparent bench
SHELL := /bin/bash
GCP_VM ?= aicl-vm
GCP_ZONE ?= europe-central2-a
-include .env
MODEL ?= $(or $(AICL_OLLAMA_MODEL),qwen3.5:2b-q4_K_M)

.PHONY: demo demo-local cloudrun up down logs models warm test deploy sync verify verify-live demo-transparent demo-transparent-offline transparent-down live live-transparent bench

# whole demo stack from zero: build + start, pull the model, load it so the first judge call is warm
demo: up models warm
sync:
	uv sync

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=100

# pull the local model into the compose ollama (AICL_OLLAMA_MODEL, default qwen3.5:2b-q4_K_M); never run from tests
models:
	docker compose up -d ollama
	docker compose --profile models run --rm ollama-pull

# load the model into memory now (keep_alive 24h), from the aicl image on the compose network
warm:
	docker compose run --rm --no-deps cloud-sim python -c 'import json, urllib.request as u; u.urlopen(u.Request("http://ollama:11434/api/generate", json.dumps({"model": "$(MODEL)", "keep_alive": "24h", "options": {"num_ctx": 4096}}).encode(), {"Content-Type": "application/json"}), timeout=900).read(); print("warm: $(MODEL)")'

test: sync
	uv run pytest -q --junitxml=reports/junit.xml

# deploy to the GCP VM (T-902): copy repo, build and start there
deploy:
	gcloud compute scp --recurse --zone $(GCP_ZONE) . $(GCP_VM):~/aicl
	gcloud compute ssh --zone $(GCP_ZONE) $(GCP_VM) --command "cd ~/aicl && docker compose up -d --build"

# ---- v4 transparent interception (research/14) ----
# corp network in miniature: devbox with Claude Code, DNS = AICL, AICL CA trusted, no route around the gateway
demo-transparent:
	bash scripts/demo-transparent.sh
demo-transparent-offline:
	AICL_OFFLINE=1 bash scripts/demo-transparent.sh
transparent-down:
	docker compose -f docker-compose.transparent.yml --profile offline down
# real Claude Code through a running gateway (host: base URL mode / devbox: transparent mode); spends real tokens
live:
	uv run pytest -m live tests/live/test_live_claude_code.py -v
live-transparent:
	uv run pytest -m live tests/live/test_live_transparent.py -v
# performance telemetry: decide() and gateway overhead on Claude Code sized traffic -> reports/bench.json
bench:
	uv run python scripts/bench.py
# requirements traceability: run the suites and write reports/requirements_report.md (PDF requirement -> tests)
verify:
	uv run python scripts/verify.py
verify-live:
	uv run python scripts/verify.py --live
# local demo: gateway + cloud-sim in docker, the model from the Ollama already running on the host (T-010)
demo-local:
	bash scripts/demo-local.sh
# public demo on Cloud Run (T-012): GCP_PROJECT=<project> make cloudrun
cloudrun:
	bash scripts/cloudrun-deploy.sh

# diagram set: docs/diagrams/*.mmd -> *.light.svg + *.dark.svg with mermaid-cli (T-906); needs Node + a Chromium/Edge/Chrome
.PHONY: diagrams
diagrams:
	bash docs/diagrams/render.sh

#!/usr/bin/env bash
# Public AICL demo on Cloud Run (T-012). Needs: gcloud logged in, a project with billing.
#   GCP_PROJECT=my-project [GCP_REGION=europe-central2] scripts/cloudrun-deploy.sh
# Steps: enable APIs, Artifact Registry repo, Cloud Build (gateway + ollama-with-model images), fresh demo key
# and admin token (printed once, never written to the repo), deploy the multi-container service, allow
# unauthenticated invocations, warm the model, print the URL and how to use it.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GCP_PROJECT:?set GCP_PROJECT}"
REGION="${GCP_REGION:-europe-central2}"
REPO="${AICL_AR_REPO:-aicl}"
MODEL="${AICL_OLLAMA_MODEL:-qwen3.5:0.8b}"          # Ollama tag baked into the sidecar (small: CPU only)
POLICY_MODEL="qwen3.5:2b-q4_K_M"                   # the policy's local model tag; the gateway renames it to $MODEL
command -v gcloud >/dev/null || { echo "gcloud CLI not found" >&2; exit 1; }

gcloud config set project "$GCP_PROJECT" >/dev/null
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
gcloud artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "$REPO" --repository-format docker --location "$REGION"
gcloud builds submit --config deploy/cloudrun/cloudbuild.yaml \
  --substitutions "_REGION=$REGION,_REPO=$REPO,_MODEL=$MODEL" .

export AICL_KEY_DEMO="aicl_$(openssl rand -hex 16)"
export AICL_ADMIN_TOKEN="$(openssl rand -hex 24)"
export REGION PROJECT="$GCP_PROJECT" REPO AICL_OLLAMA_MODEL="$MODEL"
tmp="$(mktemp)"
envsubst '${REGION} ${PROJECT} ${REPO} ${AICL_KEY_DEMO} ${AICL_ADMIN_TOKEN} ${AICL_OLLAMA_MODEL}' < deploy/cloudrun/service.yaml > "$tmp"
gcloud run services replace "$tmp" --region "$REGION"
rm -f "$tmp"
gcloud run services add-iam-policy-binding aicl --region "$REGION" --member allUsers --role roles/run.invoker >/dev/null

URL="$(gcloud run services describe aicl --region "$REGION" --format 'value(status.url)')"
for i in $(seq 1 60); do curl -fsS -m 5 "$URL/healthz" >/dev/null 2>&1 && break; sleep 5; done
curl -fsS -m 300 "$URL/v1/chat/completions" -H "Authorization: Bearer $AICL_KEY_DEMO" -H 'Content-Type: application/json' \
  -d "{\"model\": \"$POLICY_MODEL\", \"messages\": [{\"role\": \"user\", \"content\": \"warm up\"}], \"max_tokens\": 8}" >/dev/null || true

cat <<EOT

AICL is live: $URL
  console:      $URL/console        (policy edits need the admin token below)
  demo key:     $AICL_KEY_DEMO
  admin token:  $AICL_ADMIN_TOKEN
  Claude Code:  ANTHROPIC_BASE_URL=$URL claude          (your own key / login, inspected by AICL)
  demo agent:   AICL_KEY_DEMO=$AICL_KEY_DEMO uv run python -m aicl_gateway.demo_agent --url $URL
Keep the two secrets out of chat logs; redeploying generates new ones.
EOT

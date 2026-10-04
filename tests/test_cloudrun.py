"""T-012: Cloud Run deploy artifacts (static checks; the deploy itself needs a GCP project)."""
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SVC = yaml.safe_load((ROOT / "deploy" / "cloudrun" / "service.yaml").read_text(encoding="utf-8"))
TPL = SVC["spec"]["template"]
C = {c["name"]: c for c in TPL["spec"]["containers"]}


def env(c):
    return {e["name"]: e["value"] for e in C[c]["env"]}


def test_one_instance_no_throttling_gen2_long_timeout():
    a = TPL["metadata"]["annotations"]
    assert a["autoscaling.knative.dev/minScale"] == a["autoscaling.knative.dev/maxScale"] == "1"
    assert a["run.googleapis.com/cpu-throttling"] == "false" and a["run.googleapis.com/execution-environment"] == "gen2"
    assert TPL["spec"]["timeoutSeconds"] >= 3600
    assert json.loads(a["run.googleapis.com/container-dependencies"]) == {"gateway": ["cloud-sim", "ollama"]}


def test_gateway_is_the_only_ingress_and_sidecars_share_localhost():
    assert [c for c in C if C[c].get("ports")] == ["gateway"] and C["gateway"]["ports"][0]["containerPort"] == 18080
    e = env("gateway")
    assert e["AICL_OLLAMA_URL"] == "http://localhost:11434" and e["AICL_CLOUDSIM_URL"] == "http://localhost:18200"
    assert env("cloud-sim")["AICL_CLOUDSIM_SCRIPT"] == "demo" and env("cloud-sim")["AICL_CLOUDSIM_PORT"] == "18200"
    assert env("ollama")["OLLAMA_HOST"] == "127.0.0.1:11434"


def test_policy_is_seeded_to_a_writable_path_and_secrets_are_placeholders():
    e = env("gateway")
    assert e["AICL_POLICY"].startswith("/data/") and e["AICL_POLICY_SEED"] == "/app/policy"
    assert e["AICL_CONSOLE_REMOTE"] == "1"
    assert e["AICL_KEY_DEMO"] == "${AICL_KEY_DEMO}" and e["AICL_ADMIN_TOKEN"] == "${AICL_ADMIN_TOKEN}"
    assert {"mountPath": "/data", "name": "data"} in C["gateway"]["volumeMounts"]


def test_build_produces_both_images_with_the_model_baked_in():
    cb = yaml.safe_load((ROOT / "deploy" / "cloudrun" / "cloudbuild.yaml").read_text(encoding="utf-8"))
    assert len(cb["images"]) == 2 and any("aicl-ollama" in i for i in cb["images"])
    assert "ollama pull" in (ROOT / "deploy" / "cloudrun" / "ollama.Dockerfile").read_text(encoding="utf-8")


def test_deploy_script_generates_fresh_secrets_and_opens_the_service():
    s = (ROOT / "scripts" / "cloudrun-deploy.sh").read_text(encoding="utf-8")
    assert "openssl rand" in s and "allUsers" in s and "gcloud run services replace" in s and "envsubst" in s
    assert "AICL_ADMIN_TOKEN=" not in s.replace('export AICL_ADMIN_TOKEN="$(openssl', "")
    assert "cloudrun:" in (ROOT / "Makefile").read_text(encoding="utf-8")

"""T-005 container config: static checks of docker-compose.yml, w1-gateway/Dockerfile, .dockerignore,
.env.example and scripts/task.sh. Offline and deterministic: no docker daemon, no network."""
from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]
DOCKERFILE = (ROOT / "w1-gateway" / "Dockerfile").read_text(encoding="utf-8")
CODE_DIRS = ["w1-gateway/aicl_gateway", "w1-gateway/cloud_sim", "w2-core/aicl_core", "contracts"]


def interpolate(s: str) -> str:
    """Compose `${VAR:-default}` with an empty environment = the defaults."""
    return re.sub(r"\$\{[A-Z0-9_]+:-([^}]*)\}", r"\1", s)


def published(service: str) -> list[str]:
    return [interpolate(p) for p in SERVICES[service].get("ports", [])]


# ---- compose ----

@pytest.mark.parametrize("service", ["gateway", "cloud-sim", "ollama"])
def test_ports_are_host_only_by_default(service):
    ports = published(service)
    assert ports, f"{service} publishes no port"
    for p in ports:
        assert p.startswith("127.0.0.1:"), f"{service} publishes {p} beyond loopback"


def test_gateway_bind_is_configurable_for_the_vm():
    assert "${AICL_GATEWAY_BIND:-127.0.0.1}" in SERVICES["gateway"]["ports"][0]


@pytest.mark.parametrize("service", ["gateway", "cloud-sim", "ollama"])
def test_healthchecks(service):
    hc = SERVICES[service].get("healthcheck")
    assert hc and hc.get("test"), f"{service} has no healthcheck"


def test_gateway_and_cloudsim_share_one_image():
    gw, cs = SERVICES["gateway"], SERVICES["cloud-sim"]
    assert gw["build"]["dockerfile"] == cs["build"]["dockerfile"] == "w1-gateway/Dockerfile"
    assert gw["image"] == cs["image"]
    assert cs["command"] == ["python", "-m", "cloud_sim"]


def test_gateway_waits_for_healthy_cloudsim_but_not_for_a_model():
    deps = SERVICES["gateway"]["depends_on"]
    assert deps["cloud-sim"]["condition"] == "service_healthy"
    assert deps["ollama"]["condition"] == "service_started"


def test_gateway_environment_uses_service_names_and_container_paths():
    env = SERVICES["gateway"]["environment"]
    assert env["AICL_OLLAMA_URL"] == "http://ollama:11434"
    assert env["AICL_CLOUDSIM_URL"] == "http://cloud-sim:18200"
    assert env["AICL_CONSOLE_REMOTE"] == "1"   # safe only because the port mapping is host-only
    for k in ("AICL_DATA_DIR", "AICL_AUDIT_PATH", "AICL_BUDGET_DB"):
        assert env[k].startswith("/app/data"), k


def test_volumes_policy_read_only_and_data_persistent():
    vols = SERVICES["gateway"]["volumes"]
    assert "./policy:/app/policy:ro" in vols
    assert "gateway-data:/app/data" in vols
    assert {"gateway-data", "ollama-models"} <= set(COMPOSE["volumes"])


def test_model_pull_is_opt_in():
    pull = SERVICES["ollama-pull"]
    assert pull["profiles"] == ["models"]
    assert pull["restart"] == "no"
    assert "ollama-pull" not in SERVICES["gateway"].get("depends_on", {})
    for name, svc in SERVICES.items():
        if name != "ollama-pull":
            assert "profiles" not in svc, f"{name} would not start with plain `docker compose up`"


def test_no_privileged_or_host_network():
    for name, svc in SERVICES.items():
        assert not svc.get("privileged"), name
        assert svc.get("network_mode") != "host", name


# ---- Dockerfile ----

def test_dockerfile_runs_as_non_root():
    users = re.findall(r"^USER\s+(\S+)", DOCKERFILE, re.M)
    assert users and users[-1] not in ("root", "0")


def test_dockerfile_pins_uv_and_uses_the_lock():
    m = re.search(r"ghcr\.io/astral-sh/uv:(\S+)", DOCKERFILE)
    assert m and re.fullmatch(r"\d+\.\d+\.\d+", m.group(1)), "uv image must be pinned to a version"
    assert "uv.lock" in DOCKERFILE
    assert DOCKERFILE.count("--frozen") >= 2 and "--no-dev" in DOCKERFILE


def test_dockerfile_copies_every_workspace_member():
    members = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["uv"]["workspace"]["members"]
    for m in members:
        assert re.search(rf"^COPY {re.escape(m)}/pyproject\.toml ", DOCKERFILE, re.M), f"{m} manifest not copied"
        assert re.search(rf"^COPY {re.escape(m)} {re.escape(m)}$", DOCKERFILE, re.M), f"{m} sources not copied"


def test_dockerfile_serves_the_gateway_on_its_port():
    assert "aicl_gateway.app:create_app" in DOCKERFILE and '"18080"' in DOCKERFILE
    assert "/healthz" in str(SERVICES["gateway"]["healthcheck"]["test"])


# ---- .dockerignore ----

def test_dockerignore_keeps_secrets_and_venv_out_but_the_lock_in():
    lines = {ln.strip() for ln in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines() if ln.strip()}
    assert {".env", ".venv", ".git", "data"} <= lines
    assert not lines & {"uv.lock", "pyproject.toml", "policy", "contracts", "w1-gateway", "w2-core"}


# ---- .env.example ----

def env_example() -> dict[str, str]:
    out = {}
    for ln in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        if ln.strip() and not ln.lstrip().startswith("#"):
            k, _, v = ln.partition("=")
            out[k.strip()] = v.strip()
    return out


def test_env_example_documents_every_variable_the_code_reads():
    used = set()
    for d in CODE_DIRS:
        for f in (ROOT / d).rglob("*.py"):
            used |= set(re.findall(r"AICL_[A-Z0-9_]+", f.read_text(encoding="utf-8")))
    missing = used - set(env_example())
    assert not missing, f"undocumented in .env.example: {sorted(missing)}"


def test_env_example_has_only_synthetic_values():
    for k, v in env_example().items():
        assert k.startswith("AICL_"), k
        assert not re.search(r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-(proj|ant)-)", v), k


def test_env_example_defaults_match_compose():
    env = env_example()
    assert env["AICL_GATEWAY_BIND"] == "127.0.0.1"
    assert env["AICL_GATEWAY_PORT"] == "18080"
    assert env["AICL_OLLAMA_MODEL"] in SERVICES["ollama-pull"]["command"][0]


# ---- scripts/task.sh ----

def test_task_sh_hostname_falls_back_when_short_flag_is_missing():
    assert "$(hostname -s 2>/dev/null || hostname)" in (ROOT / "scripts" / "task.sh").read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
def test_task_sh_parses():
    r = subprocess.run(["bash", "-n", "scripts/task.sh"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

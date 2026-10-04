"""T-005 container config: static checks of docker-compose.yml, w1-gateway/Dockerfile, .dockerignore,
.env.example and scripts/task.sh. Offline and deterministic: no docker daemon, no network."""
from __future__ import annotations

import importlib
import json
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
PIECES = ["contracts", "w1-gateway", "w2-core", "w3-detect", "w4-semantic", "w5-console"]


def code_files():
    """Shipped Python of every piece (tests excluded), so variables added later by any piece are covered."""
    for piece in PIECES:
        for f in (ROOT / piece).rglob("*.py"):
            if not {"tests", ".venv", "__pycache__"} & set(f.relative_to(ROOT).parts):
                yield f


def interpolate(s: str) -> str:
    """Compose `${VAR:-default}` with an empty environment = the defaults."""
    return re.sub(r"\$\{[A-Z0-9_]+:-([^}]*)\}", r"\1", s)


def published(service: str) -> list[str]:
    return [interpolate(p) for p in SERVICES[service].get("ports", [])]


# ---- compose ----

@pytest.mark.parametrize("service", ["gateway", "cloud-sim", "ollama"])
def test_core_services_publish_a_port(service):
    assert published(service), f"{service} publishes no port"


@pytest.mark.parametrize("service", sorted(SERVICES))
def test_every_published_port_is_host_only_by_default(service):
    for p in published(service):
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


def test_volumes_policy_writable_for_the_console_and_data_persistent():
    vols = SERVICES["gateway"]["volumes"]
    assert "./policy:/app/policy" in vols                     # the console editor writes it (T-107, admin token)
    assert SERVICES["gateway"]["environment"]["AICL_ADMIN_TOKEN"] == "${AICL_ADMIN_TOKEN:-}"
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


def dockerfile_cmd() -> list[str]:
    cmds = re.findall(r"^CMD (\[.*\])$", DOCKERFILE, re.M)
    assert len(cmds) == 1, "exactly one exec-form CMD"
    return json.loads(cmds[0])


def test_dockerfile_serves_the_gateway_on_its_port():
    cmd = dockerfile_cmd()
    assert cmd[0] == "uvicorn" and "--factory" in cmd
    assert cmd[cmd.index("--port") + 1] == "18080" and cmd[cmd.index("--host") + 1] == "0.0.0.0"
    assert "/healthz" in str(SERVICES["gateway"]["healthcheck"]["test"])


def test_dockerfile_cmd_is_the_policy_driven_entrypoint():
    """T-009: the bare create_app() has no agents (every request 401); the image must serve the T-901 factory."""
    cmd = dockerfile_cmd()
    target = cmd[cmd.index("--factory") + 1]
    assert target == "aicl_gateway.main:create_app_from_env"
    assert "aicl_gateway.app:create_app" not in DOCKERFILE
    assert "--workers" not in cmd or cmd[cmd.index("--workers") + 1] == "1", "budget reservations are per process"


def test_dockerfile_factory_resolves():
    cmd = dockerfile_cmd()
    module, attr = cmd[cmd.index("--factory") + 1].split(":")
    assert callable(getattr(importlib.import_module(module), attr))


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
    for f in code_files():
        # a name ending in "_" is a prefix (f"AICL_KEY_{name}"), not a variable
        used |= set(re.findall(r"AICL_[A-Z0-9_]*[A-Z0-9]\b", f.read_text(encoding="utf-8")))
    assert used, "scan found no AICL_* variables at all"
    missing = used - set(env_example())
    assert not missing, f"undocumented in .env.example: {sorted(missing)}"


def test_env_example_has_only_synthetic_values():
    for k, v in env_example().items():
        assert k.startswith("AICL_"), k
        assert not re.search(r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-(proj|ant)-)", v), k


def test_env_example_defaults_match_compose():
    env = env_example()
    bind, port, _ = published("gateway")[0].split(":")
    assert env["AICL_GATEWAY_BIND"] == bind
    assert env["AICL_GATEWAY_PORT"] == port
    assert env["AICL_OLLAMA_MODEL"] == interpolate(SERVICES["ollama-pull"]["command"][0])
    assert env["AICL_CLOUDSIM_PORT"] == published("cloud-sim")[0].split(":")[-1]


def test_env_example_listeners_stay_on_loopback():
    assert env_example()["AICL_CLOUDSIM_HOST"] == "127.0.0.1"


# ---- scripts/task.sh ----

def test_task_sh_hostname_falls_back_when_short_flag_is_missing():
    assert "$(hostname -s 2>/dev/null || hostname)" in (ROOT / "scripts" / "task.sh").read_text(encoding="utf-8")


BASH = shutil.which("bash")


@pytest.mark.skipif(BASH is None or "system32" in BASH.lower(), reason="no real bash (missing or the WSL launcher)")
def test_task_sh_parses():
    r = subprocess.run([BASH, "-n", "scripts/task.sh"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# ---- T-011: compose demo wiring for T-901 ---------------------------------------------------------

def test_t011_cloud_sim_runs_the_demo_script_and_gateway_has_a_demo_key_without_env_file():
    cs = SERVICES["cloud-sim"]["environment"]
    gw = SERVICES["gateway"]["environment"]
    assert cs["AICL_CLOUDSIM_SCRIPT"] == "${AICL_CLOUDSIM_SCRIPT:-demo}"
    assert gw["AICL_KEY_DEMO"].startswith("${AICL_KEY_DEMO:-") and gw["AICL_KEY_DEMO"].endswith("}")
    assert SERVICES["gateway"]["env_file"] == [{"path": ".env", "required": False}]

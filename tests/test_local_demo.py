"""T-010: local demo mode (host Ollama, bundled ollama off), static checks of the compose override and script."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class _Loader(yaml.SafeLoader):
    pass


_Loader.add_multi_constructor("!", lambda loader, suffix, node: loader.construct_mapping(node)
                              if isinstance(node, yaml.MappingNode) else loader.construct_scalar(node))
LOCAL = yaml.load((ROOT / "docker-compose.local.yml").read_text(encoding="utf-8"), Loader=_Loader)


def test_gateway_uses_the_host_ollama_and_no_longer_waits_for_the_bundled_one():
    gw = LOCAL["services"]["gateway"]
    assert "host.docker.internal" in gw["environment"]["AICL_OLLAMA_URL"]
    assert "host.docker.internal:host-gateway" in gw["extra_hosts"]
    assert set(gw["depends_on"]) == {"cloud-sim"}
    assert "!override" in (ROOT / "docker-compose.local.yml").read_text(encoding="utf-8")


def test_bundled_ollama_is_off_by_default():
    assert LOCAL["services"]["ollama"]["profiles"] == ["bundled-ollama"]


def test_script_checks_pulls_warms_and_smoke_tests_but_never_deletes_models():
    s = (ROOT / "scripts" / "demo-local.sh").read_text(encoding="utf-8")
    for step in ("/api/version", "/api/pull", "num_ctx", "docker-compose.local.yml", "/healthz", "/console"):
        assert step in s
    assert "/api/delete" not in s and "ollama rm" not in s
    assert "demo-local:" in (ROOT / "Makefile").read_text(encoding="utf-8")

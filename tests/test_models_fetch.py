"""T-019: local INJ-04 models are pinned (revision + sha256 of every file), gitignored and mounted read-only."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _fetch_module():
    spec = importlib.util.spec_from_file_location("fetch_models", ROOT / "scripts" / "fetch_models.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_model_file_is_pinned():
    m = _fetch_module()
    assert set(m.MODELS) == {"classifier", "embedder"}
    for name, spec in m.MODELS.items():
        assert re.fullmatch(r"[0-9a-f]{40}", spec["rev"]), f"{name}: revision must be a commit sha"
        for rel, sha in spec["files"].items():
            pin = sha or m.SMALL.get((name, rel))
            assert pin and re.fullmatch(r"[0-9a-f]{64}", pin), f"{name}/{rel} has no sha256 pin"


def test_classifier_is_never_quantized():
    # measured: int8 dynamic quantization collapses DeBERTa-v3 injection scores (0.99 -> under 0.2)
    m = _fetch_module()
    assert m.MODELS["classifier"]["quantize"] is False and m.MODELS["embedder"]["quantize"] is True


def test_models_are_gitignored_and_mounted_read_only():
    assert "models/" in (ROOT / ".gitignore").read_text(encoding="utf-8").split()
    for f in ("docker-compose.yml", "docker-compose.transparent.yml"):
        doc = yaml.safe_load((ROOT / f).read_text(encoding="utf-8"))
        vols = [v for svc in doc["services"].values() for v in (svc.get("volumes") or []) if isinstance(v, str)]
        assert "./models:/app/models:ro" in vols, f
    assert "AICL_MODELS_DIR=/app/models" in (ROOT / "w1-gateway" / "Dockerfile").read_text(encoding="utf-8")

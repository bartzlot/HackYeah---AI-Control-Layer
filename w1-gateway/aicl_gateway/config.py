"""Gateway configuration: defaults, env overrides, model router."""
from __future__ import annotations

import os
from typing import Any

from aicl_contracts import DestKind

OLLAMA_MODEL = "qwen3.5:2b-q4_K_M"

DEFAULT_MODELS: dict[str, dict[str, Any]] = {
    OLLAMA_MODEL: {"kind": "local"},
    "gpt-4o-mini": {"kind": "external"},
    "gpt-4o": {"kind": "external"},
}


def default_config() -> dict[str, Any]:
    return {
        # api key -> {"agent_id": str, "models": [tags] | None (all routable), "profile": str | None}
        "agents": {},
        "models": DEFAULT_MODELS,           # tag -> {"kind": local|external, "upstream_model": optional rename}
        "upstream_urls": {
            "local": os.environ.get("AICL_OLLAMA_URL", "http://localhost:11434"),
            "external": os.environ.get("AICL_CLOUDSIM_URL", "http://localhost:8081"),
        },
        # credentials the gateway injects upstream (agent keys are never forwarded)
        "upstream_keys": {"local": None, "external": os.environ.get("AICL_UPSTREAM_KEY_EXTERNAL")},
        "audit_path": os.environ.get("AICL_AUDIT_PATH"),   # JSONL, None = bus only
        "upstream_timeout": 120.0,
        "session_header": "x-session-id",
        # console: demo_key = key the playground uses; policy = raw policy dict or callable (controls table,
        # org USD budget); budget_usd overrides the policy budget; fixtures = preload demo records;
        # remote = serve the console (and the demo key) to non-loopback clients; host-only by default,
        # set it only on a firewalled demo host or inside docker behind a host-only port mapping
        "console": {"demo_key": None, "fixtures": False, "budget_usd": None, "policy": None, "remote": False},
    }


def merge_config(config: dict | None) -> dict[str, Any]:
    cfg = default_config()
    for k, v in (config or {}).items():
        if k in ("upstream_urls", "upstream_keys", "console") and isinstance(v, dict):
            cfg[k] = {**cfg[k], **v}
        else:
            cfg[k] = v
    return cfg


def route(cfg: dict, model: str) -> tuple[DestKind, dict]:
    entry = cfg["models"].get(model)
    if not entry:
        return DestKind.UNKNOWN, {}
    return DestKind(entry["kind"]), entry

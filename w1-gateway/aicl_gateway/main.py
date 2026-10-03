"""T-901 policy-driven gateway entrypoint: policy.yaml -> agents, models, budgets, console, judge -> app.

    uvicorn --factory aicl_gateway.main:create_app_from_env --host 0.0.0.0 --port 18080

Everything comes from the one policy file (hot reloaded by the w2 engine) plus AICL_* environment variables
(all documented in .env.example):
  AICL_POLICY                  policy path (default policy/policy.yaml)
  AICL_OLLAMA_URL              local upstream (Ollama: OpenAI-compatible /v1 for chat, /api/chat for the judge)
  AICL_OLLAMA_MODEL            Ollama tag actually called for the policy's local model (CPU fallback, e.g. 0.8b)
  AICL_CLOUDSIM_URL            external upstream (priced cloud-sim mock)
  AICL_UPSTREAM_KEY_EXTERNAL   credential injected towards the external upstream (agents never hold it)
  AICL_DATA_DIR, AICL_AUDIT_PATH, AICL_BUDGET_DB   audit JSONL and budget SQLite (directories are created)
  AICL_CONSOLE_REMOTE          1 = serve /console beyond loopback (compose, behind a host-only port)
  AICL_KEY_DEMO                demo key: agent DEMO_AGENT, and the console playground key
  AICL_KEY_<AGENT_ID>          key per policy agent, id upper-cased with non-alphanumerics as _ (e.g.
                               support-bot -> prefix AICL_KEY_ + SUPPORT_BOT); or put the sha256 hex of
                               the key in agents.<id>.key_sha256
Policy edits apply live: decide() reloads the policy, and agents, models and budgets are re-derived on the
first request after a new policy version.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Callable

from aicl_core.engine import Engine, register

from . import judge as judge_mod
from .app import create_app
from .budget import config_from_policy

DEMO_AGENT = "analyst-agent"          # the demo key's agent: may use the local and the external model
KEY_PREFIX = "AICL_KEY_"
_HEX64 = re.compile(r"^(sha256:)?([0-9a-f]{64})$")


def key_env_name(agent_id: str) -> str:
    return KEY_PREFIX + re.sub(r"[^A-Z0-9]", "_", agent_id.upper())


def _agent_entry(aid: str, a: dict, default_models: list | None) -> dict:
    models = a.get("models")
    return {"agent_id": aid, "models": list(models) if isinstance(models, list) else default_models,
            "profile": a.get("profile")}


def agents_from_policy(raw: dict, env: dict) -> tuple[dict[str, dict], dict[str, dict]]:
    """-> (api key -> agent entry, sha256 hex -> agent entry). Agents without a key cannot authenticate."""
    allow = ((raw.get("destinations") or {}).get("model_allowlist") or {}).get("default")
    default_models = list(allow) if isinstance(allow, list) else None
    keys: dict[str, dict] = {}
    hashes: dict[str, dict] = {}
    agents = raw.get("agents") or {}
    for aid, a in agents.items():
        if not isinstance(a, dict):
            continue
        entry = _agent_entry(str(aid), a, default_models)
        k = env.get(key_env_name(str(aid)))
        if k:
            keys[k] = entry
        m = _HEX64.match(str(a.get("key_sha256") or "").lower())
        if m:
            hashes[m.group(2)] = entry
    demo = env.get("AICL_KEY_DEMO")
    if demo and demo not in keys and isinstance(agents.get(DEMO_AGENT), dict):
        keys[demo] = _agent_entry(DEMO_AGENT, agents[DEMO_AGENT], default_models)
    return keys, hashes


def models_from_policy(raw: dict, env: dict) -> dict[str, dict]:
    """Concrete model tags of destinations.models with class local / external (globs stay unknown)."""
    out: dict[str, dict] = {}
    ollama_tag = env.get("AICL_OLLAMA_MODEL")
    for tag, m in (((raw.get("destinations") or {}).get("models")) or {}).items():
        if not isinstance(m, dict) or any(ch in str(tag) for ch in "*?["):
            continue
        cls = m.get("class")
        if cls not in ("local", "external"):
            continue
        entry: dict[str, Any] = {"kind": cls}
        if cls == "local" and ollama_tag and ollama_tag != tag:
            entry["upstream_model"] = ollama_tag
        out[str(tag)] = entry
    return out


def build_config(raw: dict, env: dict, policy_fn: Callable[[], dict]) -> dict:
    keys, hashes = agents_from_policy(raw, env)
    data = Path(env.get("AICL_DATA_DIR") or "data")
    cfg = {
        "agents": keys,
        "agent_key_hashes": hashes,
        "models": models_from_policy(raw, env),
        "upstream_urls": {"local": env.get("AICL_OLLAMA_URL") or "http://localhost:11434",
                          "external": env.get("AICL_CLOUDSIM_URL") or "http://localhost:18200"},
        "upstream_keys": {"local": None, "external": env.get("AICL_UPSTREAM_KEY_EXTERNAL") or None},
        "audit_path": env.get("AICL_AUDIT_PATH") or str(data / "audit.jsonl"),
        "budget_db": env.get("AICL_BUDGET_DB") or str(data / "budget.db"),
        "console": {"policy": policy_fn, "demo_key": env.get("AICL_KEY_DEMO") or None,
                    "remote": env.get("AICL_CONSOLE_REMOTE") == "1"},
        **config_from_policy(raw),
    }
    return cfg


def _ensure_parent(path: str | None) -> None:
    if path and path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)


def create_app_from_env(env: dict | None = None, *, upstreams: dict | None = None,
                        judge_chat: Callable | None = None, reload_interval: float = 1.0,
                        start_reload: bool = True):
    """App factory. env defaults to os.environ; upstreams / judge_chat are test seams (ASGI mocks, fake Ollama)."""
    env = dict(os.environ) if env is None else dict(env)
    engine = Engine(env.get("AICL_POLICY") or "policy/policy.yaml", interval=reload_interval, start=start_reload)
    cfg = build_config(engine.policy.raw, env, lambda: engine.policy.raw)
    _ensure_parent(cfg["audit_path"])
    _ensure_parent(cfg["budget_db"])
    # INJ-04 local judge, registered after the w2 controls (INJ-03 first); one Judge per process
    judge = judge_mod.install(register, cfg["upstream_urls"]["local"], chat_fn=judge_chat)
    seen = {"version": engine.policy.version}
    holder: dict[str, Any] = {}

    def apply_policy(raw: dict) -> None:
        """Re-derive agents, models and budgets from a new policy version (dicts mutated in place)."""
        app = holder["app"]
        new = build_config(raw, env, lambda: engine.policy.raw)
        for k in ("agents", "agent_key_hashes", "models"):
            app.state.config[k].clear()
            app.state.config[k].update(new[k])
        app.state.ledger.limits = new["budgets"]
        app.state.ledger.warn_at = float(new["budget"].get("warn_at", 0.8))
        app.state.config["budget"].update(new["budget"])   # prices and loop limits apply on restart

    def decide(event):
        d = engine.decide(event)
        pol = engine.policy
        if pol.version != seen["version"]:
            seen["version"] = pol.version
            try:
                apply_policy(pol.raw)
            except Exception:  # noqa: BLE001 - keep the previous derived config; the engine keeps last-good
                pass
        return d

    app = create_app(decide, cfg, upstreams)
    holder["app"] = app
    app.state.engine, app.state.judge = engine, judge
    app.state.apply_policy = apply_policy

    @app.on_event("shutdown")
    async def _stop_reload():
        engine.store.stop()

    return app

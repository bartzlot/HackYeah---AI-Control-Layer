"""T-107: live policy and budget editing from the console (the judges' "change the config and watch it apply").

write_policy(text): the candidate is validated by the real loader NEXT TO the live file (same local.d/ and
rules/), then atomically replaces it and the engine reloads at once; an invalid edit returns the loader's
error and the live file is untouched. patch_budgets(body): a ruamel round-trip edit of budgets.agents /
budgets.org, so comments and layout of policy.yaml are kept, then the same write path.
seed_policy(env): AICL_POLICY_SEED copies a seed policy directory to the writable AICL_POLICY location on the
first start (Cloud Run, read-only images).
"""
from __future__ import annotations

import io
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from aicl_core.policy import PolicyError, load_policy

PERIODS = ("minute", "hour", "day", "month")
MAX_POLICY_BYTES = 512 * 1024


class PolicyWriteError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def write_policy(path: Path, text: str, engine) -> dict[str, Any]:
    if not isinstance(text, str) or not text.strip():
        raise PolicyWriteError(422, "empty policy")
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyWriteError(413, f"policy over {MAX_POLICY_BYTES // 1024} KB")
    cand = path.with_name(f".policy.candidate.{uuid.uuid4().hex[:8]}.yaml")
    try:
        cand.write_text(text, encoding="utf-8")
    except OSError as e:
        raise PolicyWriteError(409, f"policy directory is read-only ({type(e).__name__}); set AICL_POLICY to a "
                                    "writable path, e.g. with AICL_POLICY_SEED") from e
    try:
        load_policy(cand)                       # same loader, same local.d/ and rules/ as the live file
    except PolicyError as e:
        cand.unlink(missing_ok=True)
        raise PolicyWriteError(422, str(e).replace(str(cand), path.name)) from e
    except Exception as e:  # noqa: BLE001
        cand.unlink(missing_ok=True)
        raise PolicyWriteError(422, f"{type(e).__name__}: {e}") from e
    os.replace(cand, path)                      # atomic on the same filesystem
    engine.store.refresh(force=True)
    return {"ok": True, "version": engine.policy.version, "error": engine.store.error}


def _num(v: Any, where: str, integer: bool) -> int | float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
        raise PolicyWriteError(422, f"{where} must be a non-negative number")
    return int(v) if integer else float(v)


def patch_budgets(path: Path, body: dict, engine) -> dict[str, Any]:
    """body: {"agents": {id: {tokens?, usd?, period?} | null}, "org": {tokens?, usd?, period?}}; null removes."""
    if not isinstance(body, dict):
        raise PolicyWriteError(422, "body must be a JSON object")
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096
    doc = y.load(path.read_text(encoding="utf-8"))
    budgets = doc.setdefault("budgets", CommentedMap())
    agents = budgets.setdefault("agents", CommentedMap())

    def apply(target: CommentedMap, lim: dict, where: str) -> None:
        for k, v in lim.items():
            if k == "tokens":
                target[k] = _num(v, f"{where}.tokens", True)
            elif k == "usd":
                target[k] = _num(v, f"{where}.usd", False)
            elif k == "period":
                if v not in PERIODS:
                    raise PolicyWriteError(422, f"{where}.period must be {'|'.join(PERIODS)}")
                target[k] = v
            else:
                raise PolicyWriteError(422, f"{where}: unknown key {k!r}")

    for aid, lim in (body.get("agents") or {}).items():
        if not isinstance(aid, str) or not aid or len(aid) > 64:
            raise PolicyWriteError(422, "agent ids must be short strings")
        if lim is None:
            agents.pop(aid, None)
            continue
        if not isinstance(lim, dict):
            raise PolicyWriteError(422, f"budgets.agents.{aid} must be an object")
        entry = agents.get(aid)
        if not isinstance(entry, dict):
            entry = CommentedMap()
            entry.fa.set_flow_style()
            agents[aid] = entry
        apply(entry, lim, f"budgets.agents.{aid}")
    if body.get("org") is not None:
        if not isinstance(body["org"], dict):
            raise PolicyWriteError(422, "budgets.org must be an object")
        org = budgets.setdefault("org", CommentedMap())
        apply(org, body["org"], "budgets.org")
    buf = io.StringIO()
    y.dump(doc, buf)
    return write_policy(path, buf.getvalue(), engine)


def seed_policy(env: dict) -> None:
    """AICL_POLICY_SEED=<dir with policy.yaml>: copy it to the AICL_POLICY directory once (never overwrite)."""
    seed, target = env.get("AICL_POLICY_SEED"), env.get("AICL_POLICY")
    if not seed or not target:
        return
    dst = Path(target)
    if dst.exists():
        return
    src = Path(seed)
    if not (src / "policy.yaml").is_file():
        raise FileNotFoundError(f"AICL_POLICY_SEED {seed} has no policy.yaml")
    shutil.copytree(src, dst.parent, dirs_exist_ok=True)
    if dst.name != "policy.yaml" and not dst.exists():
        shutil.copy2(src / "policy.yaml", dst)

"""T-403: evaluate the INJ-04 cascade (classifier + kNN) on the held-out set tests/eval/injection_eval.yaml.

  uv run python scripts/eval_classifier.py [--profile balanced] [--json reports/injection_eval.json]

Prints per-sample scores, then precision / recall / false-positive rate of the cascade (block = caught,
gray = sent to the judge), latency p50 / p95 per part and a stability check (every sample scored again, the
scores must be identical over three more cold passes). Needs models/ (make models-onnx); never runs in the offline test suite.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "w1-gateway"))
from aicl_gateway import semantic  # noqa: E402


def thresholds(profile: str) -> dict[str, float]:
    pol = yaml.safe_load((ROOT / "policy" / "policy.yaml").read_text(encoding="utf-8"))
    c = ((pol.get("controls") or {}).get("INJ-04") or {}).get("classifier") or {}
    out = dict(semantic.DEFAULTS)
    for k in out:
        v = c.get(k, out[k])
        out[k] = float(v.get(profile, out[k]) if isinstance(v, dict) else v)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="balanced")
    ap.add_argument("--json")
    ap.add_argument("--models", default=str(ROOT / "models"))
    a = ap.parse_args()
    clf, knn = semantic.load_from_env({"AICL_MODELS_DIR": a.models, "AICL_POLICY": str(ROOT / "policy" / "policy.yaml")})
    if not clf or not knn:
        print("models missing: run make models-onnx", file=sys.stderr)
        return 2
    t = thresholds(a.profile)
    data = yaml.safe_load((ROOT / "tests" / "eval" / "injection_eval.yaml").read_text(encoding="utf-8"))
    rows, lat = [], []
    for label in ("attack", "benign"):
        for s in data[label]:
            clf.cache = semantic._Lru(10)                  # cold: measure the model, not the cache
            knn.cache = semantic._Lru(10)
            t0 = time.perf_counter()
            r = clf.score(s["text"])
            k = knn.query(semantic.text_windows(s["text"], focus=r["window"]))
            lang = semantic.language(s["text"])
            score = semantic.combine(r["p"], k["p"], lang, t)
            lat.append((time.perf_counter() - t0) * 1000)
            verdict, why = semantic.cascade(score, t)
            rows.append({"id": s["id"], "label": label, "channel": s.get("channel"), "lang": lang, "p_cls": round(r["p"], 4),
                         "p_emb": k["p"], "score": round(score, 4), "nearest": k["top"][:1], "verdict": verdict, "why": why})
    stable = True
    for _ in range(3):                                   # cold caches, three more passes: identical scores
        for s, row in zip([*data["attack"], *data["benign"]], rows):
            clf.cache, knn.cache = semantic._Lru(10), semantic._Lru(10)
            r = clf.score(s["text"])
            k = knn.query(semantic.text_windows(s["text"], focus=r["window"]))
            if round(r["p"], 4) != row["p_cls"] or k["p"] != row["p_emb"]:
                stable = False
    for r in rows:
        print(f"{r['label']:6} {r['id']:9} {r['lang']} cls {r['p_cls']:.3f} emb {r['p_emb']:.3f} score {r['score']:.3f} -> {r['verdict']:5} nearest {r['nearest']}")
    att = [r for r in rows if r["label"] == "attack"]
    ben = [r for r in rows if r["label"] == "benign"]
    caught = sum(r["verdict"] == "block" for r in att)
    flagged = sum(r["verdict"] != "pass" for r in att)
    fp_block = sum(r["verdict"] == "block" for r in ben)
    fp_gray = sum(r["verdict"] == "gray" for r in ben)
    lat.sort()
    rep = {"profile": a.profile, "thresholds": t, "attacks": len(att), "benign": len(ben),
           "recall_block": round(caught / len(att), 3), "recall_block_or_judge": round(flagged / len(att), 3),
           "fpr_block": round(fp_block / len(ben), 3), "benign_sent_to_judge": round(fp_gray / len(ben), 3),
           "precision_block": round(caught / max(1, caught + fp_block), 3),
           "latency_ms_p50": round(statistics.median(lat), 1), "latency_ms_p95": round(lat[int(0.95 * (len(lat) - 1))], 1),
           "stable": stable, "rows": rows}
    print(json.dumps({k: v for k, v in rep.items() if k != "rows"}, indent=1))
    if a.json:
        Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json).write_text(json.dumps(rep, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

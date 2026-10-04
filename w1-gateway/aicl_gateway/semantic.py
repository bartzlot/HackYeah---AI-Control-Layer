"""T-401 / T-402: INJ-04 stages 1 and 2, local and deterministic, on CPU through onnxruntime.

Stage 1, Classifier: a prompt-injection sequence classifier (DeBERTa-v3, models/classifier). The text is
tokenized once and cut into overlapping windows of `window` tokens; every window is scored (softmax of the
INJECTION logit) and the part's score is the maximum. Windows run in parallel on a thread pool (a 256-token
window takes about 75 ms on the demo CPU and does not get faster with more intra-op threads), and every window
score is cached by the hash of its token ids: a coding agent re-sends the whole conversation each turn, so only
new text costs time. A per-call deadline bounds the work; windows left when it passes are reported as
`partial` (the deterministic controls still saw the whole text). The model stays fp32: int8 dynamic
quantization collapses DeBERTa-v3 scores.

Stage 2, Knn: a multilingual sentence embedder (e5-small, int8, models/embedder) over labelled examples
(policy/semantic/examples.yaml: attacks and benign coding-agent traffic, EN + PL). The query is the most
suspicious window from stage 1 (plus a cue-centred window), the answer is the attack share of the k nearest
neighbours weighted by similarity and the best attack match. It is the second opinion that catches what the
English-centric classifier misreads (benign Polish text, Polish attacks).

No network, no sampling: the same text always gets the same scores. Both classes take injectable seams
(tokenize / infer / embed) so the offline tests run without the model files.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np
import yaml

log = logging.getLogger("aicl.semantic")

Tokenize = Callable[[str], tuple[list[int], list[tuple[int, int]]]]   # text -> (ids, char offsets), no specials
Infer = Callable[[list[int]], float]                                   # one window of ids (with specials) -> p(injection)
Embed = Callable[[list[str]], np.ndarray]                              # texts -> L2-normalised rows

# the same broad EN + PL paraphrase cues as the judge: they pick which windows go first when a part is longer
# than the window budget, and which window the kNN stage also looks at
CUES = re.compile(
    r"(?i)\b(ignore|disregard|forget|override|bypass|pretend|roleplay|jailbreak|developer mode|"
    r"system prompt|instructions|reveal|exfiltrat|unfiltered|no (rules|restrictions|limits)|act as|you are now|"
    r"zignoruj|ignoruj|zapomnij|pomin|udawaj|instrukcj|polecen|prompt systemowy|bez ograniczen)")


class _Lru:
    def __init__(self, size: int):
        self.size, self._d, self._lock = size, OrderedDict(), threading.Lock()
        self.hits = self.misses = 0

    def get(self, k):
        with self._lock:
            if k in self._d:
                self._d.move_to_end(k)
                self.hits += 1
                return self._d[k]
            self.misses += 1
            return None

    def put(self, k, v) -> None:
        with self._lock:
            self._d[k] = v
            while len(self._d) > self.size:
                self._d.popitem(last=False)

    def __len__(self) -> int:
        return len(self._d)


def _session(path: Path, threads: int):
    import onnxruntime as ort
    so = ort.SessionOptions()
    so.intra_op_num_threads = threads
    so.inter_op_num_threads = 1
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    so.log_severity_level = 3
    return ort.InferenceSession(str(path), so, providers=["CPUExecutionProvider"])


class Classifier:
    """Stage 1. score(text) -> {"p", "window": (start, end) char span of the best window, "windows", "scored",
    "partial", "cached", "ms"}."""

    def __init__(self, tokenize: Tokenize, infer: Infer, *, cls_id: int = 1, sep_id: int = 2, window: int = 256,
                 stride: int = 224, workers: int = 8, cache_size: int = 50000, model_id: str = "fake"):
        self.tokenize, self.infer, self.cls_id, self.sep_id = tokenize, infer, cls_id, sep_id
        self.window, self.stride, self.model_id = window, stride, model_id
        self.cache = _Lru(cache_size)
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="inj04-cls")
        self.lat_ms: deque[float] = deque(maxlen=512)
        self.windows_scored = 0

    @classmethod
    def from_dir(cls, d: str | Path, *, threads: int = 2, workers: int = 8, **kw) -> "Classifier":
        from tokenizers import Tokenizer
        d = Path(d)
        tok = Tokenizer.from_file(str(d / "tokenizer.json"))
        tok.no_truncation()
        tok.no_padding()
        sess = _session(d / "model.onnx", threads)
        names = {i.name for i in sess.get_inputs()}

        def tokenize(text: str):
            e = tok.encode(text, add_special_tokens=False)
            return e.ids, e.offsets

        def infer(ids: list[int]) -> float:
            x = np.asarray([ids], dtype=np.int64)
            feed = {"input_ids": x, "attention_mask": np.ones_like(x)}
            if "token_type_ids" in names:
                feed["token_type_ids"] = np.zeros_like(x)
            lo = sess.run(None, feed)[0][0].astype(np.float64)
            e = np.exp(lo - lo.max())
            return float(e[1] / e.sum())

        src = (d / "SOURCE").read_text(encoding="utf-8").strip() if (d / "SOURCE").is_file() else d.name
        return cls(tokenize, infer, cls_id=tok.token_to_id("[CLS]"), sep_id=tok.token_to_id("[SEP]"),
                   workers=workers, model_id=src, **kw)

    def _spans(self, n: int) -> list[tuple[int, int]]:
        body = self.window - 2
        if n <= body:
            return [(0, n)]
        out, s = [], 0
        while True:
            e = min(n, s + body)
            out.append((s, e))
            if e >= n:
                return out
            s += self.stride if self.stride < body else body

    def _run(self, key: str, ids: list[int]) -> float:
        p = self.infer(ids)
        self.cache.put(key, p)
        self.windows_scored += 1
        return p

    def score(self, text: str, *, max_windows: int = 16, deadline: float | None = None,
              cues: re.Pattern | None = CUES) -> dict[str, Any]:
        t0 = time.monotonic()
        ids, offs = self.tokenize(text or "")
        spans = self._spans(len(ids)) if ids else []
        order = list(range(len(spans)))
        if len(spans) > max_windows:
            # budget: windows holding cue words first, then the first and last window, then evenly spaced
            hot = []
            if cues is not None:
                starts = [m.start() for m in cues.finditer(text)]
                for i, (s, e) in enumerate(spans):
                    a, b = offs[s][0], offs[e - 1][1]
                    if any(a <= c < b for c in starts):
                        hot.append(i)
            rest = [0, len(spans) - 1] + [round(k * (len(spans) - 1) / max(1, max_windows - 1)) for k in range(max_windows)]
            order = list(dict.fromkeys(hot + rest))[:max_windows]
        scores: dict[int, float] = {}
        todo: list[tuple[int, str, list[int]]] = []
        cached = 0
        for i in order:
            s, e = spans[i]
            w = [self.cls_id, *ids[s:e], self.sep_id]
            key = hashlib.sha256(np.asarray(w, dtype=np.int32).tobytes()).hexdigest()
            hit = self.cache.get(key)
            if hit is not None:
                scores[i], cached = hit, cached + 1
            else:
                todo.append((i, key, w))
        if todo:
            futs = [(i, self.pool.submit(self._run, key, w)) for i, key, w in todo]
            for i, f in futs:
                left = None if deadline is None else max(0.0, deadline - time.monotonic())
                try:
                    scores[i] = f.result(timeout=left)
                except Exception:  # noqa: BLE001 - TimeoutError or a model error: the window stays unscored
                    f.cancel()     # a window already running finishes in the background and lands in the cache
        ms = (time.monotonic() - t0) * 1000.0
        self.lat_ms.append(ms)
        if not scores:
            return {"p": None, "window": (0, 0), "windows": len(spans), "scored": 0, "partial": bool(spans),
                    "cached": cached, "ms": round(ms, 1)}
        best = max(scores, key=lambda i: scores[i])
        s, e = spans[best]
        return {"p": scores[best], "window": (offs[s][0], offs[e - 1][1]), "windows": len(spans),
                "scored": len(scores), "partial": len(scores) < len(spans), "cached": cached, "ms": round(ms, 1)}


class Knn:
    """Stage 2: multilingual embedding head. At startup the labelled examples are embedded and a logistic
    regression (standardised features, L2, fixed iterations from zero: deterministic) is fitted on them.
    query(texts) -> {"p": max attack probability over the texts, "top": nearest examples of the best text
    [(similarity, label, id)] for the explain trace, "ms"}. Evaluated on the held-out set the head separates
    attacks from benign coding-agent text better than the English classifier (AUC 0.91 vs 0.82, EN + PL)."""

    def __init__(self, embed: Embed, examples: Sequence[dict], *, k: int = 3, l2: float = 0.003,
                 iters: int = 4000, model_id: str = "fake"):
        self.embed, self.k, self.model_id = embed, k, model_id
        self.examples = [e for e in examples if e.get("label") in ("attack", "benign") and e.get("text")]
        self.labels = np.asarray([e["label"] == "attack" for e in self.examples])
        self.vecs = embed([e["text"] for e in self.examples]) if self.examples else np.zeros((0, 1), np.float32)
        self.cache = _Lru(20000)
        self.lat_ms: deque[float] = deque(maxlen=512)
        self.w = None
        if len(self.examples) and self.labels.any() and (~self.labels).any():
            x = self.vecs.astype(np.float64)
            y = self.labels.astype(np.float64)
            self.mu, self.sd = x.mean(axis=0), x.std(axis=0) + 1e-6
            xs = (x - self.mu) / self.sd
            w, b = np.zeros(x.shape[1]), 0.0
            for _ in range(iters):
                g = 1.0 / (1.0 + np.exp(-(xs @ w + b))) - y
                w -= 0.1 * (xs.T @ g / len(y) + l2 * w)
                b -= 0.1 * float(g.mean())
            self.w, self.b = w, b

    @classmethod
    def from_dir(cls, d: str | Path, examples: Sequence[dict], *, threads: int = 2, **kw) -> "Knn":
        from tokenizers import Tokenizer
        d = Path(d)
        tok = Tokenizer.from_file(str(d / "tokenizer.json"))
        tok.enable_truncation(512)
        tok.no_padding()
        path = d / "model.int8.onnx" if (d / "model.int8.onnx").is_file() else d / "model.onnx"
        sess = _session(path, threads)
        names = {i.name for i in sess.get_inputs()}

        def embed(texts: list[str]) -> np.ndarray:
            rows = []
            for t in texts:                                   # one at a time: no padding, exact and deterministic
                e = tok.encode("query: " + t)
                x = np.asarray([e.ids], dtype=np.int64)
                feed = {"input_ids": x, "attention_mask": np.ones_like(x)}
                if "token_type_ids" in names:
                    feed["token_type_ids"] = np.zeros_like(x)
                h = sess.run(None, feed)[0][0].astype(np.float64).mean(axis=0)
                rows.append(h / (np.linalg.norm(h) or 1.0))
            return np.asarray(rows, dtype=np.float32)

        src = (d / "SOURCE").read_text(encoding="utf-8").strip() if (d / "SOURCE").is_file() else d.name
        return cls(embed, examples, model_id=src, **kw)

    def _one(self, t: str) -> dict:
        key = hashlib.sha256(" ".join(t.split()).encode()).hexdigest()
        res = self.cache.get(key)
        if res is None:
            v = self.embed([t])[0].astype(np.float64)
            sims = self.vecs @ v
            top = np.argsort(-sims, kind="stable")[: self.k]
            p = None
            if self.w is not None:
                p = float(1.0 / (1.0 + np.exp(-(((v - self.mu) / self.sd) @ self.w + self.b))))
            res = {"p": None if p is None else round(p, 4),
                   "top": [(round(float(sims[i]), 3), "attack" if self.labels[i] else "benign",
                            self.examples[i].get("id", str(i))) for i in top]}
            self.cache.put(key, res)
        return res

    def query(self, texts: Sequence[str]) -> dict[str, Any]:
        t0 = time.monotonic()
        texts = [t for t in texts if t and t.strip()]
        if not texts or self.w is None:
            return {"p": None, "top": [], "ms": 0.0}
        best = max((self._one(t) for t in texts), key=lambda r: r["p"])
        ms = (time.monotonic() - t0) * 1000.0
        self.lat_ms.append(ms)
        return {**best, "ms": round(ms, 1)}


# distinctive Polish function words (no "i", "to", "na", "do": they are English too) plus Polish letters
_PL = re.compile(r"(?i)\b(w|z|sie|nie|jest|oraz|ktor\w*|dla|przez|tylko|wszystk\w*|twoj\w*|moj\w*|jestes|prosze|"
                 r"napisz|dodaj|zignoruj|teraz|zeby|czy|jak|ze|od|po|jako|bez|tego|tym|sa|byc|mnie|mi)\b"
                 "|[\u0105\u0107\u0119\u0142\u0144\u00f3\u015b\u017a\u017c]")
_EN = re.compile(r"(?i)\b(the|and|to|of|a|in|is|you|your|for|with|this|that|be|are|on|it|as|all|from|now|please|i|my|me)\b")


def language(text: str) -> str:
    """'pl' or 'en' by function-word counts in the first 4000 characters. The classifier is trained on English:
    on Polish text it scores almost everything as an injection, so Polish is decided by the multilingual head."""
    t = text[:4000]
    return "pl" if len(_PL.findall(t)) > len(_EN.findall(t)) else "en"


def text_windows(text: str, *, size: int = 1500, stride: int = 1200, max_windows: int = 8,
                 focus: tuple[int, int] | None = None) -> list[str]:
    """Character windows for the embedding head (about 400 tokens each): the classifier's best window first,
    then windows with cue words, then the head and the tail, up to max_windows."""
    if len(text) <= size:
        return [text]
    starts = list(range(0, max(1, len(text) - size) + 1, stride))
    if starts[-1] + size < len(text):
        starts.append(len(text) - size)
    cue = [m.start() for m in CUES.finditer(text)]
    hot = [s for s in starts if any(s <= c < s + size for c in cue)]
    order = list(dict.fromkeys(hot + [starts[0], starts[-1]] + starts))[:max_windows]
    out = [text[s:s + size] for s in order]
    if focus and focus[1] > focus[0]:
        a = max(0, min(focus[0], len(text) - size))
        out.insert(0, text[a:a + size])
    return out[:max_windows]


def load_examples(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.is_file():
        return []
    doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out = []
    for label in ("attack", "benign"):
        for i, e in enumerate(doc.get(label) or []):
            e = {"text": e} if isinstance(e, str) else dict(e)
            e.setdefault("id", f"{label}-{i + 1}")
            e["label"] = label
            out.append(e)
    return out


def load_from_env(env: dict) -> tuple[Classifier | None, Knn | None]:
    """AICL_MODELS_DIR -> (classifier, knn). Unset (the offline tests), AICL_CLASSIFIER=0, or a missing file -> None:
    the cascade falls back to the judge-only path. Examples: AICL_SEMANTIC_EXAMPLES or semantic/examples.yaml next
    to the policy file."""
    if not env.get("AICL_MODELS_DIR") or env.get("AICL_CLASSIFIER", "1") in ("0", "off", "false"):
        return None, None
    d = Path(env["AICL_MODELS_DIR"])
    workers = int(env.get("AICL_CLASSIFIER_WORKERS") or min(8, max(1, (os.cpu_count() or 2) // 2)))
    clf = knn = None
    try:
        if (d / "classifier" / "model.onnx").is_file():
            clf = Classifier.from_dir(d / "classifier", workers=workers)
    except Exception as e:  # noqa: BLE001
        log.warning("INJ-04 classifier not loaded from %s: %s", d / "classifier", e)
    pol = Path(env.get("AICL_POLICY") or "policy/policy.yaml")
    ex_path = Path(env.get("AICL_SEMANTIC_EXAMPLES") or pol.parent / "semantic" / "examples.yaml")
    try:
        if (d / "embedder" / "tokenizer.json").is_file():
            knn = Knn.from_dir(d / "embedder", load_examples(ex_path))
    except Exception as e:  # noqa: BLE001
        log.warning("INJ-04 kNN not loaded from %s: %s", d / "embedder", e)
    if clf:
        clf.score("warm up")                                     # first run allocates: keep it off a request
    log.info("INJ-04 cascade: classifier %s, kNN %s (%d examples)", clf.model_id if clf else "off",
             knn.model_id if knn else "off", len(knn.examples) if knn else 0)
    return clf, knn


# calibrated on tests/eval/injection_eval.yaml (scripts/eval_classifier.py): profile maps live in policy.yaml
DEFAULTS = {"block": 0.85, "gray": 0.45, "w_classifier": 0.3}


def combine(p_cls: float | None, p_emb: float | None, lang: str, t: dict[str, float]) -> float | None:
    """English: weighted mean of the classifier and the multilingual head; Polish (or no classifier): the head
    alone; no head: the classifier alone."""
    if p_emb is None:
        return p_cls
    if p_cls is None or lang != "en":
        return p_emb
    w = t.get("w_classifier", DEFAULTS["w_classifier"])
    return w * p_cls + (1.0 - w) * p_emb


def cascade(score: float | None, t: dict[str, float]) -> tuple[str, str]:
    """Combined score -> ("block" | "gray" | "pass", reason). Pure: the gateway and the eval script share it.
    gray goes to the local LLM judge when it is enabled, else it is a WARN."""
    if score is None:
        return "pass", "no score"
    if score >= t["block"]:
        return "block", f"score {score:.2f} >= block {t['block']:.2f}"
    if score >= t["gray"]:
        return "gray", f"score {score:.2f} in the gray band [{t['gray']:.2f}, {t['block']:.2f})"
    return "pass", f"score {score:.2f} < {t['gray']:.2f}"

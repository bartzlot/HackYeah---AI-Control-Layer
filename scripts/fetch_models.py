"""Fetch the local INJ-04 models once into models/ (T-019). Never called at runtime or from tests.

  uv run python scripts/fetch_models.py [--dir models]      (or: make models-onnx)

Pinned: HuggingFace revision (commit sha) + sha256 of every file; a mismatch deletes the file and fails.
Both models are permissively licensed and run on CPU through onnxruntime:
  classifier  protectai/deberta-v3-base-prompt-injection-v2   Apache-2.0  prompt-injection classifier (EN)
  embedder    intfloat/multilingual-e5-small                    MIT         multilingual embeddings for kNN (EN + PL)
The embedder is quantized to int8 after download (onnxruntime dynamic quantization: 4x smaller, about 2x faster,
same neighbours). The classifier stays fp32: int8 dynamic quantization collapses DeBERTa-v3 scores (measured:
attacks fall from 0.99 to under 0.2), so it is never quantized.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

MODELS = {
    "classifier": {
        "repo": "protectai/deberta-v3-base-prompt-injection-v2",
        "rev": "90c9989b1a342275dd0d1a95aad283c04e075671",
        "quantize": False,
        "files": {
            "onnx/model.onnx": "f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c",
            "onnx/tokenizer.json": None,
            "onnx/config.json": None,
        },
    },
    "embedder": {
        "repo": "intfloat/multilingual-e5-small",
        "rev": "614241f622f53c4eeff9890bdc4f31cfecc418b3",
        "quantize": True,
        "files": {
            "onnx/model.onnx": "ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665",
            "onnx/tokenizer.json": "0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39",
            "onnx/config.json": None,
        },
    },
}
# small files are not LFS objects on the hub, so the API lists no sha256 for them: pinned here
SMALL = {
    ("classifier", "onnx/tokenizer.json"): "752fe5f0d5678ad563e1bd2ecc1ddf7a3ba7e2024d0ac1dba1a72975e26dff2f",
    ("classifier", "onnx/config.json"): "3093743035223c46b1497a72e939e56fa0a50afbd7bafbf7eb8aad060b8d23f8",
    ("embedder", "onnx/config.json"): "bbb7c1333fc4b3e27fbc9cd5d2070aabcc1d4dfb99917c3633e772f97545a6b6",
}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(name: str, spec: dict, root: Path) -> None:
    out = root / name
    out.mkdir(parents=True, exist_ok=True)
    for rel, want in spec["files"].items():
        want = want or SMALL.get((name, rel))
        dst = out / Path(rel).name
        if not dst.is_file():
            url = f"https://huggingface.co/{spec['repo']}/resolve/{spec['rev']}/{rel}"
            print(f"fetch {name}/{dst.name} <- {url}", flush=True)
            tmp = dst.with_suffix(dst.suffix + ".part")
            urllib.request.urlretrieve(url, tmp)
            tmp.replace(dst)
        got = sha256(dst)
        if want and got != want:
            dst.unlink()
            sys.exit(f"sha256 mismatch for {name}/{dst.name}: {got} != {want} (file removed)")
        print(f"ok {name}/{dst.name} sha256 {got[:16]}", flush=True)
    q = out / "model.int8.onnx"
    if spec["quantize"] and not q.is_file():
        from onnxruntime.quantization import QuantType, quantize_dynamic
        print(f"quantize {name} -> int8", flush=True)
        quantize_dynamic(str(out / "model.onnx"), str(q), weight_type=QuantType.QInt8)
    (out / "SOURCE").write_text(f"{spec['repo']}@{spec['rev']}\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="models")
    ap.add_argument("--only", choices=sorted(MODELS))
    a = ap.parse_args()
    root = Path(a.dir)
    for name, spec in MODELS.items():
        if not a.only or a.only == name:
            fetch(name, spec, root)
    print("models ready in", root.resolve())


if __name__ == "__main__":
    main()

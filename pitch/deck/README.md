# Deck source (T-912)

`deck.html` is the source of `../AgentsShield-deck-EN.pdf` (10 slides, 1920x1080, English). Same pipeline as the CertCordon deck
(`HackYeah---2026/pitch/deck`): `?bg` renders the background layer, `?extract` measures every text block for the PPTX.
Fonts: Inter + JetBrains Mono (`fonts/`, OFL, same files as `promo/fonts`). Logo: `img/agentsshield-*-dark.svg` from `promo/assets/brand`.

Render the PDF (Chrome or Edge, no install needed; fonts are embedded):

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-pdf-header-footer \
  --virtual-time-budget=8000 --print-to-pdf=../AgentsShield-deck-EN.pdf "file://$PWD/deck.html"
```

PPTX (`../AgentsShield-deck-EN.pptx`, same look, editable text, speaker notes): `uv run --with python-pptx --with pillow python build_pptx.py`.
Install Inter and JetBrains Mono (Google Fonts) or PowerPoint substitutes another font.

Images in `img/` (crops of `promo/assets`, real console, 4 Oct about 09:30 CEST, before the T-131 redesign):
- `activity.png`: Activity page with the Why drawer (Codex exec_command blocked by TOOL-01), sidebar cut.
- `protections.png`: Protections page, every control with its status and hit count, sidebar cut.

Numbers and their sources:
- 1,057 tests, 0 failed: `reports/junit.xml` (4 Oct 09:26). 16/16 requirements: `reports/requirements_report.md`.
- 34 ms: `reports/bench.json` (09:27), gateway overhead on a 222 KB Claude Code request, p50 33.8 / p95 34.5 ms, n = 29, fake judge, before the ONNX classifier.
- 7/7 base URL and 9/9 transparent with Claude Code 2.1.289: README.md (live suites, `make verify-live`).
- 88% / 3.3%: `tests/test_injection_eval.py`, balanced profile, 24 attacks and 30 benign prompts, EN + PL.
- 275 tool definitions per Claude Code request: `policy/policy.yaml`. EchoLeak CVE-2025-32711 and the LiteLLM price map: `research/00-summary.md`.
- 0.13 ms for TOOL-01: the decide() timeline in `img/activity.png`.

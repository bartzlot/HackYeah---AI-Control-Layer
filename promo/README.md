# AgentsShield promo video (60 s)

HyperFrames project for the HackYeah 2026 "AI Control Layer" promo of AgentsShield, formerly AICL (this repository, `..`).

- What and why: `BRIEF.md` (decisions, accuracy rules, what not to claim), `STORYBOARD.md` (per-frame shot sequences), `SCRIPT.md` (voice-over), `frame.md` (palette and type: the AgentsShield logo colors (cyan #11b9e4, navy) on the broadside preset).
- Scenes: `compositions/frames/*.html`, assembled in `index.html` (timing, transitions, voice-over, music, SFX).
- Assets: `assets/*.png` real AgentsShield console screenshots (3840x2160, dark theme; capture/console-v2), `assets/brand/` the AgentsShield logo (dark- and light-ground SVGs), `assets/voice/` voice-over (HeyGen voice Isandro, speed 1.05), `assets/bgm/bgm-007.wav` music bed, `assets/sfx/`.
- Source material: `capture/terminal/transcripts.txt` (exact Claude Code / Codex output through the gateway), `capture/extracted/asset-descriptions.md` (asset inventory and the fresh measurements).

## How the screenshots and terminal strings were made (2026-10-04)

1. Copy `policy/` of the AICL repo to a scratch dir and add four demo principals (`clients:` by key hash: anna.k, marek.w, data-team, ci-agent) with budgets.
2. Run `python -m aicl_gateway.mock_providers 18210` (Anthropic mock) and `18211 127.0.0.1 openai`, then `python -m aicl_gateway.serve` with `AICL_POLICY`, `AICL_DATA_DIR`, `AICL_UPSTREAM_ANTHROPIC/OPENAI` pointing at the scratch copy and the mocks.
3. Drive real traffic: `claude -p ... --model ...` with `ANTHROPIC_BASE_URL=http://127.0.0.1:18080` and a demo key per person (prompts `TOOL: cat notes.txt`, `TOOL: cat .env`, `TOOL: steal-creds`, AWS key, PESEL, card, plain prompts), and `codex exec` through the `aicl` provider.
4. Screenshot every console page with headless Chrome at 1920x1080, device scale 2, `prefers-color-scheme: dark`.

Numbers in the video: `make test` (1057 passed on 2026-10-04 09:40, repo HEAD a006f08) and `make bench` (decision p50 0.07 ms, gateway overhead p50 33.8 ms on a 222 KB Claude Code request). Re-run them before publishing.

## Preview and render

```bash
npx hyperframes preview --background   # Studio
npx hyperframes check                  # lint + layout + contrast
npx hyperframes render --skill=product-launch-video --quality high --output renders/agentsshield-promo-60s.mp4
```

Do not re-run `audio.mjs fetch-sfx`: the SFX cue times and the music bed in `audio_meta.json` were placed by hand.

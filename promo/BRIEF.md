---
workflow: product-launch-video
flow: automation
storyboard: yes
message: "Your developers already use AI agents. AICL shows and controls every request they send."
destination: youtube
aspect: 1920x1080
language: en
audience: HackYeah 2026 "AI Control Layer" jury (security people, CISOs, mentors) and YouTube viewers
length: 60s
angle: ciso-problem-to-control
narration: yes
capture: no
---

## Intent

Promo for AICL - AI Control Layer (HackYeah 2026, this repository: ..). A self-hosted
control layer on the network path of every AI API client: Claude Code, Codex, SDKs and agents pass
through it without changing a single setting (DNS points the AI API hosts at AICL, TLS with an org CA).
It identifies who calls, meters spend, inspects prompts, tool results, tool calls and answers, and
decides allow / warn / redact / block in milliseconds; blocks come back in the provider's native format.
One policy file, live reload, every decision explained and visible on a dashboard.

Angle (user pick): CISO problem -> control. "Your developers already use AI agents. Do you know what
they send?" Business problem first (secrets, prompt injection from files, uncontrolled spend, no
visibility), then AICL as the control and the visibility.

Draft beats (confirmed as a starting point, refined in STORYBOARD.md):
1. Hook: requests from Claude Code / Codex flow to api.anthropic.com carrying keys, PESEL, .env.
2. Problem: secret leaks, prompt injection hidden in files, runaway spend. Zero visibility.
3. AICL on the network path (DNS + TLS); nothing to configure on the laptops.
4. Three native blocks with real strings: injection 400 [AICL], tool call blocked (Read) on .env,
   AWS key -> [REDACTED_AWS_KEY].
5. Visibility: real console Overview (blocked, redacted, spend, posture), Clients & spend.
6. One policy file: profiles strict / balanced / permissive, off / shadow / enforce, live in about 1 s;
   budget answers 402.
7. Proof: self-hosted, local AI judge, gateway overhead, test count (only freshly measured numbers).
8. CTA: AICL lock-up, HackYeah 2026.

## Customizations

- Voice-over (user): HeyGen voice Isandro (Serious & Composed), en-US, same as the CertCordon promo.
- Music (user): tense electronic bed with a voiceover carve.
- Look (user): the AICL console dark palette (w1-gateway/aicl_gateway/console/style.css) on the bones
  of the broadside preset: bg #0b0f17, panel #121826, panel2 #0f1522, text #e7ebf3, muted #8b95a9,
  line #232c3d, accent indigo #818cf8, sky #38bdf8, ok #4ade80, warn #fbbf24, red #f87171,
  violet #a78bfa. Anthropic tag #c2410c, OpenAI tag #0f766e. Logo: rounded square with a conic
  gradient (indigo -> sky -> green) and a white bold "A", wordmark "AI Control Layer".
- Visuals (user): real console screenshots and real terminal output, no invented data. Populate the
  console with real traffic: host `aicl_gateway.serve` + Anthropic mock upstream + real Claude Code in
  base-URL mode (no tokens spent). Policy edits recorded on the host (Docker mounts policy read-only).

## Notes

- All on-screen text in English. Never use the em-dash or en-dash character; plain hyphen only.
- Copy problem/benefit oriented, frames must feel full (carried over from the CertCordon promo).
- Accuracy, do not overclaim:
  - Works today: transparent DNS + TLS mode and base-URL mode. Explicit proxy (HTTPS_PROXY) is NOT
    built. No MCP proxy, no approvals (REQUIRE_APPROVAL = BLOCK), no kill-switch buttons in the
    console, no hash-chained audit, no Cloud Run URL.
  - Codex was verified only against an OpenAI mock upstream: name Codex as supported, no live numbers.
  - Out of scope: web apps (claude.ai, chatgpt.com), certificate-pinned desktop apps.
  - Numbers: README says 852 tests, 1011 are collected now. Re-run `make test` and `make bench` and
    quote only freshly measured values.
- Exact native strings (passthrough.py): `[AICL] request blocked by policy: ...`,
  `[AICL] tool call blocked (Read): TOOL-01 rule CODE-AG-002: BLOCK - ... The command was not executed.`,
  `[AICL] budget exceeded for ...` (402), redaction `[REDACTED_AWS_KEY]`, `[PL_PESEL_1]`.
- Use only test values (AKIAIOSFODNN7EXAMPLE, test PESEL 44051401359) on screen.
- Music (2026-10-04): bgm_007 (HeyGen catalog, 70 s, 129 BPM, 'epic technology-documentary background music, fast-paced cinematic build'), content ends ~60 s with the video. SFX cues hand-placed on VO word times in audio_meta.json (do not re-run fetch-sfx: it resets them and the bgm path).

## Rename + logo (2026-10-04, user)

- Product renamed AICL -> **AgentsShield** ("AI Control Layer" stays as the descriptor). Logo from the repo console (T-124): w1-gateway/aicl_gateway/console/logo.svg, copied to assets/brand/ with standalone dark-ground (ink #f1f5f9) and light-ground (ink #0c1e31) variants. Never redraw it.
- Colors adapted to the logo (user): accent indigo -> logo cyan #11b9e4; ground navy-black #0a1726, panels #0f2236, hairlines #1d3550, text #f1f5f9; CTA on logo navy #0c1e31 (no cyan ground: the logo's cyan half vanishes on it).
- Voice-over lines 4 and 9 re-generated with the new name (TTS text "Agents Shield" for pronunciation).
- The product's block messages still say `[AICL]` (passthrough.py): terminal lines keep the real prefix.
- Console screenshots re-captured from the new console (T-122 plain-language UI, T-119 Why panel, AgentsShield logo): capture/console-v2 (old ones: capture/console-v1).
- Tests re-run on the updated repo: 1057 passed; bench unchanged (0.07 ms decision p50, 33.8 ms gateway overhead p50).

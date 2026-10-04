# Pitch deck (T-912)

`AgentsShield-deck-EN.pdf` (submission file) and `AgentsShield-deck-EN.pptx` (editable, speaker notes with sources): 10 slides, English, team Solvro-ng.
Partner task Goldman Sachs - AI Control Layer: the RULES ask for a PDF of at most 10 slides, read by mentors without a speaker in phase 1.
No pricing (hackathon project). Every number on a slide has its source in the speaker notes and in `deck/README.md`.

| # | Slide | Judging criterion it serves |
|---|---|---|
| 1 | Cover: see every AI request, control every one | - |
| 2 | The problem: 275 tool definitions per request, 1 poisoned file, local models priced at $0 | - |
| 3 | Our answer: a poisoned README, Codex tool call blocked by TOOL-01, the agent keeps working | Robustness |
| 4 | How it works: intercept, identify, inspect, decide, answer; the action lattice | Architecture |
| 5 | Hybrid controls: deterministic rules, local AI cascade, historical attacks, budgets | Robustness |
| 6 | Security reporting: Activity with the Why drawer (screenshot) | Security reporting |
| 7 | One policy file: Protections page (screenshot), signed feed, rejected bad edits | Implementability |
| 8 | Measured: 1,057 tests, 16/16 requirements, 34 ms overhead, 9/9 live; INJ-04 eval | Test suite, Performance |
| 9 | How it compares: base-URL gateways and cloud guard APIs; one compose deploy | Implementability, Scalability |
| 10 | A -> B -> C -> next, team | - |

## Before submitting
- Slide 10: confirm the team list for this task (same six names as the CertCordon deck; Mateusz Kierepka has no AICL commits, b4rtosh is assumed to be Bartosz Piekarczyk).
- Look: a temporary monochrome palette (near-black, square corners, AgentsShield cyan as the only accent). When the console redesign T-131 lands, swap the `:root` tokens in `deck/deck.html` and retake the two screenshots (`deck/img/activity.png`, `deck/img/protections.png`).
- Slide 8: refresh the numbers if the suite or the bench is rerun (`make test`, `make verify`, `make bench`); the bench predates the ONNX classifier and used a fake judge.
- The promo video is `promo/renders/agentsshield-promo-60s.mp4` (not required for this task, useful as a demo link).

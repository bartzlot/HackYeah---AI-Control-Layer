# Asset inventory (no website capture; real AICL console + real CLI output)

All console screenshots: 3840x2160 (1920x1080 CSS, device scale 2), dark theme, taken 2026-10-04 from a
running AICL console with real traffic (real Claude Code + Codex CLIs through the gateway, mock upstreams).
`*-full.png` = full page (taller). Demo principals: anna.k (platform), marek.w (payments), data-team (Codex),
ci-agent (strict).

- capture/assets/overview.png - Management overview: AI requests 42, Blocked 10 "threats stopped before execution", Redacted 28 "data removed in flight", Clients protected 4, API spend $1.72 (0.4% of $400), Security posture 100% (9/9 controls enforced), AICL overhead 4.37 ms p50, Bypass attempts 0. Charts: requests over time (allowed/redacted/blocked), findings by category doughnut.
- capture/assets/overview-full.png - the same plus Budgets per principal table (tokens, USD, burn bars) and Traffic by API contract (Anthropic Messages vs OpenAI Responses).
- capture/assets/clients.png - Clients & spend: data-team / Codex / gpt-5.5; anna.k, marek.w, ci-agent / Claude Code / claude-opus-5-5, sonnet, haiku; requests, blocked (red), redacted (amber), tokens, USD, last seen.
- capture/assets/security.png - Live events table (ALLOW / REDACT / BLOCK badges, client + tool, model, controls, ms) with the Explain panel open on a TOOL_CALL_BLOCKED: data-team Codex exec_command, findings CODE-AG-001 credential store read, CODE-AG-003 exfiltration, full trace.
- capture/assets/controls.png - Controls catalog DLP-01, DLP-02, DLP-05, INJ-03, INJ-04, TOOL-01, BUD-01, KILL-01, ACCESS-01 with enforce switches (INJ-04 per profile: strict/balanced enforce, permissive shadow) and hit counts.
- capture/assets/policy.png / policy-full.png - Policy page: live policy hash, profile balanced, 23 signature rules with inline tests; Interception (transparent, passthrough, api.anthropic.com, api.openai.com), Native block contract (http_400 / assistant text), Clients identity, Signed feed card; budget editor; full page includes the policy.yaml viewer.
- capture/assets/performance.png - Decision p50 4.37 ms, p95 12.79 ms, per-control latency bar chart and table.
- capture/assets/network.png / network-full.png - Network & bypass: flow diagram laptop -> AICL DNS :53 -> gateway :443 -> api.anthropic.com / api.openai.com with the dropped direct path; intercepted AI domains table.
- capture/assets/playground.png - Playground: prompt with PESEL + AWS key sent through the gateway, decision headers and per-stage trace.
- capture/assets/audit.png - Audit export (JSONL / CSV buttons).
- capture/terminal/transcripts.txt - exact terminal output of 11 real scenarios (injection 400, .env tool block, redactions, exfil block, curl|sh block, budget 402, live strict edit). Use these strings verbatim in terminal frames.

Fresh measurements (2026-10-04, `make test`, `make bench`, laptop CPU):
- 1057 tests passed (re-run 2026-10-04 ~09:40 on HEAD a006f08; first run that morning: 1011).
- decide() small prompt p50 0.07 ms; tool call p50 0.04 ms; 400 KB Claude Code turn p50 85 ms.
- Gateway passthrough overhead on a 222 KB Claude Code request: p50 33.8 ms.

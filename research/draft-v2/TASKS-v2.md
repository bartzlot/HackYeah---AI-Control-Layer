# TASKS - single source of truth for who does what (DRAFT v2: confirm at the first SYNC)

Edited ONLY by `scripts/task.sh` (atomic claim via push to main) once T-001 lands. Never edit by hand, except humans at SYNC.
Legend: `[ ]` open, `[~]` claimed, `[x]` done (landed on main, check.sh green), `[!]` blocked.
Line format: `- [s] T-NNN [piece] title | deps: T-..., T-... | claimed: who ts | done: ts`
Piece tags: `lead` (contracts, branch main), `w1`..`w6`, `any`. Tier in the title: (T1) must, (T2) should, (stretch) cut first.
Design reference for every task: `research/07-architecture.md`. Acceptance = the piece's `check.sh` covers it; every control task ships its `cases/<control>.yaml` (allowed + blocked).

## lead - setup and contracts (first hour, before builders depend on them)
- [ ] T-001 [lead] (T1) repo setup: AGENTS.md + CLAUDE.md + .omp/RULES.md adapted from HackYeah for 6 pieces; scripts/task.sh accepts w6; branches w1..w6 with wN-*/check.sh at PHASE=0; uv workspace (Python 3.13) root pyproject + Makefile (up, test, test-all, ca, feed-publish, onboard, demo) | deps: -
- [ ] T-002 [lead] (T1) contracts/aicl_contracts.py: Stage (navigation, request, upload, response, tool_*, artifact, infra), Action (allow, monitor, redact, coach, block), Who, Event, Part (with JSON path), UploadInfo, ToolInfo, Usage, Finding, Span, Decision, Ctx, Control protocol per research/07 | deps: -
- [ ] T-003 [lead] (T1) contracts/policy.example.yaml (fully annotated: identity, apps overrides, tenant, controls, profiles, quotas, models, privacy, notifications, feed) + policy/policy.yaml + policy/local.d/ | deps: T-002
- [ ] T-004 [lead] (T1) contracts: rules.md (aicl-rules/1 from research/04), catalog.md (aicl-catalog/1 from research/10), case.example.yaml, audit.md (incl. evidence + reveal), PORTS.md (ports, endpoint onboarding steps) | deps: T-002

## w1-ingress - proxy, onboarding, identity, app control, generic adapter
- [ ] T-101 [w1] (T1) spike S1a: mitmproxy 12.2.3 regular on LAN :18080 with upstream_cert=false, connection_strategy=lazy, allow_hosts; `make ca` name-constrained CA; trust via security add-trusted-cert; PAC for AI hosts; QUIC off; headed logged-in Chrome reaches chatgpt.com / claude.ai / gemini / copilot (pair with w4 for S1b); results in w1-ingress/NOTES.md | deps: -
- [ ] T-102 [w1] (T1) spike S2: mitmproxy DumpMaster + two uvicorn apps (portal :18001, console :18000) in one asyncio loop, clean shutdown | deps: -
- [ ] T-103 [w1] (T1) addon skeleton: flow -> Events -> decide() -> apply Decision; Who + catalog app into Ctx; never log cookies, Authorization, Proxy-Authorization or API keys | deps: T-002, T-101
- [ ] T-104 [w1] (T1) ID-01 identity resolver: policy IP map (exact + CIDR), live registrations from the notifier agent, anonymous strictest fallback; http://aicl.test/ whoami page | deps: T-103
- [ ] T-105 [w1] (T1) APP-01 catalog routing: decrypt list -> allow_hosts, PAC generator (host-only rules), actions sanctioned / coach / unsanctioned / unreviewed with per-department overrides, block page for navigations (template from w6) | deps: T-103, T-004
- [ ] T-106 [w1] (T1) generic adapter: string leaves of JSON / form / multipart / WebSocket text, nested JSON up to 3 levels, in-place redaction by JSON path, 403 JSON for XHR/fetch, fallback target for w4 drift | deps: T-103
- [ ] T-107 [w1] (T1) UPL-01 plumbing: requestheaders size gate (25 MB scan cap), spool to temp, hand-off to the w3 scanner, verdict cache per file id / sha256, unscannable policy | deps: T-103
- [ ] T-108 [w1] (T2) APP-02 tenant restrictions: inject ChatGPT-Allowed-Workspace-Id, anthropic-allowed-org-ids, OpenAI-Allowed-Organization-Ids from policy; block ChatGPT /backend-anon/; Google / Microsoft headers documented as inject_only | deps: T-105
- [ ] T-109 [w1] (T2) internal LLM reverse :18434 -> OLLAMA_URL with GPU-seconds from durations + INFRA-01 admin endpoint shield (pull / push / create / delete / copy / blobs) | deps: T-103
- [ ] T-110 [w1] (T2) WebSocket plumbing: per-frame Events, ws_policy inspect | drop, drop frame on block | deps: T-106
- [ ] T-111 [w1] (T2) spike S6 desktop apps: ChatGPT.app and Claude.app through the proxy; pinned -> tunnel + SNI app control; results in NOTES.md | deps: T-105
- [ ] T-112 [w1] (stretch) optional proxyauth identity (htpasswd per-device tokens); WireGuard / local-capture notes | deps: T-104

## w2-core - policy, decision, feed, catalog, test runner (lead's piece)
- [ ] T-201 [w2] (T1) policy engine: policy.yaml + local.d, pydantic validation, profile + department resolution, 1 s mtime polling, last-good on invalid, policy_version, reload events | deps: T-003
- [ ] T-202 [w2] (T1) decide(): stage routing (navigation, request, upload, response, agent stages), control registry, stop at first block, parallel semantic with per-control timeout, fail open/closed, monitor mode, action merge, redaction helper, per-control latency | deps: T-002, T-201
- [ ] T-203 [w2] (T1) `aicl up`: proxy + portal + console in one process, /health with degraded status, `make up` | deps: T-102, T-202
- [ ] T-204 [w2] (T1) test runner: collect w*/cases/*.yaml, drive the real proxy in-process against the w4 replay simulator, markers fast/semantic/live, reports/ junit + html + coverage_matrix.md, meta-test allow+block per enabled control | deps: T-004, T-106, T-405
- [ ] T-205 [w2] (T1) config tests: control removed -> its blocked case passes; department override applies < 2 s; invalid YAML keeps last-good + event; mode block -> monitor -> off | deps: T-201, T-204
- [ ] T-206 [w2] (T1) catalog seed: v2fly category-ai (MIT, NOTICE) + ~10 curated apps (risk 0-100 with reasons, evidence links, decrypt flag, adapter kind, tenant header) in feed/catalog/ | deps: T-004
- [ ] T-207 [w2] (T2) feed publisher feed/ on :18100: bundle rules (w3-dlp/rules) + catalog + semantic signatures, Ed25519-signed manifest, ETag, `make feed-publish` | deps: T-004, T-206
- [ ] T-208 [w2] (T2) feed poller: verify, reject rollback / expired, inline tests via the w3 engine, atomic swap, last-good, regenerate PAC + decrypt list on catalog change, local layer policy/local.d (source=local), feed metrics | deps: T-207, T-302, T-105
- [ ] T-209 [w2] (T2) feed tests: new signed rule blocks within one poll; new catalog entry blocks a new AI domain; tampered byte rejected + last-good kept; rollback rejected | deps: T-208, T-204
- [ ] T-210 [w2] (stretch) fetchers: OpenSSF malicious-packages (for HIST-01), KEV / OSV / ATLAS metadata into the publisher | deps: T-207

## w3-dlp - deterministic content controls, uploads, signatures
- [ ] T-301 [w3] (T1) INJ-01 normalization (NFKC, Unicode tags, zero-width, bidi) + INJ-02 decode-and-rescan (base64 / hex / rot13 / url, depth <= 3) | deps: T-002
- [ ] T-302 [w3] (T1) rule engine: aicl-rules/1 -> google-re2 + Aho-Corasick + YARA-X, stage / scan selectors, inline tests, per-rule circuit breaker (spike S5 first) | deps: T-004
- [ ] T-303 [w3] (T1) DLP-01 secrets (gitleaks TOML import, MIT) + API-key registry (HMAC of corporate keys; personal vs corporate) | deps: T-302
- [ ] T-304 [w3] (T1) DLP-02 PII with checksums: email, phone, card Luhn, IBAN mod-97, PESEL, NIP, REGON | deps: T-302
- [ ] T-305 [w3] (T1) DLP-06 custom dictionaries from policy (codenames, customer names), word boundaries, case folding | deps: T-302
- [ ] T-306 [w3] (T1) upload scanner + DLP-09: filetype + Magika, ZipInfo bomb guard, defusedxml, MSIP labels (docProps/custom.xml, LabelInfo.xml), CONFIDENTIAL markings, extraction (pypdf, python-docx, openpyxl, python-pptx) in a worker process with 5 s / 2 MB caps | deps: T-002
- [ ] T-307 [w3] (T1) INJ-03 jailbreak / injection signatures for acceptable use + converted nova-rules keywords (MIT), mention-vs-use exceptions | deps: T-302
- [ ] T-308 [w3] (T2) DLP-05 source code on 400-byte chunks via Magika, README-style exceptions | deps: T-306
- [ ] T-309 [w3] (T2) DLP-07 exact data match: HMAC-SHA256/96 index of demo customer records, candidate-token lookup | deps: T-302
- [ ] T-310 [w3] (T2) history pack: jailbreak families, HIST-01 slopsquatting / malicious package names in answers, EXF-01 exfil links in answers, exploit patterns; CVE / GHSA / ATLAS mapped, inline tests | deps: T-302
- [ ] T-311 [w3] (T2) ART-01 Hugging Face artifact scan: pickletools opcode walk (never load) + YARA-X | deps: T-302, T-107
- [ ] T-312 [w3] (T2) agent rules: TOOL-02 dangerous commands, EXF-02 egress allowlist on tool args, MCP-01 tool-description poisoning | deps: T-302
- [ ] T-313 [w3] (stretch) DLP-08 document fingerprints (own simhash + shingle containment) for protected documents | deps: T-302

## w4-apps - precise app adapters, fixtures, simulators
- [ ] T-401 [w4] (T1) spike S1b (pair with w1): human, own accounts, headed Chrome through the proxy: one benign prompt + one upload on ChatGPT, Claude, Gemini, Copilot; sanitizer script strips cookies, tokens and ids; dated fixtures in w4-apps/fixtures/<app>/ | deps: T-101
- [ ] T-402 [w4] (T1) OpenAI + Anthropic API adapters (chat / messages, tools, tool_calls, SSE buffer + re-emit, usage) + API simulator that needs no keys | deps: T-103
- [ ] T-403 [w4] (T1) ChatGPT web adapter: /backend-api/f/conversation parts, SSE answer parse, in-app block message, upload flow (/backend-api/files + PUT *.oaiusercontent.com + /uploaded), drift -> generic | deps: T-401, T-106
- [ ] T-404 [w4] (T1) Claude web / desktop adapter: .../completion prompt + attachments, /upload + /convert_document, SSE parse, in-app block message, drift -> generic | deps: T-401, T-106
- [ ] T-405 [w4] (T1) replay simulator: serves recorded fixtures per app + an echo upstream for the generic adapter; host rewrite in test mode; used by T-204 | deps: T-401
- [ ] T-406 [w4] (T2) Gemini web adapter: f.req nested JSON decode / re-encode, content-push upload, block = 403 | deps: T-401, T-106
- [ ] T-407 [w4] (T2) Copilot web adapter: WebSocket frames {event: send, content}, POST /c/api/attachments, block = drop frame + error frame | deps: T-401, T-110
- [ ] T-408 [w4] (T2) Gemini API adapter (generateContent, streamGenerateContent) | deps: T-402
- [ ] T-409 [w4] (stretch) Perplexity adapter (/rest/sse/perplexity_ask query_str) | deps: T-106

## w5-semantic - AI-based controls, quotas, budgets, usage analytics
- [ ] T-501 [w5] (T1) model assets: `make models` (Wolf Defender v2 small + bge-small-en-v1.5 ONNX, pinned revisions + sha256, no torch); judge model on the model host Ollama; demo-Mac runbook | deps: -
- [ ] T-502 [w5] (T1) spike S3: ONNX latency on M5 CPU (p50 / p95); judge latency qwen3.5:4b vs clef-flash; judge quality on 20 labelled confidential / benign examples | deps: -
- [ ] T-503 [w5] (T1) INJ-04 stage 1: Wolf score + bge-small kNN over feed semantic signatures, cases marked semantic | deps: T-002, T-502
- [ ] T-504 [w5] (T1) corpora + calibration: attack + benign incl. security questions and everyday office prompts, thresholds per profile, reports/semantic.md | deps: T-503
- [ ] T-505 [w5] (T2) SEM-01 judge on the gray band: confidential business information + harmful request, datamarked input, yes/no output, timeout + fail mode | deps: T-503
- [ ] T-506 [w5] (T1) GOV-03 quotas and budgets: user / department scopes, prompts/day, est. tokens (tiktoken o200k offline), API USD (pinned price map, reserve then settle), internal LLM GPU-s; block + notification, 429 for APIs | deps: T-002, T-003
- [ ] T-507 [w5] (T1) GOV-04 limits: rate per user, body size, wall clock, internal LLM concurrency | deps: T-506
- [ ] T-508 [w5] (T2) GOV-05 anomalies: huge paste, bulk / automation, off-hours, upload burst, app sprawl, key sharing, non-entitled model; API for the dashboards | deps: T-506
- [ ] T-509 [w5] (T2) TOOL-05 loop breaker for agent API traffic (identical call hash x4, max steps 25 per session) | deps: T-506
- [ ] T-510 [w5] (T1) degraded mode: /health lists missing models, controls follow their fail policy, offline suite unaffected | deps: T-503
- [ ] T-511 [w5] (stretch) garak before / after on the API path | deps: T-505, T-402

## w6-console - audit, evidence, portal, notifier, dashboards, demo
- [ ] T-601 [w6] (T1) audit store (JSONL hash chain + SQLite index) + evidence store (full text for blocked events only, separate 0600 file, 30-day purge, reveal needs a reason and is audited) + `aicl audit verify` | deps: T-002, T-004
- [ ] T-602 [w6] (T1) metrics: /metrics aicl_* (decisions, blocks by control / app / department, latency histograms, quota use, feed age) + in-process SSE bus | deps: T-002
- [ ] T-603 [w6] (T1) endpoint portal :18001: /onboard (monitoring notice + steps), /proxy.pac and /ca.cer (from w1), /notify SSE scoped by source IP, /me (my AI activity) | deps: T-602, T-105
- [ ] T-604 [w6] (T1) notifier agent: stdlib Python, SSE client, macOS osascript (terminal-notifier if present), registers user + hostname + IP; Windows toast + Linux notify-send (T2); LaunchAgent plist | deps: T-603
- [ ] T-605 [w6] (T1) admin console :18000: Posture (controls, modes, coverage), live Threats, Shadow AI (apps, sanctioned share, departments), Users drill-down with audited evidence reveal | deps: T-601, T-602
- [ ] T-606 [w6] (T2) Usage page (quotas, API USD, GPU-s, equivalent cost, anomalies) + Performance page (p50 / p95 per control) | deps: T-605, T-506
- [ ] T-607 [w6] (T2) Feed & Policy page (versions, reloads, rejected reloads) + exports JSONL / CSV / CEF + docs/ocsf-ecs-mapping.md | deps: T-605, T-208
- [ ] T-608 [w6] (T1) block page, coach page and in-app message texts (shared by w1 / w4) | deps: T-603
- [ ] T-609 [w6] (T1) demo kit: personas in the IP map, synthetic customer data, generator for Purview-labelled docx / pptx / xlsx / pdf, scenario scripts, agent demo (Claude Code or OpenAI SDK through the proxy) | deps: T-104
- [ ] T-610 [w6] (T2) docs: architecture diagram PNG, README quick start, policy guide, endpoint onboarding guide, deployment + legal checklist (DPIA, 14-day notice) | deps: T-203
- [ ] T-611 [w6] (T2) console hardening: admin token, portal IP-scoped, cookies / auth headers never logged, evidence file permissions | deps: T-605

## integration and delivery
- [ ] T-901 [any] (T1) walking skeleton by 20:00: browser through PAC -> chatgpt.com (or generic echo) -> DLP-01 block -> notifier popup -> audit + Threats page | deps: T-104, T-105, T-106, T-202, T-303, T-601, T-603, T-604 | pair: w2+w1
- [ ] T-902 [any] (T2) perf benchmark: prompt path and upload path, direct vs through the proxy, p50 / p95 / p99, reports/perf.md | deps: T-901
- [ ] T-903 [any] (T2) judge drills: live policy edits (department overrides, mode flips), feed publish / tamper, catalog add, ad-hoc prompts incl. benign security and office questions; fix false positives | deps: T-205, T-209, T-504
- [ ] T-904 [any] (T1) demo rehearsal on the real demo network + zero-prep instructions test by someone who built nothing | deps: T-609, T-903, T-610

# TASKS - single source of truth for who does what

Edited ONLY by `scripts/task.sh` (atomic claim via push to main). Never edit by hand, except humans at SYNC.
Legend: `[ ]` open, `[~]` claimed, `[x]` done (landed on main, check.sh green), `[!]` blocked.
Line format: `- [s] T-NNN [piece] title | deps: T-..., T-... | claimed: who ts | done: ts`
Piece tags: `lead` (shared contracts, branch main), `w1`..`w5`, `any` (anyone). The lead also owns w2.
Pair tasks carry `pair: X+Y`: the claimer drives, the partner commits too, the claimer marks done.
Tier in the title: (T1) must, (T2) should, (stretch) cut first. At FREEZE every open T2/stretch task is CUT.
Design reference for every task: `research/13-architecture.md` (section numbers in brackets). Acceptance = the piece's `check.sh` covers it; every control task ships `cases/<control>.yaml` with at least one allowed and one blocked/redacted case.

## lead - shared contracts (first hour, before builders depend on them)
- [ ] T-001 [lead] (T1) repo bootstrap: uv workspace (Python 3.13) with packages aicl_contracts, aicl_gateway, aicl_core, aicl_detect, aicl_semantic, aicl_console; Makefile (up, down, test, test-all, models, feed-publish, demo, bench); docker-compose.yml (gateway dual-homed, agentnet internal, cloud-sim, feed, mcp-corp, mcp-evil, demo-agent; Ollama stays on the host); .env.example [20] | deps: -
- [ ] T-002 [lead] (T1) contracts/aicl_contracts.py: Event (kind, channel, parts with JSON path, identity chain, destination, tool, usage), Span, Finding, Decision (action lattice ALLOW < LOG < WARN < REDACT < REQUIRE_APPROVAL < BLOCK, redactions, explain trace, policy_version, latency_us per stage, degraded), Control protocol, Ctx [2, 3] | deps: -
- [ ] T-003 [lead] (T1) contracts/policy.example.yaml (annotated, every top-level key of [12]) + policy/policy.yaml + policy/local.d/ | deps: T-002
- [ ] T-004 [lead] (T1) contracts: rules.md (aicl-rules/1 [11]), case.example.yaml (test case format [15]), audit.md (event types + JSON schema [13]), PORTS.md (listeners, upstreams, demo URLs) | deps: T-002

## w1-gateway - data plane ingress, identity, SDK
- [ ] T-101 [w1] (T1) one process, two listeners: data plane :18080 (agentnet) and console :18000 (host only, admin token); /health with degraded flags; Server-Timing header; WebSocket upgrades refused [2] | deps: T-001, T-002
- [ ] T-102 [w1] (T1) PEP A: /v1/chat/completions + /v1/models (OpenAI-compatible, non-stream) -> decide(llm.request / llm.response) -> upstream router (Ollama local, cloud-sim priced mock); clamp max_tokens and num_ctx, force stream_options.include_usage, strip logprobs/logit_bias [3, 4] | deps: T-101
- [ ] T-103 [w1] (T1) streaming: SSE hold-back buffer (longest rule span, min 64 chars) with decide(llm.response.window), tool_call deltas assembled before decide(llm.tool_call), mid-stream block = assistant notice + finish, usage settle (actual or estimated) [3] | deps: T-102
- [ ] T-104 [w1] (T1) identity Tier 0 + broker: per-agent API keys (sha256 at rest) -> principal; X-AICL-User/-Session/-Parent-Agent compared with the key (mismatch = 403 impersonation); traceparent correlation, baggage stripped; client Authorization stripped, upstream credential injected [9] | deps: T-101
- [ ] T-105 [w1] (T1) PEP B: MCP Streamable HTTP proxy /mcp/<server> (2026-07-28 and 2025-11-25 eras): Mcp-Method/Mcp-Name vs body, batches rejected, decide(mcp.tools_list) with pin hook, decide(mcp.tool_call), decide(mcp.tool_result), isError denials, Origin/Host allowlist [8] | deps: T-101, T-104
- [ ] T-106 [w1] (T2) Ollama native passthrough /api/chat, /api/generate (NDJSON); admin paths (/api/pull, push, create, delete, copy, blobs) denied unless policy allows the exact model + digest [8, 11] | deps: T-102
- [ ] T-107 [w1] (T2) PEP C: Python SDK `aicl` (guard, secure_tool, secure_mcp, secure_memory) over POST /v1/guard; OpenAI Agents SDK tool-guardrail adapter [2] | deps: T-102
- [ ] T-108 [w1] (T2) stdio wrapper `aicl-mcp-wrap -- <cmd>`: spawns only commands pinned in policy, line-oriented JSON-RPC filter both ways via /v1/guard [8] | deps: T-105
- [ ] T-109 [w1] (T2) identity Tier 1: POST /token EdDSA JWT 300 s (sub, act chain, user, session, parent, scope, depth, max_depth, epoch); child exchange narrows scope and depth+1; agent epoch revocation [9] | deps: T-104
- [ ] T-110 [w1] (T2) memory API /v1/memory/<ns> read/write/delete over SQLite with provenance, HMAC and per-namespace hash chain; gateway-injected tenant filter; calls decide(memory.write / memory.read) [9.1] | deps: T-104
- [ ] T-111 [w1] (stretch) /v1/responses and Anthropic /v1/messages adapters [4] | deps: T-103

## w2-core - policy, decision core, tool firewall, test runner (lead's piece)
- [ ] T-201 [w2] (T1) policy engine: policy.yaml + local.d, pydantic validation, compile to an immutable snapshot, 1 s mtime polling + atomic swap, last-good on invalid + POLICY_RELOAD_FAILED, policy_version = sha256, POLICY_CHANGED with diff [12] | deps: T-003
- [ ] T-202 [w2] (T1) decide(): stage routing per event kind, control registry, parallel detectors with per-control timeout and fail mode, mode enforce/shadow/off, action lattice, channel trust, explain trace (rule, stage, score vs threshold, span, counterfactual), per-stage latency [5, 6] | deps: T-002, T-201
- [ ] T-203 [w2] (T1) redaction applier: span merge by priority, typed placeholders, JSON-aware (string leaves only), streaming-safe API for w1 [5] | deps: T-202
- [ ] T-204 [w2] (T1) tool firewall: default deny, roles -> tool allow / deny / require_approval, argument conditions via w3 validators, model allowlist per principal, deny > approve > allow [9] | deps: T-202
- [ ] T-205 [w2] (T1) approvals + kill switch: approval bound to (session, tool, args_hash), single use, TTL, 20 s hold then pending result, re-evaluated at consume; agent epoch and session-tree kill state [9] | deps: T-204
- [ ] T-206 [w2] (T1) destination-aware DLP: destination registry (model tag, provider, host, MCP server -> trust tier), data class = max over findings, matrix -> allow / redact / approve / block; session taint (untrusted + private + external egress -> REQUIRE_APPROVAL) [7] | deps: T-202
- [ ] T-207 [w2] (T1) test runner: collect */cases/*.yaml, drive decide() in-process and the live gateway against mock upstreams, markers fast / semantic / live / redteam, meta-test (each enabled control has an allowed and a blocked case), reports/junit.xml + report.html + coverage_matrix.md [15] | deps: T-004, T-202
- [ ] T-208 [w2] (T1) config-mutation tests: disabled control lets its blocked case pass; threshold flip; invalid YAML keeps last-good; shadow logs but allows; reload under 2 s [15] | deps: T-201, T-207
- [ ] T-209 [w2] (T2) policy simulation: replay the last N recorded (redacted) events through decide() with a candidate policy and report flips; POST /admin/policy/simulate [12] | deps: T-201, T-202
- [ ] T-210 [w2] (stretch) adaptive session risk: allow -> require_approval -> block escalation over a per-session window [6] | deps: T-202

## w3-detect - deterministic detectors, signed feed, supply chain
- [ ] T-301 [w3] (T1) normalization: views (raw, NFKC, casefold, invisibles stripped, 1:1 confusables) with one offset map; Unicode tag decode, bidi and zero-width flags; decode-and-rescan (base64, hex, url, html entities, rot13 common-word test; depth <= 3, size caps) [5] | deps: T-002
- [ ] T-302 [w3] (T1) rules engine aicl-rules/1: google-re2 + ahocorasick-rs prefilter + YARA-X; stage and channel selectors; inline must_match / must_not_match tests at load; per-rule circuit breaker [5, 11] | deps: T-004
- [ ] T-303 [w3] (T1) secrets: gitleaks TOML -> aicl-rules converter (MIT, NOTICE kept), entropy only with context, GitHub CRC32 check, PEM / JWT / connection strings, AWS doc sample stays detectable [5] | deps: T-302
- [ ] T-304 [w3] (T1) PII with validators: email, phone, card Luhn, IBAN mod-97, PL NRB, PESEL (checksum + date), NIP, REGON, ID card, IP ranges, internal hosts and URLs from policy [5, 7] | deps: T-302
- [ ] T-305 [w3] (T1) injection signatures EN + PL (override, role-play, prompt extraction, many-shot markers), noisy-OR score, channel-aware thresholds, mention-vs-use exceptions [5] | deps: T-301, T-302
- [ ] T-306 [w3] (T1) output filters: canary tokens, system-prompt 6-gram leak, markdown image/link exfil (host allowlist), nh3 for HTML clients, dangerous commands in code blocks [5] | deps: T-302
- [ ] T-307 [w3] (T1) tool-argument validators: jsonschema, SQL (sqlglot SELECT-only, function denylist, table allowlist, /*! rejected), shell (metachar deny + argv allowlist), path (realpath + commonpath jail), URL/SSRF (resolved IPs, private / link-local / metadata blocked, mapped IPv6 unwrapped, redirects re-checked), email domain allowlist, payment caps [9] | deps: T-002
- [ ] T-308 [w3] (T1) MCP metadata: scan every tools/list string (imperatives, hidden instructions, cross-tool mentions, ANSI, invisibles), canonical-JSON sha256 pin per (server, tool), drift -> quarantine + MCP_TOOL_DRIFT, shadowing and name collisions [8] | deps: T-302
- [ ] T-309 [w3] (T1) signed feed: publisher (`aicl feed publish`: rules + lists, Ed25519 manifest, ETag) and poller (signature, rollback, expiry, hashes, compile, inline tests, benign gate, last-good, atomic swap); local.d override layer with rule_source in audit [11] | deps: T-302
- [ ] T-310 [w3] (T2) history pack: ~30 rules with inline tests and CVE / ATLAS mapping (EchoLeak-style markdown exfil, tag smuggling, Langflow exec, mcp-remote, Probllama, slopsquat names, LiteLLM 1.82.7/1.82.8, malicious pickle sha256) [11] | deps: T-309
- [ ] T-311 [w3] (T2) supply-chain gate: extension policy, safetensors header check, pickle genops allowlist (never load), zip unwrap, .keras Lambda check, YARA-X; package installs in shell args checked against malicious-packages + typosquat distance [11] | deps: T-302
- [ ] T-312 [w3] (stretch) A2A agent card digest pin + near-duplicate name check [9] | deps: T-308

## w4-semantic - semantic cascade, calibration, fingerprints, budgets, loops
- [ ] T-401 [w4] (T1) model assets: `make models` fetches the pinned ONNX classifier and embedding model (revision + sha256), no torch at runtime; /health lists missing models; degraded mode keeps the deterministic path [6] | deps: T-001
- [ ] T-402 [w4] (T1) L2 classifier control (ONNX Runtime CPU, 512-token windows) on untrusted channels and on L1 suspicion; calibrated probability per category [6] | deps: T-002, T-401
- [ ] T-403 [w4] (T1) L3 kNN over attack exemplars from the feed (semantic leaf), sentence windows, numpy brute force [6] | deps: T-401
- [ ] T-404 [w4] (T1) L4 judge: Ollama structured output (JSON schema, temperature 0, think off), datamarked untrusted text, gray band or untrusted channel only, timeout + fail mode, verdict cache keyed by (normalized hash, policy_version) [6] | deps: T-402
- [ ] T-405 [w4] (T1) fusion + calibration: per-category fusion, thresholds per profile (strict / balanced / permissive = target benign FPR), dev set (attacks + benign incl. security questions and Polish office prompts), reports/semantic.md with AUROC [6] | deps: T-402, T-403
- [ ] T-406 [w4] (T1) budgets: hierarchical scopes (org, team, user, agent, session), reserve-then-settle in SQLite WAL (nano-USD, tokens, gpu_ms), GCRA rate limits, pinned price map (LiteLLM MIT subset), local gpu_s from Ollama durations, ladder warn 80% -> downgrade -> 429 + Retry-After [10] | deps: T-002, T-003
- [ ] T-407 [w4] (T1) loop guard: per-session ring of call hashes (repeat 4, error 3, ping-pong 6, max_steps 25, wall 600 s, depth 3, children 5), AGENT_LOOP_TERMINATED, trips the w2 kill state [10] | deps: T-406
- [ ] T-408 [w4] (T2) DLP fingerprints: winnowing index (k=5, w=4, hits >= 4, df <= 5), register-document admin endpoint, span highlight; embedding sensitivity kNN with live exemplars (log only) [7] | deps: T-302
- [ ] T-409 [w4] (T2) robustness report: public attack subset + benign set through the gateway per profile (detection rate, FPR), garak before/after on the API path in a 3.13 venv, reports/robustness.md [15] | deps: T-405
- [ ] T-410 [w4] (stretch) semantic scan of memory writes and RAG reads (encoder on the gray zone) [9.1] | deps: T-402, T-110

## w5-console - audit, telemetry, dashboard, demo kit, docs
- [ ] T-501 [w5] (T1) audit store: hash-chained JSONL + SQLite index, keyed HMAC of content instead of raw text, evidence for blocked events only (0600, TTL), `aicl audit verify`, exports JSONL / CSV / CEF [13] | deps: T-002, T-004
- [ ] T-502 [w5] (T1) metrics + live bus: /metrics aicl_* (decisions by control, action, agent; stage latency histograms; budget gauges; feed age), in-process SSE bus [13, 14] | deps: T-002
- [ ] T-503 [w5] (T1) console Overview (management): requests, allowed / blocked / redacted, attack categories, budget use, cost and tokens prevented, posture score [14] | deps: T-501, T-502
- [ ] T-504 [w5] (T1) console Threats (security): live list, filters, event detail with explain trace, identity chain and replay button [14] | deps: T-501
- [ ] T-505 [w5] (T1) playground: ad-hoc prompt, tool call or MCP message -> decision + explanation, destination selector [14, 22] | deps: T-504
- [ ] T-506 [w5] (T1) demo kit: corp-tools MCP server (inert read_database, delete_database, send_email, run_shell, fetch_url), evil-tools MCP server (poisoned description, rug-pull toggle), cloud-sim priced mock upstream (scripted mode for tests), demo agent (Chat Completions loop through the gateway), synthetic data + protected memo [22] | deps: T-001
- [ ] T-507 [w5] (T2) Policy page (editor writing policy.yaml, diff, simulation flips, reload status, shadow / enforce toggles) + Feed page (version, age, rejected bundles) [14] | deps: T-503, T-209
- [ ] T-508 [w5] (T2) Approvals + kill switch UI; Agents page (identity chain graph from audit, top risky agents and tools) [14] | deps: T-504, T-205
- [ ] T-509 [w5] (T2) Budgets + Performance pages (p50 / p95 per stage, Server-Timing, cache hits) [14] | deps: T-503, T-406
- [ ] T-510 [w5] (T2) docs: architecture diagram (SVG from mermaid), README quick start, policy guide, judge guide (edit config live, run tests, read the audit) [2] | deps: T-503
- [ ] T-511 [w5] (stretch) OTel spans with gen_ai.* attributes to an optional collector [13] | deps: T-502

## integration and delivery
- [ ] T-901 [any] (T1) walking skeleton: demo agent -> gateway -> Ollama; AWS key redacted; MCP delete_database blocked; both events on the Threats page; covered by `make test` | deps: T-102, T-105, T-202, T-303, T-501, T-504, T-506 | pair: w1+w2
- [ ] T-902 [any] (T2) perf benchmark: direct vs through the gateway, p50 / p95 / p99 per path and per stage, reports/perf.md [3, 15] | deps: T-901
- [ ] T-903 [any] (T2) judge drills: live policy edits, feed publish and tamper, ad-hoc prompts incl. benign security questions; fix false positives | deps: T-208, T-309, T-405
- [ ] T-904 [any] (T1) demo rehearsal + zero-prep instructions test by someone who built nothing [22] | deps: T-901

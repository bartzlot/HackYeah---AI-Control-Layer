# CAPSULE - AI Control Layer (v3: confirm at the first SYNC)

- Topic: issuer PDF "CRIETRIA AI Control Layer". It is the source of truth; if this file disagrees with it, the PDF wins.
- Chosen: **AICL**, a self-hosted, local-first policy enforcement point for agents. One Python process with three enforcement points (OpenAI-compatible LLM gateway, MCP gateway, SDK `/v1/guard`) that all call one `decide(event, policy)`; hybrid deterministic + semantic controls; one hot-reloaded `policy/policy.yaml`; Ed25519-signed signature feed; budgets in tokens, USD and local GPU-seconds; hash-chained audit; dashboard with playground.
- Chosen by: research run 2026-10-03 evening (`research/00-13`), replacing draft v2 (employee browser egress proxy, kept in `research/draft-v2/` for facts). Design reference: `research/13-architecture.md` (section numbers in TASKS.md brackets).
- Stack: Python 3.13 + uv workspace; FastAPI + uvicorn, httpx, orjson; ruamel.yaml + pydantic; google-re2, ahocorasick-rs, yara-x, sqlglot, nh3, phonenumbers, jsonschema; onnxruntime (PIGuard ONNX, multilingual-e5-small); Ollama native on the host (qwen3.5:4b judge, shared with other projects); SQLite WAL; cryptography (Ed25519) + PyJWT (EdDSA); `mcp` SDK 2.3.0; prometheus-client; static HTML + Chart.js 4.5.1 + SSE; pytest. All runtime licences permissive (MIT / Apache-2.0 / BSD).
- Clock (set at kickoff, see AGENTS.md STATE): walking skeleton T0+4 h; Tier 1 green T0+10 h; Tier 2 green or CUT at FREEZE - 2 h; FREEZE; rehearsal; instructions test; SUBMIT.
- SEATS (fill in at kickoff): lead + w2 = ?, w1 = ?, w3 = ?, w4 = ?, w5 = ?. Demo laptop = Apple M5 32 GB (Ollama shared).

## 1. What we are building
- **Ingress:** agents run on a Docker `internal` network; their only route out is the gateway (`:18080`). `OPENAI_BASE_URL` points at PEP A; MCP clients point at `/mcp/<server>` or wrap stdio servers with `aicl-mcp-wrap`; in-process tools, memory writes and agent-to-agent messages call `/v1/guard`. Agents hold only gateway keys; the gateway injects upstream credentials.
- **Per event** `decide()` runs: identity (key -> principal, impersonation check, delegation scope) -> budget reserve -> L0 normalize -> L1 deterministic (signed feed rules, secrets, PII with checksums, injection signatures, output filters, tool-argument validators, MCP list scan + pins, artifact checks) -> L2 classifier + L3 kNN on untrusted channels or after an L1 signal -> L4 local judge on the gray band -> tool firewall (default deny, approvals, taint) -> destination matrix -> lattice ALLOW < LOG < WARN < REDACT < REQUIRE_APPROVAL < BLOCK -> redaction -> audit.
- **Control plane:** `policy.yaml` + `local.d/` reload in about a second with validation, last-good, hash, diff and simulation; feed publisher `:18100` signs bundles whose rules carry inline tests; approvals and kill switch from the console.
- **Records and reporting:** hash-chained JSONL audit with HMAC content (full text only for blocked events, 7 days), Prometheus `aicl_*`, `Server-Timing`, console `:18000` (host-only): Overview, Security, Event detail with explain trace and replay, Agents, Approvals, Policy, Feed, Budgets, Performance, Playground, Tests.
- **Demo kit:** demo agent (Chat Completions loop), `mcp-corp` (inert read / delete / send_email / run_shell / fetch tools), `mcp-evil` (poisoned description, rug-pull toggle), `cloud-sim` priced mock "commercial" model (scripted mode for tests).

## 2. Why this option
- The PDF asks for a gateway / proxy / SDK that developers integrate between agents, MCP, models and APIs, judged with a test suite, ad-hoc prompts and live config edits: an API gateway makes all three trivial to drive and to observe.
- Gaps verified in open-source tools that we fill [10]: one policy file for guardrails + budgets + MCP + identity with simulation; local-model budgets in GPU-seconds (others price Ollama at 0); destination-aware DLP; MCP pinning joined with the identity chain and taint; a signed feed whose rules carry inline tests.
- **Rejected:** draft v2's browser egress proxy as the MVP ingress (Cloudflare challenges, pinned desktop apps, per-app protocol drift, employee-monitoring law; moved to the roadmap); wrapping LiteLLM (Enterprise-gated guardrails, zero-priced local models skip budgets, poisoned 2026 releases); OPA/Cedar as the user-facing policy language (second language, no transforms or budgets); gated Llama models; Redis 8 (licence); WebSocket / gRPC / A2A / SPIFFE / own OAuth AS in the MVP.

## 3. What we know
- 00: one-screen facts and everything measured today. 01: threats, paths, 44-row matrix. 02: patterns, overhead, diagrams. 03: protocols and MCP. 04: deterministic engine. 05: models and fusion. 06: DLP and fingerprints. 07: tool authz and identity. 08: memory and budgets. 09: feed and supply chain. 10: landscape and differentiators. 11: policy, telemetry, dashboard. 12: tests, datasets, demo. 13: the decisions.

## 4. What we do not know
- Classifier, kNN and judge latency on the M5 under the shared Ollama (spike in hour 1, T-401); PIGuard vs Wolf Defender small on our benign / Polish dev set (decides L2).
- Whether `eval_count` includes qwen3.5 thinking tokens (one live call).
- How the demo MCP client surfaces `isError` denials and a 20 s approval hold (T-105 / T-205).
- Real false-positive rate on judges' prompts: measured by T-405 / T-409 / T-903, never assumed.
- The real deadline and seats.

## 5. Five pieces

| # | Directory | Input / output | Does | Does not touch | Waits for |
|---|---|---|---|---|---|
| w1 | `w1-gateway/` | HTTP / SSE / MCP / stdio -> Events; Decision -> responses | listeners, PEP A (OpenAI chat + stream guard, Ollama native + admin shield), PEP B (MCP proxy both eras, stdio wrapper), PEP C (SDK, `/v1/guard`, memory API), identity (keys, JWT, chain), credential broker | detector and policy logic | lead contracts |
| w2 | `w2-core/` (lead) | policy + Events -> Decision | policy engine (reload, last-good, simulation), `decide()` (registry, timeouts, shadow, lattice, explain), redaction applier, tool firewall, approvals, kill switch, destination matrix, taint, test runner, config tests | transports, detector internals | contracts (same person) |
| w3 | `w3-detect/` | Event parts -> Findings; `rules/*.yaml`, feed bundles | normalization + decode, rules engine (RE2 / AC / YARA-X), secrets, PII, injection signatures, output filters, tool-argument validators, MCP metadata + pins, supply chain, signed feed publisher + poller, history pack | transports, policy loader | lead contracts |
| w4 | `w4-semantic/` | Event parts -> Findings; ledger | model assets, L2 classifier, L3 kNN, L4 judge, fusion + calibration, fingerprints, budgets (tokens, USD, GPU-s), rate limits, loop guard, robustness report | deterministic rules, transports | lead contracts |
| w5 | `w5-console/` | audit events -> dashboards; demo traffic | audit + evidence + exports, metrics + SSE, console pages, playground, demo kit (agent, MCP servers, cloud-sim), docs | detection | lead contracts |

- Interface files (lead only): `contracts/*`, root `pyproject.toml` / `uv.lock` / `Makefile` / `docker-compose.yml` / `.env.example`, the structure of `policy/policy.yaml` (each piece edits only its own control blocks; YAML conflicts are mechanical; `uv.lock` conflicts: rerun `uv lock`).
- Landing order: contracts (T-001..T-004) -> walking skeleton T-901 at T0+4 h (w1 + w2 + w3 + w5) -> continuous. The semantic piece is never on the critical path (degraded mode keeps the deterministic demo alive).
- Test cases and fixtures live in the owner's dir (`wN-*/cases/`, `wN-*/tests/`).

## 6. How we check
- Per piece: `./wN-*/check.sh` = unit tests + the piece's `cases/*.yaml` through the runner + one step proving the test catches something (a blocked case must pass when its control is `off`). Offline, deterministic, no Ollama.
- Whole system: `docker compose up -d && make test` (offline, mock upstreams, < 60 s) -> `reports/junit.xml`, `report.html`, `coverage_matrix.md`; `make test-all` adds semantic, live and red-team markers; `make robustness`, `make bench`, `aicl audit verify`.
- Gates: T-901 green at T0+4 h, Tier 1 green at T0+10 h, Tier 2 green or CUT at FREEZE - 2 h. Cut order: research/13 section 19 (LATER list first, then Tier 2 in reverse task order).

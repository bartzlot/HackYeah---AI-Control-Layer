# CAPSULE - AI Control Layer (v4: transparent interception, confirm at SYNC)

- Topic: issuer PDF "CRIETRIA AI Control Layer" (repo root). It is the source of truth; if this file disagrees with it, the PDF wins. Verbatim sections 2-8 incl. the judging weights: `research/brief.md`.
- Chosen: **AICL**, a self-hosted policy enforcement point that sits on the network path of AI API clients (Claude Code, Codex, SDKs, agents). Our DNS resolver points the AI API hosts at the gateway, the gateway terminates TLS with the AICL CA, speaks each provider's native API contract, runs one `decide(event, policy)` (deterministic + semantic controls, dynamic rules, budgets) and forwards allowed traffic to the real provider with the client's own credentials. The end user configures nothing in the tool; the egress firewall (network infrastructure, not built by us) makes bypass impossible, and our DNS log detects attempts.
- Chosen by: v3 (research run 2026-10-03, `research/00-13`) gave the gateway + `decide()` + policy core; MVP rescope 2026-10-03 22:20 (3-4 h, 2 seats, `BACKLOG.md`); v4 2026-10-04 ~01:00 moves the main ingress from "agent sets OPENAI_BASE_URL" (user can unset it) to transparent DNS + TLS interception. Design reference: `research/14-transparent-interception.md` (wins on ingress), `research/13-architecture.md` (everything else; section numbers in TASKS.md brackets).
- Stack: Python 3.13 + uv workspace; FastAPI + uvicorn (TLS listener), httpx, orjson; ruamel.yaml + pydantic; dnslib (DNS); cryptography (CA + leaf); Ollama `qwen3.5:2b-q4_K_M` on CPU as the local model and the INJ-04 judge (`think: false`); SQLite (budgets); static HTML + Chart.js + SSE; pytest. Permissive licences only.
- Clock (AGENTS.md STATE): FREEZE Sun 07:00, rehearsal 08:00, instructions test 09:00, SUBMIT 09:30.
- SEATS: A = lead + w2 (branch main / w2), B = w1 (branch w1). w3, w4, w5 directories stay empty in the MVP (their scope is folded into w1 / w2 or parked in `BACKLOG.md`).

## 1. What we are building
- **Ingress, three modes, one gateway** [14 s.1]: C transparent (main): DHCP-provided DNS = AICL DNS, AICL CA trusted by the OS, nothing in the tool. B explicit proxy: `HTTPS_PROXY` + CA. A base URL: `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` (also the remote Cloud Run demo, T-012). The existing demo agent + `cloud-sim` + Ollama path stays as the offline demo and test upstream.
- **Native API contract** [14 s.3]: adapters for Anthropic Messages (`/v1/messages`), OpenAI Responses (`/v1/responses`) and OpenAI Chat Completions, streaming (SSE) included. Allowed traffic is forwarded unchanged except redacted spans; blocks come back as provider-native 400 errors (hard block), 402 (budget) or a normal assistant message `[AICL] ...` (soft block, blocked tool call, output redaction), so Claude Code and Codex render them as their own messages. Never `stop_reason: refusal`, 403, 429 / 5xx or mid-stream errors (spike: misleading text or automatic retries). Every other path is proxied byte-for-byte.
- **Per event** `decide()`: identity (client IP + key hash + user agent -> principal) -> budget reserve -> deterministic (secrets, PII with checksums, injection signatures EN + PL, historical rules, tool rules for coding-agent tools: Bash / shell / Write / apply_patch / WebFetch) -> semantic (INJ-04 local judge on the gray band, `tool_result` treated as untrusted) -> destination matrix -> lattice ALLOW < LOG < WARN < REDACT < BLOCK -> redaction -> audit.
- **Control plane:** `policy/policy.yaml` + `local.d/` reload in about a second with last-good and a sha256 version; new blocks `interception:` (hosts, protocols, DNS, TLS, block styles) and `clients:` (identity in passthrough mode) [14 s.4]; console editor for policy and budgets (T-107).
- **Network pieces** [14 s.5]: DNS resolver (intercepted hosts -> gateway, no AAAA, DoH resolvers sinkholed, everything else forwarded, every query audited); `aicl ca` (root CA, one leaf with SAN = all intercepted hosts, export + install guide); reference egress firewall rules in the docs.
- **Records and reporting:** JSONL audit + SSE bus; dashboard: posture, controls, live events with explain, clients (who, which tool, tokens, USD, blocks), DNS and bypass alerts (NET-01), cost, playground; `Server-Timing` per request; JSONL / CSV export.
- **Demo kit:** compose demo whose client container (Claude Code CLI, CA trusted, resolver = AICL DNS) sits on an `internal` network with no other route out (the firewall in miniature); live calls use our own provider credentials, the offline fallback and the test suite use mock upstreams.

## 2. Why this option
- The PDF wants a control layer "developers can easily integrate" and judges who test ad-hoc and edit the config live; transparent interception is the easiest integration there is (no change in the tool) and still an API gateway, so the test suite and live edits stay trivial to drive.
- Base-URL-only gateways are opt-in: a user who changes one variable leaves the control. Network interception + egress firewall is how commercial SSE products enforce it; we add AI-native parsing, coding-agent tool rules, destination-aware DLP, local judge and budgets per person.
- **Rejected:** browser / web-app interception (Cloudflare challenges, pinned desktop apps, per-app protocol drift: research/draft-v2/08) - API clients only; mDNS (only `.local` names, cannot answer `api.anthropic.com`); answering blocks with `refusal` or 403 (spike: Claude Code blames the provider or reports an auth failure); wrapping LiteLLM; OPA / Cedar as the policy language; Redis 8.

## 3. What we know
- 00-13: v3 research (threats, patterns, protocols, engines, DLP, identity, budgets, feed, landscape, policy, tests, decisions). 14: transparent interception, bypass model, native contract table measured on Claude Code 2.1.289 (2026-10-04), DNS / CA design, demo. brief: PDF verbatim incl. weights (robustness 30, architecture + performance 20, reporting 20, test suite 15, implementability 15).
- Built and green on main (TASKS.md): policy engine + `decide()`, detectors, tool rules, test runner with meta-test, OpenAI-compatible gateway, budgets + loop guard, dashboard, INJ-04 judge, walking skeleton, containers.

## 4. What we do not know
- How Codex CLI renders each block shape on `/v1/responses` and where a ChatGPT-login Codex sends traffic (spike in the Codex task).
- Whether the Claude Code native build trusts the OS CA store or only `NODE_EXTRA_CA_CERTS`; whether a name-constrained CA works with our own TLS listener.
- Latency of buffering a full SSE answer before release on long coding-agent turns.
- Whether judges can join our network for mode C (else they use mode A on Cloud Run).
- Real false-positive rate of the judge and the coding-agent tool rules on normal developer traffic.

## 5. Pieces (MVP, 2 seats)

| # | Directory | Does | Waits for |
|---|---|---|---|
| lead | contracts, root files, compose | Event fields (protocol, upstream host, client ip, credential hash, user agent), `interception:` + `clients:` policy structure, deps (dnslib), compose transparent demo network | - |
| w1 | `w1-gateway/` | provider adapters + native contract, passthrough router, TLS listener + `aicl ca`, DNS resolver, dashboard (clients, DNS), existing gateway / budgets / judge / console | lead contract task |
| w2 | `w2-core/` | `decide()`, policy engine, detectors, coding-agent tool rules, `tool_result` as untrusted channel, NET-01 bypass detection, test runner with `protocol:` cases and native-contract assertions | lead contract task |

- Interface files (lead only): `contracts/*`, root `pyproject.toml` / `uv.lock` / `Makefile` / `docker-compose.yml` / `.env.example`, the structure of `policy/policy.yaml`.
- Landing order: lead contract task -> Anthropic adapter + passthrough router (mode A works with real Claude Code) -> TLS + DNS (mode C) -> Codex adapter -> dashboard and NET-01.

## 6. How we check
- Per piece: `./wN-*/check.sh` = unit tests + `cases/*.yaml` through the runner + one mutation step (a blocked case must pass when its control is `off`). Offline, deterministic, no Ollama, no provider calls.
- Whole system: `make test` (offline, mock upstreams incl. recorded Claude Code / Codex requests and SSE replays) -> `reports/junit.xml`; marker `live` (not in `make test`) runs real Claude Code through the gateway.
- Gates: mode A with real Claude Code green before mode C starts; mode C demo green at FREEZE - 2 h or CUT to mode A. Cut order: research/14 section 11, then BACKLOG.

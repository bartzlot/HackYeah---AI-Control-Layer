# CAPSULE - AI Control Layer (DRAFT v2: confirm at the first SYNC)

- Topic: issuer PDF "CRIETRIA AI Control Layer". It is the source of truth; if this file disagrees with it, the PDF wins.
- Chosen: an inspecting egress gateway for the internal network. Employees' endpoints (browsers, desktop apps; agent tools as a secondary layer) reach external AI only through it. Built on mitmproxy + FastAPI; one hot-reloaded `policy/`; a signed feed of rules + AI app catalog; hybrid deterministic + semantic controls; a native notification on every block.
- Chosen by: team answers 2026-10-03 (latest 17:00 CEST). Design reference: `research/07-architecture.md` (section 1 = PDF traceability, section 3 = verified stack and licences). Facts: `research/00-summary.md`; endpoint facts in 08 (web apps), 09 (onboarding, identity, legal), 10 (catalog, uploads, DLP).
- Stack:
  - core: Python 3.13 + uv, mitmproxy 12.2.3, FastAPI + Jinja2/htmx/Chart.js, pydantic/PyYAML, SQLite WAL, prometheus-client, cryptography (Ed25519), pytest;
  - detection: google-re2 + pyahocorasick + yara-x, filetype + Magika, pypdf / python-docx / openpyxl / python-pptx + defusedxml, tiktoken, onnxruntime (Wolf Defender v2 small + bge-small-en-v1.5), Ollama (judge + internal LLM).
  - All runtime licences are permissive.
- Clock (ASSUMED = HackYeah, confirm): SYNC every 2 h on the hour; walking skeleton 20:00; Tier 1 green 02:00; Tier 2 green or CUT 05:00; FREEZE Sun 07:00; rehearsal 08:00; instructions test 09:00; SUBMIT 09:30.
- SEATS (fill in at kickoff): lead/w2 = ?, w1 = ?, w3 = ?, w4 = ?, w5 = ?, w6 = ?. Model host for dev = ?. Endpoint 2 laptop = ?

## 1. What we are building
- **Onboarding:** an employee's laptop gets two settings: a PAC URL (only AI domains go to our proxy) and our company CA, which is name-constrained to AI hosts.
- **Per request:** for every request to ChatGPT, Claude, Gemini, Copilot or an AI API, the gateway:
  1. finds the employee and department from the IP map (or the notifier agent's registration);
  2. applies app control from the signed catalog: sanctioned, coach, unsanctioned or unreviewed, with per-department overrides and tenant-restriction headers;
  3. inspects prompts and file uploads (text extraction + sensitivity labels) with deterministic DLP and a semantic cascade;
  4. checks answers for exfil links and malicious package names;
  5. enforces quotas and budgets (prompts, estimated tokens, API USD, internal LLM GPU-seconds).
- **On a violation:** the request is blocked. The app shows an in-app message (precise adapters) or a 403 / block page, and the notifier agent pops a native notification.
- **Agents (secondary):** agent tools on the same laptops get tool-call guards and loop caps on the same path.
- **Records and reporting:**
  - full prompt text is kept for blocked events only (30 days, audited reveal);
  - management sees shadow AI, departments, prevented events and cost;
  - security sees user / app / event drill-down;
  - everything is in a hash-chained audit with exports.

## 2. Why this option
- The PDF asks for a gateway / proxy that is easy to integrate. A PAC + CA egress proxy needs no change to any app, and it is how enterprises already govern AI use (Zscaler, Netskope, Cloudflare) [08, 09].
- The team focus is normal employees, so the biggest risks are data leaking in prompts and uploads, and shadow AI. The PDF's agentic and local-model-budget requirements are kept as a secondary layer on the same path.
- Judges edit config and feeds live, so we own the reload path (1 s policy reload, signed feed with last-good, local override layer).
- **Rejected:**
  - Decrypting ChatGPT desktop: certificate-pinned, so app control by SNI only.
  - Decrypting M365 Copilot: Microsoft advises bypass.
  - WPAD: security history.
  - Proxy authentication as the main identity: Electron apps cannot answer it.
  - Storing all prompts: GDPR minimisation.
  - LiteLLM as the base: Enterprise-gated guardrails, malicious PyPI release.

## 3. What we know
- 00: one-screen facts; 01: threats and control catalog; 02: tools and licences; 03: local models; 04: rule schema, feed, 30 historical attacks; 05: budgets and identity; 06: tests and reporting.
- 07: decisions, contracts, policy, data model, ports, demo, cut list.
- 08: per-app request and upload shapes, plus the spike: no proxy-caused breakage seen.
- 09: PAC, CA trust, identity, tenant headers, EU/PL legal.
- 10: catalog seed, upload pipeline with measured costs, human DLP set, usage model.

## 4. What we do not know
- Spike S1: does a headed, logged-in Chrome stay unchallenged by Cloudflare through our proxy on chatgpt.com and claude.ai? Live prompt and upload shapes for Claude, Gemini and Copilot. If the spike fails, those apps fall back to the generic adapter or app control only.
- Whether Claude.app trusts the OS store (S6).
- A real Purview-labelled document. Does a teammate have one?
- Real enterprise tenants for the tenant headers (none: demo against the simulator).
- The real deadline.
- Legal sign-off: production only.

## 5. Six pieces

| # | Directory | Input / output | Does | Does not touch | Waits for |
|---|---|---|---|---|---|
| w1 | `w1-ingress/` | endpoint flows -> Events; Decision -> response | mitmproxy on LAN, CA + PAC, identity resolver, catalog routing + app control + block pages, generic adapter, upload plumbing, WebSocket policy, tenant headers, internal LLM reverse + admin shield | detector logic | lead contracts |
| w2 | `w2-core/`, `feed/`, `policy/`, `tests/` | policy + Events -> Decision | policy engine + hot reload, `decide()`, `aicl up`, feed publisher + poller (rules + catalog), catalog seed, test runner + config / feed tests, integration | detector internals | lead contracts (same person) |
| w3 | `w3-dlp/` | Event -> Findings; `rules/*.yaml` | normalization, rule engine, DLP-01/02/05/06/07/09, upload scanner (types, extraction, labels), signatures + history pack, ART-01, agent tool rules | proxy, policy loader | lead contracts |
| w4 | `w4-apps/` | app traffic -> Events; in-app block messages | precise adapters (ChatGPT web, Claude web/desktop, Gemini web, Copilot WS, OpenAI / Anthropic / Gemini APIs), per-app upload flows, fixture capture + sanitizer + replay simulator, API simulator | detection | lead contracts, S1 |
| w5 | `w5-semantic/` | Event -> Findings; ledger | model assets, classifier + signature kNN, confidential-info judge, calibration, quotas / budgets / GPU-s / equivalent cost, usage anomalies, agent loop breaker | deterministic rules | lead contracts |
| w6 | `w6-console/` | audit events -> dashboards; notifications | audit + evidence store (retention, audited reveal), metrics, endpoint portal (onboard, PAC / CA download, notify, my activity), notifier agent, admin console (management + security), exports, demo kit, docs | detection | lead contracts |

- Interface files (lead only):
  - `contracts/*`;
  - root `pyproject.toml` (uv workspace) and `Makefile`;
  - `policy/policy.yaml` structure. Each piece edits only its own control blocks; YAML conflicts are mechanical.
  - `uv.lock` conflicts: rerun `uv lock`.
- Landing order: contracts (T-001..T-004) -> walking skeleton T-901 (w1 + w2 + w6, 20:00) -> continuous.
- Test cases and fixtures live in the owner's dir (`wN-*/cases/`, `w4-apps/fixtures/`).
- w3 and w4 carry the most work. At the first SYNC, move T2 tasks to `any` if they slip.

## 6. How we check
- Per piece: `./wN-*/check.sh` = unit tests + the piece's `cases/*.yaml` through the runner + one step proving the test catches something (a blocked case must pass when the control is `off`).
- Whole system: `make test` (offline: recorded app fixtures replayed by the simulator, synthetic labelled documents, no models, no internet, under 60 s) -> `reports/junit.xml`, `report.html`, `coverage_matrix.md`. `make test-all` adds `semantic` and `live`.
- Gates: T-901 green 20:00, Tier 1 green 02:00, Tier 2 green or CUT 05:00, FREEZE 07:00. The cut order is in `07` section 14.

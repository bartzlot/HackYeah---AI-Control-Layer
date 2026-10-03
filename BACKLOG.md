# BACKLOG - work cut from the 3-4 h MVP

Not a task board. To bring an item back: `scripts/task.sh add "[piece] title | deps: ..."`.
"was T-xxx" = task id in the original plan (commit 0c05475); design in `research/13-architecture.md` [section].

## Priority 1 - quick add-ons to the MVP
- GPU-seconds budget for Ollama from prompt_eval_duration + eval_duration (was T-406) [10]
- Model downgrade ladder at 80% budget, x-aicl-budget-warning header (was T-406) [10]
- Shadow mode per control with would_decision (was T-202) [6]
- Hash-chained audit + `aicl audit verify` + CEF export (was T-501) [13]
- Normalization and decode-and-rescan: base64, hex, Unicode tags, zero-width, homoglyphs (was T-301) [5]
- Output filters: markdown image / link exfil, canary token, system prompt leak (was T-306) [5]
- Tool-argument validators: SQL via sqlglot, path jail, URL / SSRF resolved IPs (was T-307) [9]
- Pickle / artifact scanner `/v1/guard/artifact` (genops allowlist, never load) (was T-311) [11]
- SSE streaming with hold-back buffer and tool_call assembly (was T-103) [3]
- Impersonation check (X-AICL-* headers vs key), traceparent correlation (was T-104) [9]
- More PII: NIP, REGON, PL NRB, ID card, phone, IP ranges (was T-304) [5]

## Priority 2 - original Tier 1
- MCP Streamable HTTP proxy /mcp/<server> (was T-105) [8]
- MCP metadata scan + canonical sha256 pins, rug-pull quarantine (was T-308) [8]
- Signed feed: Ed25519 publisher + poller, rollback / tamper rejection (was T-309) [11]
- Approvals bound to args hash + kill switch (was T-205) [9]
- Session taint (lethal trifecta) -> REQUIRE_APPROVAL (was T-206) [7]
- Semantic cascade: model assets, ONNX classifier, kNN, fusion + calibration (was T-401..T-405) [6]
- Config-mutation tests (was T-208) [15]
- Threats page + event detail with replay (was T-504) [14]
- Demo MCP servers corp / evil (was T-506) [22]
- Metrics /metrics aicl_* + Server-Timing (was T-502) [13]

## Priority 3 - original Tier 2 and stretch
- Policy simulation over recent traffic (was T-209) [12]
- Adaptive session risk (was T-210) [6]
- Ollama native passthrough + admin shield (was T-106) [8]
- Python SDK + /v1/guard (was T-107) [2]
- stdio MCP wrapper (was T-108) [8]
- JWT delegation tokens (was T-109) [9]
- Memory API with provenance (was T-110) [9.1]
- Responses / Anthropic adapters (was T-111) [4]
- History pack ~30 rules with CVE / ATLAS mapping (was T-310) [11]
- Package / supply-chain gate (was T-311) [11]
- A2A agent card pin (was T-312) [9]
- DLP fingerprints, winnowing (was T-408) [7]
- Robustness report + garak (was T-409) [15]
- Semantic scan of memory / RAG (was T-410) [9.1]
- Dashboard pages: Policy, Feed, Approvals, Agents, Budgets, Performance (was T-507..T-509) [14]
- OTel spans (was T-511) [13]
- Perf benchmark (was T-902) [3, 15]
- Judge drills on false positives (was T-903)

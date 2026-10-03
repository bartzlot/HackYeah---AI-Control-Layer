# 02 - Tools landscape: which open-source gateways and guardrail frameworks can we build on (licences, maturity, Oct 2026)?

Verified 2026-10-03 against primary sources. `[INFERENCE]` = reasoning, not read anywhere.

Method: repo metadata (LICENSE file, release, push date, archived) via authenticated read-only `gh api` (scrapling hit GitHub's unauthenticated rate limit, 403); docs via scrapling. Boundary: detector accuracy = report 03, signature formats = 04. Helper agents surveyed MCP tools, guardrail libraries and secondary gateways; I spot-checked their licence/date claims (GoModel, ferro, Pipelock, AGT, Preloop, cpex, ACS, PyRIT, Portkey README).

## Established

### A. Master comparison
Verdict: BASE = could be our data plane, COMP = use as component/library, INSP = ideas only, SKIP.

| Name | Licence (from LICENSE) | Last release / push | Covers vs our criteria | Surface | Verdict |
|---|---|---|---|---|---|
| [agentgateway](https://github.com/agentgateway/agentgateway) (Rust; Linux Foundation, now AAIF) | Apache-2.0 | v1.6.0 2026-10-02 / 2026-10-03; 5.2k stars | LLM+MCP+A2A; per-key USD/token budgets (Block/Audit); allowedModels; regex/PII, moderation and webhook guards; ExtMCP gRPC guard; CEL authz; cost UI; Ollama | OpenAI HTTP, MCP streamable HTTP, A2A, ExtProc, webhook | BASE or reference architecture (sec. C) |
| [LiteLLM](https://github.com/BerriAI/litellm) (Py) | MIT except `enterprise/` = paid [BerriAI licence](https://github.com/BerriAI/litellm/blob/main/enterprise/LICENSE.md) (GitHub shows NOASSERTION) | v1.103.2 2026-10-01; 60k stars | virtual keys, budgets, OSS custom/Presidio/content-filter/generic-HTTP guardrails, MCP+A2A | OpenAI HTTP, Python | COMP with caveats (sec. B) |
| [GoModel](https://github.com/ENTERPILOT/GoModel) (Go) | MIT | v0.1.99 2026-10-03; created 2025-12 | budgets per path/label, RPM/TPM, guardrail plugins (prompt/response/stream; llm_judge, string_replace), audit, dashboard, Ollama ([docs](https://github.com/ENTERPILOT/GoModel/blob/main/docs/advanced/guardrails.mdx)) | OpenAI+Anthropic, Go plugins | COMP/BASE; pre-1.0, young |
| [Bifrost](https://github.com/maximhq/bifrost) (Go) | Apache-2.0; guardrails [Enterprise-only](https://github.com/maximhq/bifrost/blob/main/docs/enterprise/guardrails.mdx) | `ent-v2.2.5-base` 2026-10-02 is repo "latest"; OSS tag `transports/v2.2.5` | OSS: virtual keys, hierarchical budgets, rate limits, Go+WASM plugin hooks, MCP gateway | OpenAI HTTP, Ollama | COMP (own guardrail plugin) |
| [ferro-labs/ai-gateway](https://github.com/ferro-labs/ai-gateway) (Go) | Apache-2.0 | v1.5.9 2026-09-18; created 2026-02; 3 contributors | OSS plugins: regex-guard, pii-redact, secret-scan, injection shield, in-memory per-key USD budget | OpenAI HTTP | INSP; bus factor |
| [APISIX](https://github.com/apache/apisix) (Lua) | Apache-2.0 | 3.19.0 2026-09-28 | ai-proxy, ai-prompt-guard (regex), token-based ai-rate-limiting, Go/Python [plugin runners](https://github.com/apache/apisix/blob/master/docs/en/latest/external-plugin.md); no USD budget | HTTP | COMP if classic gateway wanted |
| [Agent Router](https://github.com/theagentrouter/agent-router) = ex Envoy AI Gateway | Apache-2.0 | v1.1.0 2026-08-21; repo moved, old links redirect | routing, token limits, MCP route; no guardrail feature seen in repo tree [INFERENCE] | K8s CRDs on Envoy; `aigw run` :1975 | SKIP |
| [Plano](https://github.com/katanemo/plano), [vllm semantic-router](https://github.com/vllm-project/semantic-router) | Apache-2.0 | 0.4.37 2026-09-28 / v0.4.0 2026-09-27 | Plano: HTTP/MCP [filter chain](https://github.com/katanemo/plano/blob/main/docs/source/concepts/filter_chain.rst); semantic-router: learned jailbreak/PII signals via ExtProc | Envoy | INSP |
| [Portkey gateway](https://github.com/Portkey-AI/gateway) (TS) | MIT | v1.15.2 2026-01-12; README still "2.0 Pre-Release"; PANW [acquired 2026-05-29](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-portkey-to-secure-ai-agents) | OSS guardrails incl. generic `webhook`, regexMatch, modelWhitelist; no budget enforcement code found | OpenAI HTTP | INSP |
| [Kong](https://github.com/Kong/kong) | Apache-2.0 repo; OSS binaries end 3.9.1 per [Kong staff](https://github.com/Kong/kong/discussions/14628) | 3.9.3 2026-06-17 (CVE patch) | OSS: ai-proxy, regex prompt-guard; token/cost limits, sanitizer, semantic guard are [Enterprise](https://developer.konghq.com/plugins/ai-rate-limiting-advanced/) | HTTP | SKIP |
| [TensorZero](https://github.com/tensorzero/tensorzero) | Apache-2.0 | 2026.6.0 2026-06-04; **ARCHIVED** 2026-06-11, company wound down ([secondary](https://byteiota.com/tensorzero-shuts-down-what-oss-llmops-cant-survive)) | - | - | SKIP |
| [Helicone](https://github.com/Helicone/helicone) | Apache-2.0 (its Rust `ai-gateway` repo is GPL-3.0) | Mintlify [acquired 2026-03-03](https://www.mintlify.com/blog/mintlify-acquires-helicone); maintenance mode | observability | - | SKIP |
| Higress, kgateway, traceloop hub | Apache-2.0 | v2.2.4 / v2.4.5 / 0.10.1 | Higress moderation hosted (Alibaba); kgateway AI guard [deprecated](https://kgateway.dev/docs/envoy/2.1.x/ai/prompt-guards) for agentgateway | - | SKIP |
| **MCP layer** | | | | | |
| [IBM ContextForge](https://github.com/IBM/mcp-context-forge) (Py) | Apache-2.0; PII/secrets/rate-limit plugins are separate PyPI `cpex_*` ([cpex-plugins](https://github.com/IBM/cpex-plugins), Apache-2.0) | v1.0.11 2026-09-28 | MCP+A2A gateway, hooks `tool_pre_invoke/post_invoke`, PII mask, secrets, EncodedExfilDetector, RBAC, Prometheus, UI; `requires-python <3.14`; restart for config | MCP streamable HTTP, REST | COMP/INSP |
| [Docker MCP Gateway](https://github.com/docker/mcp-gateway) (Go) | MIT | no GitHub Releases, tag v0.44.1; push 2026-09-23 | `--block-secrets`, `--watch`, **interceptors** `before/after:http:URL` replace tools/call request/result ([source](https://github.com/docker/mcp-gateway/blob/main/pkg/interceptors/interceptors.go)); tools/call only | stdio/SSE/streamable; needs Docker | COMP |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) (Go) | Apache-2.0 core + `enterprise/` dir under Elastic License 2.0 (budgets, dashboard) | v3.6.0 2026-10-03; created 2026-02; 919 stars | HTTP/WS/MCP/A2A proxy: DLP, entropy exfil detection, SSRF, injection and tool-poisoning scan, signed receipts, fsnotify/SIGHUP reload | proxy | COMP/INSP for exfil rules |
| [MS Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | MIT | v4.1.0 2026-06-09 / push 2026-10-03; "Public Preview" | YAML/OPA/Cedar policy, hash-chain audit, MCP gateway spec (poisoning, drift, typosquat), dashboard demo | Python lib | INSP/COMP (closest concept) |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Apache-2.0 | 4.8.6 2026-10-02 | offline YARA rules for MCP tool poisoning; LLM/cloud analyzers optional | Python lib/CLI | COMP (rules, see 04) |
| [Snyk agent-scan](https://github.com/snyk/agent-scan) | Apache-2.0 code, Snyk terms | v0.6.8 2026-09-29 | scan REQUIRES `SNYK_TOKEN` and uploads tool descriptions; no runtime proxy | CLI | SKIP (not local) |
| [Invariant Guardrails](https://github.com/invariantlabs-ai/invariant), [Lasso MCP GW](https://github.com/lasso-security/mcp-gateway), ToolHive, MetaMCP, MS MCP Gateway | Apache / MIT / Apache / MIT / MIT | Invariant: no releases, Snyk-owned since 2025-06; Lasso v1.2.0 2026-01-21; rest stale or K8s-only | tool-flow DSL; regex+Presidio plugins (best Lasso plugin needs paid key); Cedar authz. None gives local injection detection | - | INSP only |
| **Guardrail libraries** | | | | | |
| [Presidio](https://github.com/data-privacy-stack/presidio) (moved from microsoft/) | MIT | 2.2.364 2026-07-22; py 3.10-3.14 | PII redaction, custom regex/deny-list recognizers, `NoOpNlpEngine` (no model) or spaCy sm 12 MB / lg 400 MB | Python lib | **COMP, biggest ROI** |
| [gitleaks](https://github.com/gitleaks/gitleaks) rules | MIT | v8.30.1 2026-03-21; "feature complete", author moved to [Betterleaks](https://github.com/betterleaks/betterleaks) | `config/gitleaks.toml`: 222 regex+keyword+entropy rules, plain TOML | rules file | **COMP: secret rules** |
| [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | Apache-2.0 (NOASSERTION is a file-format artefact) | v0.24.1 2026-09-16; `py<3.14` | input/output rails, self-check LLM rails, YARA injection, Presidio; server `--auto-reload`; Ollama engine; **telemetry on by default** (`NEMO_GUARDRAILS_NO_USAGE_STATS=1`); no budgets | Python lib, FastAPI | INSP |
| [Guardrails AI](https://github.com/guardrails-ai/guardrails) | Apache-2.0 | v0.11.0 2026-08-14; `py<3.14` | validator pipeline; Hub install and hosted inference [shut down 2026-08-25](https://github.com/guardrails-ai/guardrails/issues/1560), validators now plain PyPI, no token; each validator's model weights have own licence | Python lib/REST | INSP |
| [LLM Guard](https://github.com/protectai/llm-guard) | MIT | PyPI 0.3.16 2025-05-19; **ARCHIVED 2026-07-08**, README: unmaintained incl. HF models; Protect AI bought by Palo Alto 2025-07 (helper-reported); pins `py<3.13`, `transformers==4.51.3` | 35 scanners | Python lib | SKIP as dep; reuse Apache-2.0 deberta model ids (03) |
| [LlamaFirewall / PurpleLlama](https://github.com/meta-llama/PurpleLlama) | repo root Llama 3.2 licence; `LlamaFirewall/`, `CodeShield/` MIT; PromptGuard 2 weights Llama 4 Community Licence, HF gated with manual approval | PyPI 1.0.3 2025-05-29; later commits lint only | PromptGuard 2 (86M/22M), AlignmentCheck (defaults to Together API; Ollama needs a small subclass [INFERENCE]), CodeShield | Python lib | COMP only for PromptGuard 2 if approval arrives |
| Vigil, Rebuff, detect-secrets, Superagent | Apache-2.0 / Apache-2.0 / Apache-2.0 / MIT SDK (weights CC-BY-NC-4.0) | pushes 2024-01 / 2024-08 archived / release 2024-05 / hosted API | dead, superseded by gitleaks rules, or hosted | - | SKIP |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | **AGPL-3.0** | v3.97.9 2026-09-24 | 800+ detectors that verify hits against live provider APIs (egress) | CLI | SKIP |
| [OpenGuardrails](https://github.com/openguardrails/openguardrails) | Apache-2.0 | v1.9 2026-09-18 | an event/verdict protocol (its model is 14.8B params), not an engine | spec | INSP |
| Test sources: [garak](https://github.com/NVIDIA/garak), [promptfoo](https://github.com/promptfoo/promptfoo), [PyRIT](https://github.com/microsoft/PyRIT), [OWASP ACS](https://github.com/GenAI-Security-Project/agent-control-standard) | Apache / MIT / MIT / Apache | v0.17.0 / 0.123.1 / v1.1.0 / no release | garak has `ollama`+`rest` generators; promptfoo [stays MIT after OpenAI deal](https://www.promptfoo.dev/blog/promptfoo-joining-openai); ACS = allow/deny/modify verdict + audit envelope spec | CLI / spec | COMP for tests (05), INSP for audit schema |

### B. LiteLLM in detail

| Question | Finding |
|---|---|
| Licence | MIT except `enterprise/` which needs the BerriAI subscription in production; copying/modifying for development and testing is allowed ([LICENSE](https://github.com/BerriAI/litellm/blob/main/enterprise/LICENSE.md)). Whether a hackathon demo counts is not stated [INFERENCE: gray]. |
| OSS ([docs](https://docs.litellm.ai/docs/enterprise)) | OpenAI-compatible gateway, virtual keys, spend tracking, budgets, fallbacks, request/response logging, Prometheus, custom guardrails, Presidio masking |
| Enterprise-only (same page) | key/team-scoped guardrails, audit logs, SSO beyond 5 users, tag budgets, per-key model budgets, spend reports, secret redaction, banned keywords; callbacks `llmguard_moderations`, `llamaguard_moderations`, `hide_secrets`, `openai_moderations`, `google_text_moderation`, `lakera_prompt_injection`, `aporia_prompt_injection` (code in [enterprise/](https://github.com/BerriAI/litellm/tree/main/enterprise/litellm_enterprise/enterprise_callbacks)) |
| OSS hooks (MIT tree) | `custom_guardrail`, sandboxed `custom_code`, `generic_guardrail_api` (HTTP call-out), `litellm_content_filter` (block/mask, categories incl. prompt-injection, data-exfiltration, malicious-code), `presidio`, `guardrails_ai`, `block_code_execution`, `tool_policy`, `mcp_security` ([tree](https://github.com/BerriAI/litellm/tree/main/litellm/proxy/guardrails/guardrail_hooks)); runtime CRUD at `/guardrails` ([code](https://github.com/BerriAI/litellm/blob/main/litellm/proxy/guardrails/guardrail_endpoints.py)) |
| Footprint | Python `>=3.10,<3.15` ([pyproject](https://github.com/BerriAI/litellm/blob/main/pyproject.toml)); reference compose adds Postgres 16 ([compose](https://github.com/BerriAI/litellm/blob/main/docker-compose.yml)); 5432 and 55432 are taken so a new DB port is needed [INFERENCE]. README claims 8 ms P95 at 1k RPS (vendor). |
| 2026 security | **Supply chain**: v1.82.7/1.82.8 pushed to PyPI 2026-03-24, live ~40 min, credential stealer, via compromised Trivy in CI ([post-mortem](https://docs.litellm.ai/blog/security-townhall-updates), [GHSA-5mg7-485q-xm76](https://github.com/advisories/GHSA-5mg7-485q-xm76)). **28 advisories since 2026-01-01**: critical SQLi in key verification ([CVE-2026-42208](https://github.com/advisories/GHSA-r75f-5x8p-qvmc)), critical Host-header auth bypass ([CVE-2026-49468](https://github.com/advisories/GHSA-4xpc-pv4p-pm3w), fixed 1.84.0), critical OIDC cache-key auth bypass, SSTI, MCP stdio command exec, **custom-code guardrail sandbox escape** (GHSA-wxxx-gvqv-xp7p), BannedKeywords/AzureContentSafety guardrail bypass (GHSA-p897-vf7j-f5h8); newest 2026-09-30 SSRF. |
| Fit | Good transport and spend tracking, but "one policy file" is not its model (config.yaml + DB + enterprise gating); new minor weekly, only four lines patched; Rust core is opt-in beta ([doc](https://docs.litellm.ai/docs/proxy/rust_gateway)). A security jury sees 3 critical auth bugs plus a poisoned release in one year. |

### C. agentgateway in detail

- Release v1.6.0 ships `agentgateway-darwin-arm64` (87 MB) ([release](https://github.com/agentgateway/agentgateway/releases/tag/v1.6.0)); v1.0 March 2026; joined AAIF 2026-06-04, accepted by Linux Foundation 2025-08-25 ([index](https://agentgateway.dev/llms.txt)).
- **Budgets (OSS)**: per-API-key `USD` or `Tokens`, rolling windows, `Block` (429) or `Audit`; needs `config.database.url` (SQLite/Postgres); `allowedModels` per key (403); `GET :15000/api/budgets/status`. A USD budget stays at 0 silently when the model has no catalog price, so Ollama needs a custom catalog entry or a `Tokens` budget ([doc](https://agentgateway.dev/docs/standalone/latest/documentation/llm/cost-controls/budget-limits/per-key.md)).
- **Guardrails**: regex (builtin PII + custom, `mask|reject|audit`), OpenAI moderation, Bedrock, Model Armor, Azure, **webhook** (`POST /request` and `/response`, 10 s default timeout, `failClosed` default) ([overview](https://agentgateway.dev/docs/standalone/latest/documentation/llm/prompt-guards/overview.md), [webhooks](https://agentgateway.dev/docs/standalone/main/llm/prompt-guards/webhooks.md)).
- **Documented gaps judges can hit**: `mask` does not apply to streamed responses (only `reject`, and only with `streaming: Enabled`); default scope is system prompt + user/assistant text, so tool results are NOT scanned unless `scope` lists `toolOutput`; embeddings, rerank and passthrough routes skip guards (same overview).
- **MCP**: federation, CEL authz, **ExtMCP** gRPC processors with pass/mutate/deny on `tools/call`, `tools/list`, `prompts/get`, `resources/read` ([doc](https://agentgateway.dev/docs/standalone/latest/documentation/mcp/guardrails/about.md)); MCP spec 2026-07-28 support since v1.4 ([blog](https://agentgateway.dev/blog/2026-08-03-new-mcp-spec-revision/)).
- **Config/UI**: most config updates dynamically; only top `config:` block is startup-only (except `modelCatalog`, `standardAttributes`) ([doc](https://agentgateway.dev/docs/standalone/latest/documentation/configuration/static-configuration.md)); admin UI :15000 Costs/Analytics ([blog](https://agentgateway.dev/blog/2026-06-24-agentgateway-cost-tokenomics-dashboard/)).
- Own record: 5 advisories, 1 high (stateful MCP sessions could cross routes and overwrite authz policy, 2026-07-27), 4 medium ([advisories](https://github.com/agentgateway/agentgateway/security/advisories)).

### D. Cross-cutting facts

| Topic | Fact |
|---|---|
| Ollama budgets | USD budgets need a price and Ollama is $0: Bifrost `CalculateCost` returns 0.0 without pricing, agentgateway stays at 0 without a catalog entry, GoModel needs a pricing override, ferro takes explicit per-Mtok rates ([ferro plugin](https://github.com/ferro-labs/ai-gateway/blob/main/plugin/budget/plugin.go)). Answer: token budgets plus a pseudo-price per Mtok so the dashboard shows "cost". |
| Hot reload | APISIX standalone re-reads YAML every 1 s ([doc](https://github.com/apache/apisix/blob/master/docs/en/latest/deployment-modes.md)); agentgateway dynamic except `config:`; Pipelock fsnotify/SIGHUP; Docker gateway `--watch`; NeMo server `--auto-reload`; Kong DB-less `POST /config`; ContextForge restart; LiteLLM guardrails via DB/API [INFERENCE]. Nobody gives "judge edits one YAML, budgets + guardrails + models change in 1 s" across all controls: we write the watcher regardless. |
| Python 3.14 and telemetry | NeMo, Guardrails AI, ContextForge need `<3.14`, llm-guard `<3.13`; Presidio supports 3.14, so ML paths need a uv 3.13 venv. NeMo pings NVIDIA by default; Snyk uploads to Snyk: verify "local" per dependency. |
| MCP wire change | Spec 2026-07-28 drops sessions, GET stream and SSE resume; one POST per message; `Mcp-Method`/`Mcp-Name`/`Mcp-Param-*` headers must equal the body ([spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)). Our proxy must also pass `Mcp-Session-Id` for 2025 clients [INFERENCE]. |

### E. Build vs buy

Scores 1-5 are my judgment [INFERENCE]; weighted = sum(weight x score)/100. Hot reload counts inside Robustness.

| Criterion (weight) | (a) Own FastAPI + libs | (b) LiteLLM + our plugins | (c) Go gateway (own or GoModel) + Python sidecar | (d) agentgateway + our webhook/ExtMCP service |
|---|---|---|---|---|
| Robustness, guardrail quality, hot reload (30) | 4: all detection ours; one YAML + watchfiles trivial; risk = our SSE bugs | 3: guards partly enterprise-gated, config split yaml/DB, inherited auth CVEs | 3: guardrail polish competes with writing a gateway | 4: budgets/allowlist/regex built in; ML via webhook; reload native but config split |
| Architecture, performance (20) | 3: clean, Python-only | 2: glue on LiteLLM, Postgres, low originality | 5: best separation and latency | 5: PDP/PEP split, ExtProc/ExtMCP, A2A, UI |
| Security reporting (20) | 5: own audit schema and export | 3: audit logs Enterprise | 4 | 4: access-log DB + UI, ours on top |
| Test suite (15) | 5: in-process ASGI, deterministic | 3: needs LiteLLM + Postgres | 3: two languages | 4: binary + Python service, budgets via admin API |
| Practicality, scalability (15) | 3 | 4 | 5 | 5 |
| **Weighted** | **4.00** | **2.95** | **3.65** | **4.35** |
| Delivery risk, 24-36 h | Low | Medium | High | Medium-high: webhook JSON schema unread, two config surfaces break "ONE central config" unless we compile our policy into agentgateway config, stream-mask limit, new YAML schema during a parallel project |

(d) wins on paper, (a) on risk; the gap is mostly architecture/scalability points, not guardrail quality (detectors are ours in both). If (d) is chosen, judges editing agentgateway's own file would bypass our audit and the central catalog, so `policy.yaml` must compile into its config [INFERENCE].

## Inconsistent

| Subject | Side 1 | Side 2 |
|---|---|---|
| Portkey "fully open source" | Mar 2026 [press release](https://www.globenewswire.com/news-release/2026/03/24/3261574/0/en/Portkey-s-Gateway-is-Now-Fully-Open-Source-Processing-over-1-Trillion-Tokens-Every-Day.html) | main README still "Gateway 2.0 (Pre-Release)", v1.15.2 is Jan 2026, no budget code in main ([README](https://github.com/Portkey-AI/gateway)); claim likely refers to the unreleased 2.0 branch [INFERENCE] |
| Kong version | GitHub latest 3.9.3 | Kong staff: OSS binaries ended at 3.9.1 ([discussion](https://github.com/Kong/kong/discussions/14628)) |
| LLM Guard liveness | pushed 2026-07-08, 3.2k stars | that push is the archival commit; last PyPI 2025-05-19 ([repo](https://github.com/protectai/llm-guard)) |
| LiteLLM licence | GitHub API NOASSERTION; docs footer "MIT license" | split LICENSE: MIT + proprietary `enterprise/` ([LICENSE](https://github.com/BerriAI/litellm/blob/main/LICENSE)) |
| Envoy AI Gateway name | blogs and older docs use `envoyproxy/ai-gateway` | renamed Agent Router, CRDs/CLI unchanged ([README](https://github.com/theagentrouter/agent-router)) |
| MS AGT versions | release 4.1.0 | sub-packages 5.0.0, docs disagree with pyproject (helper finding, not re-checked) |

## Could not establish

- Measured latency or RAM of any tool on the M5 (read-only task). Only vendor claims: LiteLLM 8 ms P95/1k RPS, agentgateway regex < 1 ms, Bifrost ~11 us. agentgateway-vs-LiteLLM benchmarks exist on the [agentgateway blog](https://agentgateway.dev/llms.txt) (vendor-authored; numbers unread).
- agentgateway webhook JSON schema; whether a custom Ollama catalog price works end to end; which features Solo.io's enterprise edition gates.
- GoModel/ferro live-apply of config changes; Pipelock internals beyond README.
- PANW-Portkey and TensorZero wind-down details beyond the linked press release and secondary article.
- Whether judges accept use of LiteLLM `enterprise/` under "development and testing".
- Kong/Agent Router guardrail completeness beyond repo-tree and doc greps.

## Further

**Recommendation for our build**

1. **Primary: option (a), architected so (d) is an adapter.** Write the engine as a transport-agnostic Python library `decide(event, policy) -> allow | redact | block + reasons`; front it with a thin FastAPI gateway: OpenAI-compatible `/v1/chat/completions` to Ollama (`host.docker.internal` from containers) and a POST-only streamable-HTTP MCP proxy that keys on `Mcp-Method`/`Mcp-Name` and passes `Mcp-Session-Id` through. One `policy.yaml` watched by watchfiles, atomically swapped, `policy_version` hash in every audit line so judges see edits apply in about 1 s. Why: lowest delivery risk, we own every control judges probe, in-process tests, no extra binary (ports 4000/8000 free; 5432, 8080, 8085, 11434 taken).
2. **Stretch after core + tests: agentgateway adapter.** `/request` and `/response` webhooks (ExtMCP gRPC if time) calling the same `decide()`, plus a `policy.yaml -> agentgateway config.yaml` compiler. Buys the PDP/PEP architecture diagram and A2A/scale story; native darwin-arm64 binary, loopback only, no Docker needed.
3. **Libraries inside the core:** Presidio (`NoOpNlpEngine` or spaCy sm) + custom recognizers; gitleaks TOML compiled to regex with keyword prefilter (confirm all 222 rules compile in Python [INFERENCE]); Cisco mcp-scanner YARA and Docker secretsscan regexes as signature seeds (04); Apache-2.0 deberta prompt-injection model via transformers/ONNX (03) in a 3.13 venv.
4. **Budgets:** in-process token budget per key/model/day; pseudo-price per Mtok for local models; list-price table for cloud models (simulated, no paid APIs). Mirror agentgateway semantics `Block|Audit`, `failClosed|failOpen`.
5. **Borrow vocabularies, not code:** ContextForge hook names/modes (enforce/permissive/disabled), AGT hash-chain audit, OpenGuardrails/ACS verdict fields for the audit schema.
6. **Tests/demo:** bulk-generate negatives with garak (`ollama`/`rest`) and promptfoo offline; each control gets allowed + blocked + redacted fixtures; a "judge edit" test rewrites `policy.yaml` mid-run and asserts the next verdict flips. Demo: delete a control, replay the prompt, dashboard flips block to allow.
7. **Do not build on:** LiteLLM as primary, LLM Guard, TensorZero, Portkey, Kong OSS, trufflehog, Superagent, Snyk agent-scan.

**Risks**
- Streaming: redaction of a streamed response is impossible once bytes are out (agentgateway documents this; our own gateway has the same physics). Either buffer (kills token streaming) or block-only on streams; decide per control.
- Own-gateway SSE chunk reassembly across PII boundaries is the likeliest demo bug.
- Young dependencies: GoModel (5 months, pre-1.0), Pipelock (8 months, ELv2 dir), AGT (preview), ferro (3 contributors).
- Licence re-checks before importing: PromptGuard 2 weights (gated, approval latency), LiteLLM/Pipelock `enterprise/`, Bifrost `ent-*`, NeMo telemetry default.
- Any LiteLLM-like dependency with a 2026 supply-chain incident is a story liability at a security event; pin versions and hashes for everything installed.

**Decisions for the team**
1. Commit to (a)+adapter, or to (d) from hour 0 (higher ceiling, one person must own the compiler)?
2. Is token streaming a hard demo requirement (changes redaction design)?
3. Local-model pseudo-price: tokens only, or also energy/GPU-time?
4. Allow gated HF models (PromptGuard 2) or Apache-2.0-only?

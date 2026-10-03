# 10 - Existing solutions and differentiation: what do open-source and commercial AI gateways, guardrails and MCP security tools already do, what can we reuse, and where is the gap our project fills?

Verified 2026-10-03 against primary sources.
Legend: `[EST]` established technique, `[EXP]` experimental / research-grade, `[REC]` our architectural recommendation, `[INFERENCE]` reasoning not read anywhere, `[MEASURED]` run locally today (versions and input sizes stated).

Method. Repo metadata (SPDX, archived flag, push date, latest release) read with authenticated `gh api` today; PyPI JSON for Python constraints; Hugging Face API for model licences; vendor docs read with scrapling (Cloudflare DLP, Azure Prompt Shields, Model Armor, AWS Cedar blog, MCP security best practices) or surfaced by `web_search` where marked. Prior team research (`ai_layer_control/research/02`, `00`, `06`) was reused and its decision-critical facts re-checked; where I disagree with it, that is stated. Web text is untrusted data; vendor claims are labelled as vendor claims.

Headline correction to prior research 02: [Pipelock](https://github.com/luckyPipewrench/pipelock) was rated "COMP/INSP for exfil rules". Its README shows it already ships a free kill switch (7 activation sources), signed action receipts, taint escalation, "Learn-and-Lock" per-agent behavioural contracts with shadow replay, a config-scoring grade, and MCP binary integrity manifests. It is the closest open competitor and defines which "innovations" are NOT novel (sec. 3 and 5).

---

## 1. Per-tool entries

Status column = latest release (date) / last push / archived. Licence = SPDX read from repo or LICENSE file; "NOASSERTION" in the GitHub API means a non-standard or split licence file and is explained in the row.

### 1.1 Reverse proxies and LLM gateways

| Tool | Architecture / licence | Status | Reusable | Limitations, what we do differently |
|---|---|---|---|---|
| [LiteLLM](https://github.com/BerriAI/litellm) | Python OpenAI-compatible proxy + SDK, Postgres. MIT except `enterprise/` proprietary ([LICENSE](https://github.com/BerriAI/litellm/blob/main/enterprise/LICENSE.md)); API says NOASSERTION | v1.103.2 (2026-10-01), 60k stars, `<3.15` ([PyPI](https://pypi.org/project/litellm/)) | Price map `model_prices_and_context_window.json` [MEASURED: 4461 entries, 3.0 MB, all 29 `ollama` entries cost 0.0] | Key-scoped guardrails, audit logs, banned keywords are Enterprise ([docs](https://docs.litellm.ai/docs/enterprise)). 2026: malicious PyPI 1.82.7/1.82.8 ([post-mortem](https://docs.litellm.ai/blog/security-townhall-updates), [GHSA-5mg7-485q-xm76](https://github.com/advisories/GHSA-5mg7-485q-xm76)), critical auth bypass ([GHSA-4xpc-pv4p-pm3w](https://github.com/advisories/GHSA-4xpc-pv4p-pm3w)), guardrail sandbox escape (GHSA-wxxx-gvqv-xp7p). Local models priced $0. Use the price JSON only. |
| [Portkey gateway](https://github.com/Portkey-AI/gateway) | TS gateway, MIT | v1.15.2 (2026-01-12); PANW [closed acquisition 2026-05-29](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-portkey-to-secure-ai-agents) | `webhook`, `regexMatch`, model-whitelist guardrail shapes | README "2.0 Pre-Release"; no budget code found (02). INSP only. |
| [Kong](https://github.com/Kong/kong) AI | Nginx/Lua plugins, Apache-2.0 | 3.9.3 (2026-06-17); OSS binaries ended at 3.9.1 per [Kong staff](https://github.com/Kong/kong/discussions/14628) | `ai-proxy`, regex `ai-prompt-guard` | Token/cost limits, sanitizer, semantic guard are [Enterprise](https://developer.konghq.com/plugins/ai-rate-limiting-advanced/). SKIP. |
| Envoy AI Gateway = [Agent Router](https://github.com/theagentrouter/agent-router) | K8s CRDs on Envoy, Apache-2.0 | v1.1.0 (2026-08-21); old repo redirects (`gh api`) | routing, token limits, MCP route | No guardrail feature in repo tree (02) [INFERENCE]. SKIP. |
| [agentgateway](https://github.com/agentgateway/agentgateway) | Rust LLM+MCP+A2A proxy, CEL authz, ExtMCP/webhook guards, UI. Apache-2.0, Linux Foundation | v1.6.0 (2026-10-02), 5.2k stars | Webhook contract `POST /request`,`/response`; per-key USD/Token budgets `Block|Audit`; `failClosed` default ([doc](https://agentgateway.dev/docs/standalone/latest/documentation/llm/cost-controls/budget-limits/per-key.md)) | `mask` not applied to streamed responses; tool output unscanned unless `scope` says so; USD budget 0 without catalog price (so Ollama needs Tokens); two config surfaces. Wrapping it = integration, not product; stretch adapter only. |
| [Bifrost](https://github.com/maximhq/bifrost) | Go gateway, WASM plugins, MCP gateway. Apache-2.0; guardrails [Enterprise-only](https://github.com/maximhq/bifrost/blob/main/docs/enterprise/guardrails.mdx) | repo latest `ent-v2.2.5-base` (2026-10-02); OSS `transports/v2.2.5` | Virtual-key + hierarchical budget model | Cost 0 without price (02). INSP. |
| [TensorZero](https://github.com/tensorzero/tensorzero) | Rust gateway + eval, Apache-2.0 | **ARCHIVED 2026-06-11** | - | SKIP. |
| [Plano](https://github.com/katanemo/plano), [vllm semantic-router](https://github.com/vllm-project/semantic-router) | Envoy-based agent data plane / router, Apache-2.0 | 0.4.37 (2026-09-28) / pushed 2026-10-03 | filter-chain concept | Too heavy for 24-48 h. INSP. |
| [Cloudflare AI Gateway](https://developers.cloudflare.com/ai-gateway/features/dlp/) | SaaS edge proxy | docs 2026-09-30 | gateway-level DLP profiles, flag vs block, `cf-aig-dlp` header | See 1.6. Cloud-only. |

### 1.2 Guardrail libraries and models

| Tool | Licence | Status | Python | Reusable / limitations |
|---|---|---|---|---|
| [NeMo Guardrails](https://github.com/NVIDIA-NeMo/Guardrails) | Apache-2.0 (LICENSE.md header read; API NOASSERTION is a file-format artefact) | v0.24.1 (2026-09-16) | `<3.14` ([PyPI](https://pypi.org/project/nemoguardrails/)) | Rail taxonomy as vocabulary. Telemetry on by default (02), no budgets, rail LLM calls cost 0.5-1.5 s. INSP. |
| [Guardrails AI](https://github.com/guardrails-ai/guardrails) | Apache-2.0 | v0.11.0 (2026-08-14) | `<3.14` | Hub and hosted inference shut down 2026-08-25 ([issue #1560](https://github.com/guardrails-ai/guardrails/issues/1560), read today); validators now plain PyPI with own model licences. Supply-chain lesson. SKIP. |
| [LLM Guard](https://github.com/protectai/llm-guard) | MIT | **ARCHIVED**; push 2026-07-08 is the archival commit; PyPI 0.3.16 (2025-05-19) | `<3.13` | Unmaintained incl. HF models. SKIP. |
| [ModelScan](https://github.com/protectai/modelscan) | Apache-2.0 | v0.8.8 (2026-02-18), pushed 2026-09-28 | `<3.13` | Offline model-file scanner for supply-chain tests; pickle scanners have bypass families (04). Guardian = commercial sibling in PANW Prisma AIRS (not verified in detail). |
| [Rebuff](https://github.com/protectai/rebuff), [Vigil](https://github.com/deadbits/vigil-llm) | Apache-2.0 | Rebuff ARCHIVED (2024-08-07); Vigil last push 2024-01-31 | - | Dead. Vigil YARA files = seed signatures (02); canary-word idea survives (sec. 5 #17). |
| [LlamaFirewall](https://github.com/meta-llama/PurpleLlama) | Repo root NOASSERTION (Llama licence); `LlamaFirewall/` MIT ([LICENSE](https://github.com/meta-llama/PurpleLlama/blob/main/LlamaFirewall/LICENSE)) | PyPI 1.0.3 (2025-05-29) | not declared | AlignmentCheck idea (judge compares action to user goal; 0.86-1.49 s per step in paper traces, 06). PromptGuard 2 weights gated, licence `other` ([86M card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M), `gated: manual`). INSP. |
| Llama Guard 3 / 4 | `llama3.1` ([LG3](https://huggingface.co/meta-llama/Llama-Guard-3-8B)), `other` ([LG4](https://huggingface.co/meta-llama/Llama-Guard-4-12B)); both gated manual | 2024-10 / 2025-04 | - | Harm taxonomy, not injection/exfil; no Polish (03). Cloudflare Guardrails run LG3 8B ([blog](https://blog.cloudflare.com/guardrails-in-ai-gateway/)). Keep out of the required path. |
| [protectai deberta-v3 PI v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | `apache-2.0`, not gated (HF API) | modified 2026-07-09, 760k downloads | transformers/ONNX | **Reusable weights**; English-only, trigger-word over-defense (03). |
| PIGuard; Qwen3Guard-Gen-0.6B; Granite Guardian 3.3 8B; gpt-oss-safeguard-20b | `mit`; `apache-2.0`; `apache-2.0`; `apache-2.0` (none gated, HF API today) | 2025-08; 2025-11; 2025-09; 2026-01 | - | PIGuard (injection) and Qwen3Guard 0.6B (harm, 119 languages) fit; 8B/20B too big beside the other team's Ollama (03). |
| Lakera Gandalf data, [PINT](https://github.com/lakeraai/pint-benchmark) | PINT repo MIT, **ARCHIVED** (2026-04-16) | - | - | HF API gave no JSON for `lakera/gandalf_*`: licence not established. `deepset/prompt-injections`, `jackhhao/jailbreak-classification` are `apache-2.0` but small and 2023-2024. |

### 1.3 Red-team and eval tools (test-suite sources, not runtime)

| Tool | Licence | Status | Notes |
|---|---|---|---|
| [garak](https://github.com/NVIDIA/garak) | Apache-2.0 | v0.17.0 (2026-09-09), 9.4k stars | Third-party before/after number; `rest` + `ollama` generators, no cloud (06). Use. |
| [promptfoo](https://github.com/promptfoo/promptfoo) | MIT | 0.123.1 (2026-09-18); OpenAI deal, MIT stays ([blog](https://www.promptfoo.dev/blog/promptfoo-joining-openai)) | Static `eval` + JUnit OK; red-team generation goes to its API unless `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true` (06). |
| [PyRIT](https://github.com/microsoft/PyRIT), [DeepTeam](https://github.com/confident-ai/deepteam), [Giskard](https://github.com/Giskard-AI/giskard-oss) | MIT / Apache-2.0 / Apache-2.0 | v1.1.0 (2026-09-04; `Azure/PyRIT` ARCHIVED) / v1.0.9 (2025-11-12) / v3.0.1 (2026-10-02) | Need a judge LLM competing for RAM; Python `<3.15` / `<3.14` / `>=3.12`. Skip (06). |

### 1.4 MCP gateways and scanners

| Tool | Architecture / licence | Status | Reusable | Limitations / difference |
|---|---|---|---|---|
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | Go single binary: HTTP/WS/MCP/A2A proxy + host containment. Apache-2.0 core + `enterprise/` under Elastic License 2.0 | v3.6.0 (2026-10-03), 920 stars, created 2026-02 | 65 DLP patterns with checksums, entropy exfil, canary tokens, SSRF rules, signed receipts, `pipelock explain`, config score (23 categories, 170-point budget) | **Closest competitor.** Per-agent profiles, budgets, dashboard = Pro; fleet, decision replay, dry-run = Enterprise (README tier table). Budgets count tool calls, retries, loops, wall-clock, not tokens/GPU time; no model allowlist or LLM-token metering in README [INFERENCE: README grep]. Egress-centric, not LLM-semantics. Benchmark to beat, not a dependency. |
| [MS Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | Python lib (+TS/Rust/Go/.NET): YAML/OPA/Cedar policy, SPIFFE/DID identity, trust scoring, privilege rings, SRE kill switch, MCP gateway spec, Streamlit dashboard. MIT | v4.1.0 (2026-06-09), 6.4k stars, Public Preview; [launch blog](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/) claims <0.1 ms p99 (vendor) | Trust tiers, delegation-chain spec, Decision BOM | Library you import: an agent that does not import it is ungoverned. Closest on identity chain + kill switch. |
| [IBM ContextForge](https://github.com/IBM/mcp-context-forge) | Python MCP+A2A gateway, hooks `tool_pre_invoke/post_invoke`, RBAC. Apache-2.0, plugins in `cpex_*` | v1.0.11 (2026-09-28) | Hook names, modes enforce/permissive/disabled | `<3.14`, restart for config (02). INSP. |
| [Docker MCP Gateway](https://github.com/docker/mcp-gateway) | Go; `--block-secrets`, `--watch`, interceptors `before/after:http:URL`. MIT | tag v0.44.1, no Releases, pushed 2026-09-23 | Interceptor contract | Needs Docker; tools/call only (02). |
| [Lasso MCP Gateway](https://github.com/lasso-security/mcp-gateway) | Python plugins, MIT | v1.2.0 (2026-01-21) | - | Best plugin needs paid key (02). INSP. |
| Invariant [guardrails DSL](https://github.com/invariantlabs-ai/invariant); `mcp-scan` -> [snyk/agent-scan](https://github.com/snyk/agent-scan) | DSL; scanner. Apache-2.0 both | invariant pushed 2026-01-12, no releases; agent-scan v0.6.8 (2026-09-29); `invariantlabs-ai/mcp-scan` redirects to `snyk/agent-scan`; PyPI `mcp-scan` stuck at 0.4.3 | Issue codes: injection, tool poisoning, shadowing, toxic flows | Scan needs `SNYK_TOKEN`, uploads descriptions, no runtime proxy ([README](https://github.com/snyk/agent-scan)). Snyk-Invariant deal from 02, not re-read. SKIP. |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) | Python CLI/lib: YARA + optional LLM/cloud analyzers. Apache-2.0 | 4.8.6 (2026-10-02) | Offline YARA tool-poisoning rules (feed seed, 04) | Scan-time. COMP for rules. |
| [Pomerium](https://github.com/pomerium/pomerium) MCP | Identity-aware proxy, downstream OAuth 2.1 via your IdP, upstream OAuth held by proxy, tool-level policy ([ref](https://www.pomerium.com/docs/capabilities/mcp/reference)). Apache-2.0 repo | v0.33.4 (2026-10-02) | Token separation: client sees External Token, upstream Internal Token | Human identity only, needs IdP, no content guardrails. INSP. |
| [ToolHive](https://github.com/stacklok/toolhive), [MCPX](https://github.com/TheLunarCompany/lunar), [mcp-firewall](https://github.com/ressl/mcp-firewall), [Microsoft mcp-gateway](https://github.com/microsoft/mcp-gateway) | Server runner with Cedar / MCP gateway / YAML firewall / K8s router. Apache-2.0 / MIT / **AGPL-3.0** (PyPI 0.1.0 `AGPL-3.0-or-later`) / MIT | pushed 2026-10-03 / 10-01 / 09-09 (18 stars) / 10-02 | chain-detector idea | mcp-firewall: never copy code (AGPL). |
| [Cloudflare MCP server portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/) | SaaS Zero Trust in front of MCP; DLP on tool calls both ways | proprietary; supports MCP 2026-07-28 | portal-level tool overrides | DLP "AI prompt profiles" do not apply to MCP traffic (docs). |
| [OWASP Agent Control Standard](https://github.com/GenAI-Security-Project/agent-control-standard) | Spec: allow/deny/modify + envelope audit. Apache-2.0 | pushed 2026-09-28 | Verdict vocabulary | Default failure posture fail-open (06). |

### 1.5 Policy languages and AI policy work (OPA / Cedar)

| Item | What | Licence / status | Verdict |
|---|---|---|---|
| [Amazon Bedrock AgentCore Policy](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/) | Cedar policies on an AgentCore Gateway; each MCP tool invocation with arguments evaluated; **blocks everything by default**; GA 2026-03-03; natural language -> Cedar; Bedrock Guardrails support since 2026-06-17 ([ClassMethod](https://dev.classmethod.jp/en/articles/20260617-amazon-bedrock-agentcore-policy-guardrails/), search-surfaced) | AWS service. [AWS blog](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/) read: `forbid` overrides `permit`; Cedar Analysis compares policy versions | Best conceptual model (default deny, forbid-wins, policy diff). Cloud-only; tool authz only, no budgets or DLP. |
| [Cedar](https://github.com/cedar-policy/cedar), [cedar-for-agents](https://github.com/cedar-policy/cedar-for-agents) | Language; crates generating Cedar schemas from MCP tool descriptions; analysis MCP server | Apache-2.0; CLI v4.13.0 (2026-09-15); cedar-for-agents pushed 2026-09-30, 53 stars | `cedarpy` 4.12.1 (2026-09-24, macOS arm64 wheel, [cedar-py](https://github.com/k9securityio/cedar-py) Apache-2.0). [MEASURED 2026-10-03, py3.14, 2 policies + 3 entities, parsed every call]: **58 us / `is_authorized`**. |
| [OPA](https://github.com/open-policy-agent/opa) | Rego engine | Apache-2.0; v1.21.1 (2026-09-29) | Used for MCP tool calls by Strata Maverics and TrueFoundry ([OPA guardrails](https://www.truefoundry.com/docs/ai-gateway/opa-guardrails)), search-surfaced. NOT RECOMMENDED FOR HACKATHON MVP: sidecar + Rego for live-editing judges -> in-process YAML. |
| CEL | agentgateway authz language | `common-expression-language` 0.10.0, Apache-2.0, py>=3.11, macOS arm64 wheel (2026-09-15) | [MEASURED same run] **24 us / evaluate**, compiled every call. Optional `when:` evaluator. |

### 1.6 Hyperscaler / SaaS guardrails

| Product | What it does (primary source) | Price | Limitations vs ours |
|---|---|---|---|
| Microsoft Prompt Shields ([doc 2026-09-18](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection)) | User-prompt and document (indirect) attacks, scanned at user-input and tool-response points; spotlighting (base64-wrap untrusted docs); `annotate` vs `block`; API takes a `userPrompt` + up to 5 `documents`, returns `attackDetected` | F0: 5 req/s, 5,000 records/month; S0: 1000 req/10 s ([overview](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/overview), search-surfaced) | Verdict is boolean `detected/filtered`: no rule id, score or evidence. Prompts leave the machine. |
| Google Model Armor ([overview](https://docs.cloud.google.com/model-armor/overview)) | Templates with per-filter confidence (High / Medium and above / Low and above), floor settings at org/folder/project, injection + jailbreak, Sensitive Data Protection, URLs, MCP tool-call sanitization | Free 2M tokens/month, then $0.10 per 1M ([pricing](https://cloud.google.com/security/products/model-armor)) | Cloud. Floor/template hierarchy is a model for our strictness profiles + overrides. |
| AWS Bedrock Guardrails ([page](https://aws.amazon.com/bedrock/guardrails/)) | `ApplyGuardrail` scores text without invoking a model, works with third-party models; content/prompt-attack filters, denied topics, 50+ PII types block/mask, grounding, word filters | $0.15 per 1,000 text units content/topics, $0.10 PII, words free; 1 unit = 1,000 chars ([AWS](https://aws.amazon.com/about-aws/whats-new/2024/12/amazon-bedrock-guardrails-reduces-pricing-85-percent/)); 50 calls/s ([AWS](https://aws.amazon.com/about-aws/whats-new/2025/02/amazon-bedrock-guardrails-increase-service-quota-limits)) | Per-call hop and cost; action menu is block or mask. |
| Cloudflare AI Gateway ([DLP doc 2026-09-30](https://developers.cloudflare.com/ai-gateway/features/dlp/)) | DLP on prompts/responses, flag or block; Guardrails (Beta, Llama Guard 3 8B); Spend limits (Beta) | DLP free; Guardrails billed as Workers AI inference; injection detection is a separate paid WAF add-on "AI Security for Apps" (secondary: [mintmcp](https://www.mintmcp.com/blog/cloudflare-ai-gateway-pricing)) | **Read today:** streamed responses buffered fully before scan (TTFT = full generation); base64 and URLs not decoded; per-gateway policies, "no per-request header to select DLP profiles"; cache hits skip DLP and are not re-evaluated after policy change. |
| Lakera Guard | Injection/PII API; 98%+ detection, <50 ms, 100+ languages are vendor-reported (secondary) | Community 10k req/month, 8k tokens ([pricing](https://platform.lakera.ai/pricing)) | Check Point-owned (1.7). The guard is itself an egress path. |

### 1.7 Commercial entrants (brief; none installable for a local demo)

| Vendor | Event | Source |
|---|---|---|
| Protect AI -> Palo Alto Prisma AIRS | closed 2025-07-22, $634.5M (explains LLM Guard's death) | [PANW](https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai) |
| Portkey -> Palo Alto | closed 2026-05-29 | [PANW](https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-portkey-to-secure-ai-agents) |
| Lakera -> Check Point | announced Sept 2025; price and close date disagree (see Inconsistent) | [SecurityWeek](https://www.securityweek.com/check-point-to-acquire-ai-security-firm-lakera/) |
| Prompt Security -> SentinelOne (closed 2025-09-05); CalypsoAI -> F5 (2025-09-26, $145.2M); Aim -> Cato (2025-09, reported $350M); SPLX -> Zscaler (2025-10-31, $40.6M) | acquisitions | [Globe and Mail](https://www.theglobeandmail.com/investing/markets/stocks/S/pressreleases/34691488/sentinelone-completes-acquisition-of-prompt-security/), [F5 10-K](https://www.sec.gov/Archives/edgar/data/1048695/000104869525000157/ffiv-20250930.htm), [CyberScoop](https://cyberscoop.com/cato-networks-acquires-ai-security-startup-aim-security/), [Zscaler 10-Q](https://www.sec.gov/Archives/edgar/data/1713683/000171368325000205/zs-20251031.htm) |
| Helicone -> Mintlify (2026-03-03); promptfoo -> OpenAI (MIT stays); Invariant -> Snyk (2025-06) | see rows above | 02 |
| Zenity $125M Series C (Aug 2026); Noma $100M Series B (Jul 2025); Pillar $9M seed (Apr 2025) | funding only | [SecurityWeek](https://www.securityweek.com/zenity-raises-125-million-in-series-c-funding/), [appsecsanta](https://appsecsanta.com/noma-security), [Calcalist](https://www.calcalistech.com/ctechnews/article/hklv8g6cje) |

Reading [INFERENCE]: nearly every independent gateway, guardrail and red-team shop was absorbed within 15 months; nobody sells a self-hosted, single-policy, local-model-aware layer because buyers are cloud-first. Answer to "what survives": open code you control.

---

## 2. Market table

| Technology | What it does | License | Useful parts | Limitations |
|---|---|---|---|---|
| agentgateway 1.6.0 | LLM+MCP+A2A proxy, budgets, CEL | Apache-2.0 | Webhook contract, budget semantics | 2 config surfaces; stream-mask gap; $0 local |
| LiteLLM 1.103.2 | OpenAI proxy, keys, spend | MIT + proprietary `enterprise/` | Price JSON | Gated guardrails/audit; 2026 CVEs + poisoned release |
| Bifrost / Portkey / Kong / APISIX | Gateways with AI plugins | Apache-2.0 / MIT / Apache-2.0 / Apache-2.0 | Budget model, guardrail shapes, APISIX plugin runners | Guardrails or cost features paywalled; Portkey acquired |
| TensorZero, LLM Guard, Rebuff | gateway / scanners / heuristics | Apache / MIT / Apache | - | ARCHIVED 2026-06 / 2026-07 / 2024-08 |
| Pipelock 3.6.0 | Agent egress proxy, DLP, MCP scan, kill switch, receipts | Apache-2.0 + ELv2 dir | DLP patterns, canaries, receipts, `explain` | Per-agent budgets paid; no token/GPU budgets |
| MS Agent Governance Toolkit 4.1.0 | In-process policy, identity, SRE | MIT | Trust tiers, delegation spec | Library, preview |
| IBM ContextForge / Docker MCP GW / Lasso | MCP gateways + plugins/interceptors | Apache-2.0 / MIT / MIT | Hook and interceptor contracts | `<3.14`; Docker needed; paid plugin |
| Cisco mcp-scanner / snyk agent-scan | MCP poisoning scanners | Apache-2.0 | YARA rules; issue codes | Scan-time; Snyk needs token |
| Presidio 2.2.364 | PII analyzer/anonymizer | MIT | PII + custom recognizers, py3.14 | PL only PESEL built in |
| gitleaks 8.30.1 rules | 222 secret rules (TOML) | MIT | Signature seed | "feature complete" |
| NeMo Guardrails / Guardrails AI | Rails runtime / validators | Apache-2.0 / Apache-2.0 | Taxonomy | `<3.14`; telemetry default; hub shut 2026-08-25 |
| Llama Guard, PromptGuard 2, LlamaFirewall | Safety/injection models + agent lib | Llama licences (gated) / MIT subdir | AlignmentCheck idea | Gated, English-first |
| deberta-v3 PI v2, PIGuard, Qwen3Guard-0.6B | Open classifiers | Apache-2.0 / MIT / Apache-2.0 | Offline weights | Accuracy trade-offs (03) |
| garak / promptfoo | Red-team scanners | Apache-2.0 / MIT | Third-party probes, JUnit | 3.13 venv / remote generation default |
| Prompt Shields, Model Armor, Bedrock Guardrails, Lakera, Cloudflare | Hosted guard APIs | Proprietary | Confidence levels, flag vs block UX | Cloud egress, per-call cost, opaque verdicts |
| AgentCore Policy + Cedar | Default-deny tool authz | AWS service; Cedar Apache-2.0 | forbid-wins, policy diff, `cedarpy` 58 us | AWS-only; no content/budget controls |
| OPA | Rego engine | Apache-2.0 | Bundle last-known-good | Sidecar + Rego for live editing |
| mcp-firewall 0.1.0 | YAML MCP firewall | **AGPL-3.0** | Tool-chain detector idea | AGPL, 18 stars |

---

## 3. Gap analysis

A gap counts only if I read what the nearest product does and it falls short. "Not found" = negative result from READMEs/docs read, so `[INFERENCE]` at the edges.

| # | Capability | Closest existing | Evidence | Verdict |
|---|---|---|---|---|
| G1 | One hot-reloaded policy over guardrails + budgets + model allowlist + MCP + identity | Pipelock (fsnotify/SIGHUP), agentgateway (dynamic) | agentgateway: startup-only `config:` block + DB for budgets (02 C); LiteLLM: yaml + DB, key-scoped guardrails Enterprise (02 B); Pipelock per-agent budgets/profiles/dashboard are Pro ([tiers](https://github.com/luckyPipewrench/pipelock)); AGT is a library | **PARTIAL.** Parts exist; one file, one second, all controls, with diff does not. |
| G2 | Compute budgets for local models (tokens, GPU-seconds from Ollama durations) | agentgateway Tokens budget; Pipelock call/duration budgets | [MEASURED] LiteLLM price JSON: 29/29 Ollama entries 0.0; agentgateway USD budget stays 0 without catalog price; Bifrost cost 0 without price (02 D); Pipelock budgets = calls/retries/loops/wall-clock | **REAL.** Issuer names local-model budgets. |
| G3 | Destination-aware DLP: verdict = f(data class, destination class, identity) | Cloudflare AI Gateway DLP, Model Armor templates | Cloudflare (read today): per-gateway policy, no per-request profile, buffered streams, base64 undecoded; OSS gateways give per-key guards at best | **REAL** for self-hosted. Commercial workaround: one gateway per tenant. |
| G4 | MCP tool pinning (hash of name + description + schema) joined with identity chain user -> agent -> sub-agent -> tool | Pipelock integrity manifests (binaries) + actor-identity envelope; AGT delegation spec; Snyk agent-scan | agent-scan: scan-time, needs `SNYK_TOKEN`, no runtime (README); Pipelock pins server binaries/scripts by hash; AGT spec is in-process; Pomerium: human identity + tool policy, no pinning | **PARTIAL.** Pieces in three products; none enforces all in one local gateway. |
| G5 | Explainable decisions: rule, stage, threshold, evidence span, counterfactual | Pipelock `explain` + `X-Pipelock-Block-Reason` | Prompt Shields: only `detected`/`filtered` (read today); Model Armor: confidence match per filter; Cloudflare: flag/block + header | **PARTIAL.** Reason codes exist; threshold counterfactual does not. |
| G6 | Signed threat feed whose rules carry inline tests and are rejected on failure | Pipelock Conductor signed bundles (Enterprise); Guardrails AI Hub (dead) | No project among those read ships rules with install-time tests [INFERENCE]; Hub shutdown 2026-08-25 shows hosted-validator fragility | **REAL**; literal issuer requirement. |
| G7 | Agent-loop kill switch | Pipelock (free, 7 sources), AGT SRE | Pipelock: "Emergency kill switch (7 sources)", loop/cycle detection; AGT: "Kill switch, SLO monitoring" | **NOT A GAP.** Table stakes. |
| G8 | What-if simulation of a policy edit over recorded traffic, in OSS | Pipelock Conductor dry-run + replay | Enterprise-only; Learn-and-Lock replay is per-agent contracts; Prompt Shields `annotate` is single-feature shadow | **PARTIAL.** Free general version open. |
| G9 | Guard runs fully local | OSS libraries | Prompt Shields, Model Armor, Bedrock, Lakera, Snyk agent-scan all send content to a vendor | **REAL** as framing: a guard SaaS is a DLP channel. |
| G10 | Fail-closed under judge-broken config | agentgateway `failClosed` | OWASP ACS default fail-open (06) | **PARTIAL**; cheap to demo (invalid YAML keeps last good). |

Do NOT claim novelty for: kill switch, signed receipts, hash-chained audit (Pipelock, AGT), canary tokens (Pipelock), learn-then-lock allowlists (Pipelock), default-deny + forbid-wins (AgentCore), trust scores (AGT).

---

## 4. Differentiated angle

We do not wrap a product. Decision function, policy format, budgets, feed verifier and dashboard are ours; libraries sit underneath (4.1).

**T1 "One file, one second, one diff" (G1, G8, G10).** A single `policy.yaml` is the only source of controls, thresholds, allowed models, budgets, MCP allowlists and identity rules. On each edit the gateway validates, diffs, and **simulates the candidate over the last N recorded decisions**: "this edit flips 3 of 200: 2 block->allow (control X), 1 allow->block". Invalid YAML keeps last-good and logs `config_reload_rejected`. Judge sees: edits a threshold, banner shows new policy hash and flip counts in ~1 s, same curl returns a different verdict; deletes a control and its negative case passes; breaks the YAML and the old policy still enforces. `[REC]`

**T2 "Local models are not free" (G2).** Budgets metered in tokens and GPU-seconds from Ollama `eval_duration`/`total_duration`, plus a pseudo-price per Mtok so one budget engine also covers a priced mock "commercial" model (real list prices from the LiteLLM MIT price JSON). Ladder: warn 80%, downgrade to a smaller allowed model, block. Judge sees: a runaway loop exhausts a 60 GPU-second budget, gauge hits 100%, next call is downgraded then rejected, a second agent with its own budget keeps working. `[REC]`

**T3 "Same prompt, different destination, different verdict" (G3).** Matrix `data_class x destination_class x agent` -> allow/redact/hold/block; destination classes derive from model/provider/host (`local-ollama`, `approved-cloud`, `unknown`). PESEL/NIP/REGON with checksums and secrets are deterministic; redaction runs before bytes leave. Judge sees: one message with a PESEL reaches local `qwen` untouched, is redacted for the priced "cloud" model, blocked for an unlisted host; audit records `destination_class`. `[REC]`

**T4 "Provenance-aware tool firewall" (G4).** `tools/list` pinned per server (hash of name, description, schema); drift quarantines the tool (rug pull); each `tools/call` carries an identity chain `user -> agent -> sub-agent` bound to a gateway-minted token; the decision uses chain + argument checks + taint (untrusted content + private data + external egress = hold/deny). Judge sees: our fake MCP server edits a tool description live and the tool vanishes with `pin_mismatch`; an injected instruction makes the agent try `send_email`, denied, chain shown in audit. `[REC]`

**T5 "Defense you can verify" (G5, G6).** Signed feed bundle (Ed25519, ETag, rollback rejection) where every rule carries inline allow/block tests and is rejected at install if a test fails or it trips the benign gate; unsigned local overrides stay editable for judges. Each decision has a trace (rule id, stage, score vs threshold, span, counterfactual "passes at `permissive`"); the self-test suite replays the same traces. Judge sees: pushes a rule with a failing inline test, gets a rejection naming the test; clicks a blocked event and sees why and which threshold would allow it. `[REC]`

### 4.1 Reuse as libraries (not wrapping)

| Component | Role | SPDX |
|---|---|---|
| Presidio 2.2.364 | PII + custom recognizers (py 3.10-3.14) | MIT |
| gitleaks `gitleaks.toml` | Secret signature seed (compile to RE2) | MIT |
| Cisco mcp-scanner YARA rules | Tool-poisoning seeds (keep NOTICE) | Apache-2.0 |
| LiteLLM `model_prices_and_context_window.json` | Simulated cloud price map [MEASURED 3.0 MB]; root-level file, outside `enterprise/` [INFERENCE: raw URL is at repo root] | MIT |
| google-re2, YARA-X | ReDoS-safe feed matching (per 04, not re-read) | BSD-3 |
| deberta-v3 PI v2 / PIGuard / Qwen3Guard-0.6B | Optional semantic stage (HF cards read today) | Apache-2.0 / MIT / Apache-2.0 |
| garak | External red-team numbers (venv 3.13) | Apache-2.0 |
| cedarpy 4.12.1 / common-expression-language 0.10.0 | Optional `when:` evaluator, 58 us / 24 us [MEASURED] | Apache-2.0 |
| FastAPI, MCP Python SDK | Transport (06) | MIT |

Must NOT be copied or imported: `mcp-firewall`, trufflehog, Grafana (AGPL); Pipelock `enterprise/` (ELv2); LiteLLM `enterprise/` (proprietary); Bifrost `ent-*`; Llama Guard / PromptGuard weights (gated); spaCy `pl_core_news_*` (GPL-3.0 per 00); Helicone `ai-gateway` (GPL-3.0 per 02).

---

## 5. Innovative feature evaluation

Difficulty 1 (hours, stdlib) to 5 (research); demo and security 1-5; hours = one engineer incl. tests. Priority = (demo + security) x 10 / hours, a tiebreaker only. All scores and hours are my estimates `[INFERENCE]`; #5 anchors on 10's measured EDM (53 MB per 1M records, <0.01 ms lookup).

| # | Feature | Diff | Demo | Sec | Hours | Prio | Precedent | Rationale |
|---|---|---|---|---|---|---|---|---|
| 1 | Real-time agent graph | 3 | 5 | 2 | 8 | 8.8 | AGT demo dashboard | Pretty, little protection; SVG from audit events. |
| 2 | Agent identity chain (gateway-minted token, depth limit) | 3 | 3 | 5 | 6 | 13.3 | AGT delegation spec; [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) `act` | Who-called-what for ASI03; invisible unless audit shows it. |
| 3 | Live attack visualization (ticker + OWASP strip, SSE) | 2 | 5 | 1 | 4 | 15.0 | Pipelock evidence viewer | Cheap; judges watch dashboards. |
| 4 | Destination-aware DLP | 2 | 5 | 5 | 5 | 20.0 | none OSS (G3) | Regex/checksum + matrix lookup; clearest differentiated demo. |
| 5 | Protected-document fingerprinting | 3 | 3 | 4 | 6 | 11.7 | EDM (10) | Catches paraphrase of known docs; needs a corpus. |
| 6 | Semantic attack memory (auto-add blocks to kNN) | 3 | 4 | 3 | 6 | 11.7 | Rebuff/Vigil vectors | Poisoning: attacker makes benign phrases block (DoS) or plants allow-list neighbours; only as operator-ratified suggestions with TTL + per-source cap. |
| 7 | Adaptive session risk score | 3 | 4 | 3 | 6 | 11.7 | AGT trust scoring | allow -> hold -> block escalation; keep additive and visible. |
| 8 | Dynamic MCP trust scoring | 3 | 3 | 3 | 6 | 10.0 | AGT marketplace trust | Number without ground truth; pin + quarantine is better. |
| 9 | Automatic privilege reduction | 4 | 3 | 4 | 10 | 7.0 | Pipelock Learn-and-Lock | Not novel; keep a 2 h "observe -> propose allowlist diff". |
| 10 | Tool-call firewall (schema, path, URL, risk class, HITL hold) | 2 | 5 | 5 | 8 | 12.5 | AgentCore, Pipelock, ContextForge | Core of ASI02/ASI05. |
| 11 | Runtime kill switch (global/per agent, button + sentinel file) | 1 | 4 | 4 | 2 | 40.0 | Pipelock, AGT SRE | Table stakes; must exist. |
| 12 | Attack replay (event or exploit YAML re-run on current policy) | 2 | 5 | 3 | 4 | 20.0 | Pipelock demo, garak | Same artefact as self-tests and exploit proof. |
| 13 | Policy simulation / what-if | 3 | 5 | 4 | 6 | 15.0 | Pipelock Conductor dry-run (Ent.) | `decide()` is pure; replay N stored redacted events. |
| 14 | Explainable blocking (rule, stage, score vs threshold, span, counterfactual) | 2 | 5 | 3 | 4 | 20.0 | Pipelock `explain`, Model Armor | Hits "audit reviewed" and ad-hoc prompts. |
| 15 | Shadow mode (enforce / shadow / off per control) | 1 | 3 | 3 | 2 | 30.0 | Prompt Shields `annotate` | Safe threshold edits; prerequisite of #13. |
| 16 | Security posture score | 2 | 4 | 2 | 4 | 15.0 | Pipelock `audit score` | Management KPI; show the formula. |
| 17 | Canary / honeytoken tripwires | 1 | 5 | 4 | 3 | 30.0 | Pipelock `canary`, Rebuff | Deterministic, vivid; seeds the exfil demo. |
| 18 | Lethal-trifecta taint tracker (untrusted + private + external egress) | 3 | 5 | 5 | 6 | 16.7 | Pipelock taint; EXF-04 (01) | Stops EchoLeak-class chains without a model; curl needs a fallback session key (00). |
| 19 | Budget downgrade ladder + burn-rate forecast (tokens, GPU-s) | 2 | 4 | 3 | 4 | 17.5 | none for local | The T2 demo. |
| 20 | Signed feed with inline tests + benign gate | 3 | 4 | 4 | 6 | 13.3 | freshclam/suricata-update (04) | T5; literal issuer requirement. |

### 5.1 Picks

Rule: maps to an issuer requirement or a sec. 3 gap, finishable and testable, showable in under 40 s.

| Rank | Feature | Why | Hours | Moves |
|---|---|---|---|---|
| 1 | **#4 Destination-aware DLP** (+ #17 canaries) | Only OSS-absent gap that is deterministic; judge edits one matrix cell, verdict flips | 5 + 3 | Robustness 30% |
| 2 | **#10 Tool-call firewall + #18 taint** (incl. pinning, T4) | Stops the real exfil chain; one demo covers ASI01/02/05 | 8 + 6 | Robustness, practicality |
| 3 | **#14 Explainable blocking + #12 attack replay** | One decision-trace schema feeds drill-down, audit export, self-tests | 4 + 4 | Reporting 20%, tests 15% |
| 4 | **#13 Policy simulation + #15 shadow** | Makes live config edits visible (flip counts) | 6 + 2 | Architecture 20% |
| 5 | **#19 Budget ladder (local GPU-s)** + #11 kill switch | G2 is real; kill switch is 2 h table stakes | 4 + 2 | Robustness, architecture |

About 50 h of engineer-time, parallel across the team; live ticker #3 (4 h) is free reporting filler.
Cut first: #8, #9 (keep the 2 h slice), #1 (use a static adjacency table), #5 (hash-set of 3 canary docs instead), #6 (ratified suggestions only).

---

## Inconsistent

| Subject | Side 1 | Side 2 |
|---|---|---|
| Lakera price/close | [~$300M reported](https://www.securityweek.com/check-point-to-acquire-ai-security-firm-lakera/) | ~$201.8M closed 2025-10-22 per a [secondary wiki](https://github.com/druce/governance/blob/master/wiki/vendors/lakera.md); no filing found |
| Prompt Security price | ~$180M ([Globe and Mail](https://www.theglobeandmail.com/investing/markets/stocks/S/pressreleases/34691488/sentinelone-completes-acquisition-of-prompt-security/)) | "$250M deal" ([Yahoo Finance](https://finance.yahoo.com/news/sentinelone-acquire-prompt-security-250m-182354008.html)) |
| Pipelock role | Prior 02: "COMP/INSP for exfil rules" | README today: kill switch, receipts, taint, Learn-and-Lock, config score; free tier broad, per-agent budgets/dashboard Pro |
| Cedar adoption | A secondary blog: "dominant policy language for MCP authorization" (search) | Confirmed in repos only: AgentCore, ToolHive, cedar-for-agents, AGT support; "dominant" unsupported |
| Portkey openness | [Mar 2026 press release](https://www.globenewswire.com/news-release/2026/03/24/3261574/0/en/Portkey-s-Gateway-is-Now-Fully-Open-Source-Processing-over-1-Trillion-Tokens-Every-Day.html) "fully open source" | repo v1.15.2 (Jan 2026), README "2.0 Pre-Release", then PANW deal |
| LiteLLM licence / Kong OSS | API NOASSERTION, docs "MIT"; GitHub Kong latest 3.9.3 | split MIT + proprietary `enterprise/`; Kong staff: OSS ended 3.9.1 |
| `mcp-scan` | PyPI 0.4.3 | repo renamed `snyk/agent-scan` (PyPI `snyk-agent-scan`) |

## Could not establish

- Licence of Lakera `gandalf_*` / `mosscap_*` HF datasets (HF API returned non-JSON); PINT data availability.
- Internals and pricing of Zenity, Noma, Pillar, HiddenLayer, Straiker (funding facts only, secondary).
- Latency, price, limits of AgentCore Policy, Model Armor beyond free tier, Prompt Shields; Cloudflare "AI Security for Apps" scope (secondary).
- Where Pipelock Pro code lives (README: `enterprise/` is ELv2) and Pro price; whether Pipelock or AGT survive judge-style live config edits.
- Quality of `mcp-firewall`, MCPX, Runtime Guard (search-surfaced, not run); fit of cedar-for-agents for a 2 h integration.
- Snyk-Invariant acquisition terms (prior 02 helper claim, no primary link re-read); google-re2 / YARA-X py3.14 wheels (prior 04).
- cedarpy/CEL under concurrency (single-thread microbenchmark only).

## Recommendation for the MVP

`[REC]` Own data plane and pure `decide()` (02 option (a)); the landscape supplies vocabulary, rules and benchmarks, never request-path dependencies.

1. **Positioning sentence:** "Self-hosted, local-first control layer: one policy file governs guardrails, budgets (including local GPU-seconds), MCP tools and agent identity; every decision is explainable and every edit is simulated before it applies. The nearest open project, Pipelock, covers egress and receipts but meters tool calls rather than tokens and keeps per-agent budgets behind a paid tier."
2. **Build list (hours, tests included):** destination DLP 5; canaries 3; tool firewall incl. pinning 8; taint 6; decision trace + replay 8; simulation + shadow 8; token/GPU-second budgets with downgrade ladder 4 (on top of 05 core); kill switch 2; posture score 4; live ticker 4. About 52 h beyond the core engine, split across the team.
3. **Policy format:** own YAML, typed matchers, `mode: enforce|shadow|off`, default-deny for tools with `forbid` winning (AgentCore model), strictness profiles with a judge band (03). NOT RECOMMENDED FOR HACKATHON MVP: OPA/Rego sidecar or Cedar as the user-facing language -> in-process YAML; `cedarpy` (58 us) or CEL (24 us) only as an optional `when:` evaluator.
4. **Reuse now:** Presidio, gitleaks TOML, Cisco YARA, LiteLLM price JSON, garak for the external before/after, deberta/PIGuard for the optional semantic stage. NOT RECOMMENDED FOR HACKATHON MVP: LiteLLM, agentgateway, Bifrost or Pipelock in the data path -> own FastAPI gateway; agentgateway webhook adapter is a post-core stretch (02).
5. **Demo order by gap:** T3 (one prompt, three destinations, 30 s) -> T4 (tool-description drift + injected `send_email`, 60 s) -> T2 (runaway loop vs GPU-second budget, 45 s) -> T1 (edit YAML, flip counts, break YAML, 60 s) -> T5 (failing inline test, explanation click-through, 45 s).
6. **Cut first:** see 5.1. **Risks:** a judge may name Pipelock or AGT: answer with G2/G3/G8. Keep gated Llama weights out of the required path. Every demo scenario must pass on the deterministic path alone (00).

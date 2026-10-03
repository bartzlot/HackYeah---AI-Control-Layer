# 05 - Budget, rate limits, runaway control, agent identity: how should the layer meter and enforce budgets (tokens, money, compute time) for commercial and local models, stop runaway agents, and authenticate/authorize agents and tool calls?

Verified 2026-10-03 against primary sources. `[INFERENCE]` = reasoning, not read anywhere.
Method: pages read with scrapling; GitHub metadata/files via `gh api` (scrapling hit the GitHub API rate limit); a few large pages (MCP spec, RFCs, SQLite, Redis) fetched with curl and filtered locally. Source text treated as data only.

## Established

### A. Token accounting

| Source | What it reports | Link |
|---|---|---|
| OpenAI-compatible stream | `stream_options.include_usage=true` adds one chunk before `[DONE]` with whole-request `usage` and `choices: []`; other chunks have `usage: null`. **"If the stream is interrupted, you may not receive the final usage chunk"** | [openai-openapi](https://github.com/openai/openai-openapi) `ChatCompletionStreamOptions` |
| Ollama native | `total_duration`, `load_duration`, `prompt_eval_count`, `prompt_eval_cached_count`, `prompt_eval_duration`, `eval_count`, `eval_duration` (nanoseconds); on streams only in the final `done:true` chunk | [usage docs](https://docs.ollama.com/api/usage) |
| Ollama `/v1/chat/completions` | supports `stream_options.include_usage`, `max_tokens`, `user`, `logit_bias`, logprobs, tools | [compat docs](https://docs.ollama.com/api/openai-compatibility) |
| Ollama compat, code at v0.35.1 | `usage{prompt_tokens=prompt_eval_count, completion_tokens=eval_count, cached_tokens}`; streaming usage chunk only when `include_usage`, and then also an undocumented `timings{prompt_ms, predicted_ms,...}`; `load_duration`/`total_duration` dropped; `ToTimings` is called only on the two streaming paths (non-stream responses have usage but no timings) | [openai.go](https://github.com/ollama/ollama/blob/v0.35.1/openai/openai.go), [middleware/openai.go](https://github.com/ollama/ollama/blob/v0.35.1/middleware/openai.go) |
| Provider quirk | OpenAI `prompt_tokens` includes cached tokens, Anthropic `input_tokens` does not | [TensorZero docs](https://github.com/tensorzero/tensorzero/blob/main/docs/operations/track-usage-and-cost.mdx) |

Ollama defaults: `num_predict` = -1 (infinite generation) ([Modelfile](https://github.com/ollama/ollama/blob/main/docs/modelfile.mdx)), so the gateway MUST inject `max_tokens`. `OLLAMA_NUM_PARALLEL` default 1, `OLLAMA_MAX_QUEUE` 512, RAM scales with NUM_PARALLEL x context ([FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)); this Ollama is shared with the other project, so the gateway needs its own local concurrency cap.

Estimation libs: [tiktoken](https://github.com/openai/tiktoken) MIT 0.14.0; [HF tokenizers](https://github.com/huggingface/tokenizers) Apache-2.0 v0.23.2. No Ollama tokenize endpoint found. `[INFERENCE]` For worst-case reservation use `ceil(utf8_bytes/3)` (over-counts, so conservative) and settle with real `prompt_eval_count`.

### B. Prices and local cost

| Item | Fact |
|---|---|
| LiteLLM map | [`model_prices_and_context_window.json`](https://github.com/BerriAI/litellm/blob/main/model_prices_and_context_window.json): 3.0 MB, 4460 entries; [schema](https://github.com/BerriAI/litellm/blob/main/model_prices_and_context_window.schema.json) (USD per unit, ignore unknown fields). Keys `input_cost_per_token`, `output_cost_per_token`, `cache_read_input_token_cost`, `max_input_tokens`, `max_output_tokens`. `gpt-4o-mini` 1.5e-7/6e-7; `claude-haiku-4-5` 1e-6/5e-6; 29 `ollama/*` entries all `0.0`. Repo MIT outside `enterprise/` ([LICENSE](https://github.com/BerriAI/litellm/blob/main/LICENSE)) |
| OpenRouter | public `GET https://openrouter.ai/api/v1/models`: 466 models; `pricing.prompt/completion` are strings, USD per token; `context_length`, `top_provider.max_completion_tokens` |
| LiteLLM local | `cost_per_second` (v1.105.0+, times full duration incl. streaming); **explicit zero token costs make LiteLLM skip ALL budget checks for that model** (a documented feature) ([custom pricing](https://docs.litellm.ai/docs/proxy/custom_pricing)) |
| TensorZero | cost = list of `{JSON Pointer into provider response, cost_per_million/unit}`, negatives allowed; cost limits pre-estimate with `default_cost` $1.00 then adjust ([rate limits](https://github.com/tensorzero/tensorzero/blob/main/docs/operations/enforce-custom-rate-limits.mdx)) |
| Portkey | USD or token budgets, weekly/monthly reset, alert thresholds; **Enterprise/select Pro only**; unpriced models count 0 ([docs](https://portkey.ai/docs/product/ai-gateway/virtual-keys/budget-limits)) |

None treats local compute as a first-class budget. The criteria require local budgets, so a separate `gpu_seconds` metric plus optional USD-equivalent is a differentiator. `[INFERENCE]` `gpu_s = (prompt_eval_duration+eval_duration)/1e9` (native) or `(timings.prompt_ms+predicted_ms)/1000` (compat stream); `usd_equiv = gpu_s * usd_per_gpu_second` where the rate is a config calibration knob (amortized hardware or energy x tariff; no verified M5 wattage found). Fallback: gateway stopwatch (includes queue wait, over-charges).

### C. Gateways

| Project | License / maturity | Budget features | Fit |
|---|---|---|---|
| [LiteLLM](https://github.com/BerriAI/litellm) | MIT + commercial `enterprise/` dir ([terms](https://github.com/BerriAI/litellm/blob/main/enterprise/LICENSE.md)); v1.103.2 (2026-10-01) | budgets global/team/member/user/key/end-user/org/tag; multi-window per key ($10/24h AND $100/30d); **reservation on by default** (max cost from `max_tokens` or model limits, reserve, replace by actual); Redis counters, `fail_closed_*`; TPM/RPM/max_parallel; agent `tpm/rpm`, `max_iterations`, `max_budget_per_session` (429); `model_max_budget` is Enterprise; **needs Postgres, otherwise budgets do not cap** ([users](https://docs.litellm.ai/docs/proxy/users), [iterations](https://docs.litellm.ai/docs/a2a_iteration_budgets)) | best design reference, heavy to embed |
| [Portkey gateway](https://github.com/Portkey-AI/gateway) | MIT; v1.15.2 (2026-01-12); docs say "now PRISMA AIRS AI Gateway" | repo tree has no budget code; budgets are hosted | no |
| [TensorZero](https://github.com/tensorzero/tensorzero) | Apache-2.0, **archived**, last push 2026-06-11 | rules per `model_inferences`/`tokens`/`cost`, tag or key scope, Valkey/Postgres, fixed (not sliding) windows | design reference only |

Supply chain: LiteLLM PyPI `1.82.7`/`1.82.8` were malicious (credential stealer, 2026-03-24, about 40 min); clean `v1.83.0`; official Docker image unaffected ([post](https://docs.litellm.ai/blog/security-update-march-2026), [JFrog](https://research.jfrog.com/post/litellm-compromised-teampcp)).

### D. Enforcement primitives

- SQLite: `BEGIN IMMEDIATE` takes the write lock up front ([docs](https://www.sqlite.org/lang_transaction.html)); WAL lets readers and writer proceed concurrently ([docs](https://www.sqlite.org/wal.html)). `[INFERENCE]` one conditional `UPDATE ... WHERE spent+reserved+:r<=:limit` plus rowcount is an atomic check-and-increment.
- Redis Lua scripts run atomically ([docs](https://redis.io/docs/latest/develop/programmability/eval-intro/)). Redis 8+ is RSALv2/SSPLv1/AGPLv3, 7.2 and older BSD ([LICENSE](https://github.com/redis/redis/blob/HEAD/LICENSE.txt)); [Valkey](https://github.com/valkey-io/valkey) is BSD-3.
- Libs: [redis-cell](https://github.com/brandur/redis-cell) MIT (GCRA), [limits](https://github.com/alisaifee/limits) MIT, [PyrateLimiter](https://github.com/vutran1710/PyrateLimiter) MIT. `[INFERENCE]` GCRA is one float per key, about 15 lines in-process.
- LiteLLM on Redis outage falls back to per-instance counters (N x limit) unless `fail_closed_rate_limit_enforcement` (then 503) ([users](https://docs.litellm.ai/docs/proxy/users)).

### E. Runaway / unbounded consumption

- [OWASP LLM10:2025](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/): input flood, denial of wallet, continuous input overflow, resource-intensive queries, model extraction, side channels. Mitigations: input size validation, **restrict logits/logprobs**, rate limits and quotas, resource allocation, timeouts/throttling, sandboxing, logging/anomaly detection, graceful degradation, limit queued/total actions, access control. Cites Sponge Examples and ATLAS AML.T0034 Cost Harvesting.
- Reference thresholds: OpenHands stuck detector = 4+ identical action-observation cycles, 3+ action-error repeats, 3+ monologue messages, 6+ alternating cycles, actions compared by tool name + content ([docs](https://docs.openhands.dev/sdk/guides/agent-stuck-detector)). OpenAI Agents SDK `DEFAULT_MAX_TURNS = 10` ([source](https://github.com/openai/openai-agents-python/blob/main/src/agents/run_config.py)); LangGraph `recursion_limit` 25 ([ref](https://reference.langchain.com/python/langgraph-sdk/schema/Config/recursion_limit)); LiteLLM example 25 iterations / $5 per session, needs a session id header, counters expire after 1 h.
- MCP 2026-07-28 removed protocol sessions and `Mcp-Session-Id`, and documents `traceparent`/`baggage` in `_meta` ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)); `[INFERENCE]` the gateway must mint its own session id and can carry hop depth in `_meta`/a header.

### F. Identity and authorization

| Topic | Facts |
|---|---|
| MCP versions | Current = **2026-07-28** ([versioning](https://modelcontextprotocol.io/specification/versioning)). Auth is OPTIONAL; HTTP transports SHOULD follow it, stdio SHOULD NOT. **2025-06-18**: server is OAuth 2.1 resource server, MUST serve RFC 9728 metadata, clients MUST send RFC 8707 `resource`, server MUST validate audience and MUST NOT pass tokens through upstream ([spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)). **2025-11-25** adds scope challenge/step-up (`403` + `WWW-Authenticate error="insufficient_scope"`), PKCE S256 checks, Client ID Metadata Documents ([spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)). **2026-07-28**: `iss` check (RFC 9207), DCR deprecated for CIMD, no initialize/session, required `Mcp-Method`/`Mcp-Name` headers ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog), [headers](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)) |
| Passthrough | "explicitly forbidden": breaks audience-bound rate limits, audit trail, confused deputy ([best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)) |
| Tools spec | SHOULD keep a human in the loop able to deny; servers MUST validate inputs, enforce access control, **rate limit tool calls**; **annotations are untrusted** unless server trusted ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)) |
| OAuth/JWT RFCs | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.txt) token exchange (impersonation vs delegation, nestable `act`, `may_act`); [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.txt) DPoP proof-of-possession; [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.txt) JWT BCP; [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.txt) JWT access-token profile. [PyJWT](https://github.com/jpadilla/pyjwt) MIT |
| A2A | v1.0.1, Apache-2.0: auth schemes in `AgentCard.securitySchemes`, credentials out-of-band, server MUST authenticate every request and authorize per skill/action/data/scope, `TASK_STATE_AUTH_REQUIRED` covers "human approval before a destructive action", cards MAY be JWS-signed over JCS ([spec](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)) |
| SPIFFE | SPIFFE ID + X.509/JWT SVID, JWT-SVID replayable ([concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)); [SPIRE](https://github.com/spiffe/spire) Apache-2.0 v1.15.3. `[INFERENCE]` too heavy for 24-36 h |

Policy engines: **plain YAML + Python** (fastest, judge-editable); [Cedar via cedarpy](https://github.com/k9securityio/cedar-py) (Apache-2.0, v4.12.1, macOS arm64 wheels Python 3.11-3.14, unofficial; request `context` carries argument attributes); [OPA](https://github.com/open-policy-agent/opa) v1.21.1 is a Go sidecar and the [regorus](https://github.com/microsoft/regorus) Python binding is "not yet available in PyPI" ([README](https://github.com/microsoft/regorus/blob/main/bindings/python/README.md)); [pycasbin](https://github.com/apache/casbin-pycasbin) v2.8.0 (ACL/RBAC/ABAC); [Cerbos](https://github.com/cerbos/cerbos) v0.56.0 sidecar. All Apache-2.0 except regorus (MIT).

Memory/RAG: [OWASP LLM08](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/) = permission-aware stores, logical partitioning, data classification, immutable retrieval logs. [Qdrant](https://qdrant.tech/documentation/manage-data/multitenancy/): tenant id in payload with `is_tenant` index and a `must` filter on it in every query.

## Inconsistent

| Topic | Side 1 | Side 2 |
|---|---|---|
| LiteLLM budget status code | user/key budget returns `code: "400"` ([users](https://docs.litellm.ai/docs/proxy/users)) | session budget and max_iterations return **429** ([iterations](https://docs.litellm.ai/docs/a2a_iteration_budgets)). Our tests expect 429 everywhere |
| Ollama default context | `num_ctx` 2048 ([Modelfile](https://github.com/ollama/ollama/blob/main/docs/modelfile.mdx)) | 4k/32k/256k by VRAM ([context-length](https://github.com/ollama/ollama/blob/main/docs/context-length.mdx)). Set it explicitly |
| Ollama compat timings | docs list usage only | code at v0.35.1 adds `timings` on final stream chunk |
| MCP client registration | 2025-06-18: SHOULD support DCR | 2026-07-28: DCR deprecated for CIMD (version change) |

## Could not establish

- Whether Ollama `eval_count` includes thinking tokens for qwen3.5 (measure with one call).
- A verified M5 wattage or USD per GPU-second.
- An Ollama tokenize endpoint.
- LiteLLM's exact reservation estimate when `max_tokens` is absent beyond "model's configured limits".
- False-positive rates of the loop thresholds (framework defaults only).

## Further

**Recommendation for our build**

Build budget + identity in-process (Python ASGI), seed prices from the LiteLLM JSON (copy about 10 models, pin commit), copy LiteLLM's *design* (reserve then settle, windows, per-session caps), not its code: LiteLLM needs Postgres (5432 is taken), zero-costs local models, returns 400, and had a PyPI compromise; TensorZero is archived; Portkey budgets are paid. This module needs no model and no GPU RAM; its "AI" part is EWMA anomaly detection (content ML stays in 01/03/04). `[INFERENCE]` about 600 LOC, auth+policy+reservation under 1 ms against hundreds of ms Ollama TTFT, RSS under 150 MB, SQLite WAL, ledger writes off the hot path.

Policy file (hot-reloaded by mtime; judges edit live):
```yaml
prices: {gpt-4o-mini: {in: 1.5e-7, out: 6e-7}}
local:  {qwen3.5:9b: {usd_per_gpu_s: 0.0004, pp_tps: 400, tg_tps: 40}}   # calibration knobs
limits: {max_input_tokens: 8000, max_out_cap: 1024, max_depth: 3, max_session_s: 600}
budgets:   # on, metric, period, limit, soft, action
  - {on: org:acme,         metric: usd,         period: month, limit: 5.00, soft: 0.8, action: block}
  - {on: agent:researcher, metric: usd,         period: day,   limit: 0.05, soft: 0.8, action: downgrade, to: qwen3.5:9b}
  - {on: agent:researcher, metric: gpu_seconds, period: hour,  limit: 300, action: block}
  - {on: session:*,        metric: steps,       period: session, limit: 25, action: block}
agents:
  researcher: {models: [gpt-4o-mini, qwen3.5:9b], mem_ns: [acme/shared, acme/researcher],
               tools: {web.search: {}, fs.read: {args: {path: {prefix: /workspace/}}}}}
  writer:     {models: [qwen3.5:9b], mem_ns: [acme/writer],
               tools: {fs.write: {args: {path: {prefix: /out/}}}, email.send: {approval: true}}}
loops: {repeat_identical: 4, repeat_error: 3, pingpong_cycles: 6, monologue: 3}
```

**Data model (SQLite, WAL)**

| Table | Key columns |
|---|---|
| `principals` | `id PK` (`org:acme`, `team:`, `project:`, `agent:researcher`, `user:`), `kind`, `parent_id` (chain org>team>project>agent; session/user attach per call) |
| `api_keys` | `key_hash PK` (sha256), `principal_id`, `scopes`, `expires_at`, `revoked_at` |
| `budgets` | `id PK`, `principal_id`, `metric` (usd/tokens/gpu_seconds/calls/steps), `period`, `limit`, `soft_pct`, `action` (block/downgrade/warn), `downgrade_to`, `model_scope` (mirror of policy file) |
| `counters` | `PK(budget_id, window_start)`, `spent`, `reserved`, `alerted` |
| `reservations` | `id`, `request_id`, `budget_id`, `amount`, `expires_at` (sweeper) |
| `sessions` | `session_id PK`, `agent_id`, `parent_session`, `depth`, `started_at`, `steps`, `tool_calls`, `usd`, `tokens`, `state`, `halt_reason`, `recent` (ring of 20 call hashes) |
| `ledger` (append-only) | ULID, `ts`, `request_id`, `session_id`, principal chain, `user`, `key_id`, `model`, `kind`, `prompt/completion/cached_tokens`, `usd`, `gpu_s`, `wall_ms`, `usage_source` (provider/estimated), `decision`, `reservation`, `hop_depth` |
| `approvals` | `id`, `session_id`, `tool`, `args_hash`, `status`, `approver`, `expires_at`, `used_at` |
| `audit` | hash-chained events (`prev_hash`, `hash`) for export |

**Enforcement algorithm (LLM request)**
1. Authenticate key/JWT to principal chain (401 unknown/expired, 403 revoked). Identity asserted in headers/body (`X-Agent-Id`, `user`) must equal the bound one, else 403 `impersonation` + audit.
2. Session: `x-acl-session` (mint if absent); halted -> 429 `session_halted`; delegation-token `depth` > `max_depth` -> 429 `depth_exceeded`.
3. Model allowlist per agent, else 403.
4. Shape: estimate input; > `max_input_tokens` -> 413; rewrite `max_tokens=min(req, max_out_cap)`, `stream_options.include_usage=true`, drop `logprobs`/`logit_bias`, set `num_ctx`.
5. Loop pre-checks: steps, session wall-clock, repeat/ping-pong from tool-call history -> 429 `loop_detected|max_steps|session_timeout`.
6. Rate: GCRA RPM, token-bucket TPM debited `est_in+max_out`, concurrency semaphores per key and per local model (cap 1-2 for shared Ollama; bounded wait, then 429 + `Retry-After`).
7. Worst-case cost: commercial `est_in*p_in+max_out*p_out`; local `est_in/pp_tps+max_out/tg_tps` gpu_s (EMA of observed speeds) and its USD-equivalent.
8. Reserve in one `BEGIN IMMEDIATE` txn across every applicable budget: `UPDATE counters SET reserved=reserved+:r WHERE budget_id=:b AND window_start=:w AND spent+reserved+:r<=:limit`; rowcount 0 = over. Over and `action=downgrade` with a passing fallback (one swap, redo 3-8) -> serve fallback with `x-acl-downgraded-from`; otherwise rollback, 429 `budget_exceeded {budget_id, level, metric, limit, spent, reset_at}`. Crossing `soft_pct` -> one alert event per window + `x-acl-budget-warning`.
9. Forward (httpx stream) with the gateway's own upstream credential; idle timeout + hard deadline; client disconnect cancels upstream.
10. Settle in `finally`: real usage from final chunk/body, else estimate (`est_in` + received chunks) with `usage_source=estimated`; one txn `reserved-=r, spent+=actual`, ledger row, TPM refund, release semaphores, `steps++`.
11. Post: update EWMA speed and token velocity; extract `tool_calls`, push `sha256(tool+sorted args)` into the session ring; run repeat/ping-pong detectors; trip -> `halted` + alert.
12. Sweeper every 30 s frees expired reservations (LiteLLM documents a flag for unreconciled reservations).

Overshoot `[INFERENCE]`: without reservation, worst overshoot = cost of all in-flight requests (10 parallel x $0.06 = $0.60 over a $0.05 cap); with reservation admitted spend never exceeds the limit, at the cost of conservative rejections near the cap.

**Tool-call path (MCP `tools/call`, A2A skill):** authenticate; deny-by-default per-agent allowlist; argument constraints checked on the JSON-RPC **body** (headers are redundant, body is truth); risk class from **our policy** (annotations untrusted); `approval: true` creates a single-use approval bound to `(session, tool, args_hash)`, TTL 5 min, approved on the dashboard; per-tool rate limit and `calls` budget; repeat detector; forward with gateway-held credential (no passthrough); audit.

**Memory/RAG:** namespace `tenant/owner`; agent policy lists allowed `mem_ns`; gateway rejects other namespaces and **injects** the filter (`tenant == caller.tenant AND acl_groups ∩ caller.groups`), never trusting an agent-supplied `where`; post-filter results; writes stamp `owner/acl/source`; log every retrieval.

**Identity scheme for the hackathon**
- Tier 0 (must): per-agent opaque keys `acl_<agent>_<random>`, stored as sha256; identity only from the key; claims in headers are compared, never trusted.
- Tier 1 (+2 h): `POST /token` mints a 5-min JWT (PyJWT, **pinned alg**, RFC 8725) with `sub=agent:researcher`, canonical `aud`, `scope="llm:qwen3.5:9b tool:web.search"`, `jti`, `exp`, `session`, `depth`, `act` when acting for a user. Exchange (RFC 8693 shape) only **narrows** scope and increments `depth`; used for agent-to-agent hops and budget slices.
- Tier 2 (stretch): DPoP-style proof (`cnf` thumbprint, signed `htm/htu/iat/jti`) so a stolen token fails. SPIFFE and a full OAuth AS: roadmap only.
- Cast: `researcher` (`web.search`, `fs.read` under `/workspace/`, $0.05/day commercial-sim then downgrade), `writer` (`fs.write` under `/out/`, `email.send` needs approval), `rogue`. Commercial-sim = mock upstream returning OpenAI-shaped `usage`, billed at `gpt-4o-mini` prices (no paid API allowed).

**Test cases** (offline with fake upstream; local cases need one Ollama call)

| ID | Action | Expected |
|---|---|---|
| B1 | agent day budget $0.0005, call until exhausted | 200s then **429 `budget_exceeded`** with budget_id/limit/spent/reset_at; ledger `block:budget` |
| B2 | cross 80% | 200 + `x-acl-budget-warning`, exactly one alert per window |
| B3 | `downgrade` policy, commercial budget empty | 200 from `qwen3.5:9b`, `x-acl-downgraded-from`, ledger `downgrade`; local gpu budget also empty -> 429 |
| B4 | 20 parallel calls, budget fits 5 reservations | exactly 5 admitted, 15 x 429, `spent<=limit` |
| B5/B6 | stream without client `include_usage`; client aborts mid-stream | usage injected, no extra chunk to client; abort settles with `usage_source=estimated`, no leaked reservation |
| B7 | local `gpu_seconds` budget 1 s | gpu_s in ledger, later call 429 |
| B8 | edit policy limit 5.00 -> 0.01 live | next call 429, no restart |
| B9 | RPM=3 | 4th 429 + `Retry-After`, recovers |
| B10/B11 | no `max_tokens` or 10^6; prompt > `max_input_tokens` | value clamped; 413, no upstream call, zero cost |
| L1/L2 | identical tool+args x4; A,B ping-pong x6 | `loop_detected`, session `halted` |
| L3/L4/L5 | 26th call with max 25; session > 600 s; depth 4 | 429 `max_steps` / `session_timeout` (stream cut) / `depth_exceeded` |
| L6 | token velocity > 5x EWMA and floor | alert; at 10x block |
| I1/I2 | `researcher` calls `web.search`; `writer` calls `web.search`, `rogue` calls `fs.write` | 200; 403 `tool_not_allowed` |
| I3 | `researcher` key + `X-Agent-Id: writer` | 403 `impersonation`, audit event |
| I4 | forged `sub`, `alg:none`, expired, wrong `aud` | rejected, distinct audit reason each |
| I5 | exchange requests scope parent lacks | narrowed or rejected |
| I6 | `fs.read /etc/passwd` vs `/workspace/a.txt` | 403 `arg_violation` vs 200 |
| I7 | `email.send` | `approval_required`; after approve one call 200; replay or changed args 403 |
| I8 | tool call to upstream MCP | fake upstream sees gateway credential, never the agent token |
| M1/M2 | query another agent's namespace; shared ns doc with ACL excluding caller | 403 `namespace_denied`; doc absent |

Dashboard: spend/gpu_seconds per agent, burn bars with soft/hard lines, blocks by reason, loop trips, downgrades, pending approvals; export ledger CSV/JSONL and the hash-chained audit.

**Risks**

| Risk | Mitigation |
|---|---|
| Local gpu-second price is an assumption | show raw gpu_seconds, label rate "model assumption", config knob |
| Interrupted streams lose usage | estimate and flag, never skip settle |
| Conservative reservation rejects legit calls near cap | small `max_out_cap` default, show reservation in 429 body |
| Hot-reload race | atomic swap, request pins policy version, invalid file keeps last good + dashboard error |
| Shared Ollama contention | local semaphore 1-2, bounded queue, `num_ctx` clamp |
| Loop false positives | warn then block, per-tool override |
| Bearer theft at Tier 0/1 | short TTL, audience binding, DPoP stretch; say so honestly |
| Licensing | LiteLLM `enterprise/` commercial; Redis 8 RSAL/SSPL/AGPL (use Valkey or none); cedarpy unofficial |
| Port clashes / spec churn (3 MCP revisions in 13 months) | SQLite avoids 5432; terminate own auth, target 2026-07-28, keep audience binding and no passthrough (stable across all three) |

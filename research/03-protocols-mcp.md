# 03 - Protocols and MCP: which protocols and wire formats must the layer speak, and how exactly do we intercept and authorize MCP?

Verified 2026-10-03 against primary sources.
Legend: `[EST]` established technique, `[EXP]` experimental, `[REC]` our recommendation, `[INFERENCE]` reasoning not read anywhere, `[MEASURED]` run locally today.

Method: MCP spec as markdown from modelcontextprotocol.io; GitHub `gh api`; PyPI JSON; datatracker; Ollama docs/code at `v0.35.1`. Shared Ollama untouched: Ollama stream examples are code-derived. Prior files 01, 02, 04, 05 reused.

**Revision used: MCP 2026-07-28 is the latest** ([versioning](https://modelcontextprotocol.io/specification/versioning), [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)). Prior claim "removed protocol sessions" is CONFIRMED but incomplete: it also removed `initialize`, GET streams, `Last-Event-ID`, `ping` and all server-initiated requests. Most deployed servers and clients still speak 2025-11-25, so the gateway MUST speak both eras.

## 1. Protocol table (MUST / SHOULD / LATER / NO)

| Protocol | Verdict | Why / where it bites | Source |
|---|---|---|---|
| HTTP/1.1 | **MUST** | Ollama, OpenAI SDKs, MCP clients use it; keep-alive, chunked, no response buffering | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) |
| HTTP/2, gRPC, WebSocket | **NO** | uvicorn 0.53.0 (2026-09-14) has only experimental opt-in HTTP/2 ([notes](https://github.com/Kludex/uvicorn/releases/tag/0.53.0)). MCP has no WebSocket transport ([transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/index)). gRPC only for optional A2A binding and OTLP/gRPC; use OTLP/HTTP | - |
| HTTPS termination | **SHOULD** | MVP: 127.0.0.1 plain HTTP (OAuth 2.1 allows loopback); optional mkcert. No MITM/CA (prior 07-10 pivot) | [MCP auth security](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) |
| REST + JSON | **MUST** | Admin/audit API, OpenAI surface; `orjson` 3.12.0 0.08 ms vs 0.30 ms stdlib on 59 KB `[MEASURED]` | [orjson](https://pypi.org/project/orjson/) |
| JSON-RPC 2.0 | **MUST** | MCP, A2A. `id` string/int, never null; result has `resultType`; **batching removed in 2025-06-18**: reject arrays | [base](https://modelcontextprotocol.io/specification/2026-07-28/basic/index), [2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/changelog) |
| SSE + chunked/NDJSON | **MUST** | LLM and MCP POST streams. `data:` lines, blank-line end, `:` comments = keep-alive, OpenAI `data: [DONE]`; send `X-Accel-Buffering: no`. Ollama native streams NDJSON, default `stream:true` | [streamable-http](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [WHATWG](https://html.spec.whatwg.org/multipage/server-sent-events.html), [api.md](https://github.com/ollama/ollama/blob/v0.35.1/docs/api.md) |
| MCP stdio + Streamable HTTP | **MUST** | stdio: most local servers; NDJSON, no embedded newlines, stdout MCP-only, stdin EOF = shutdown, no OAuth (env creds). Streamable HTTP: the only non-deprecated HTTP transport, two eras (Q3) | [stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio), [HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) |
| MCP HTTP+SSE | **NO** | Deprecated since 2025-03-26, re-classified by SEP-2596 (>=12-month window). Bridge with `mcp-proxy` 0.12.0 MIT if needed | [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog) |
| OAuth 2.0/2.1 | **SHOULD** | MCP HTTP auth = OAuth 2.1 resource server. Spec cites `draft-ietf-oauth-v2-1-13`; draft is now `-16`, not an RFC. MVP: discovery + token validation, no AS | [auth](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) |
| JWT | **SHOULD** | PyJWT 2.15.1 MIT (avoid `jwcrypto` 1.6.1, LGPL-3.0+); `alg` allowlist | [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725), [PyJWT](https://pypi.org/project/PyJWT/) |
| API keys | **MUST** | MVP agent authN: `Authorization: Bearer aicl_<id>_<secret>`, store sha256; never in query string (MCP forbids) | [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) |
| OIDC, mTLS, SPIFFE/SPIRE | **LATER / NO** | OIDC = dashboard login + AS discovery fallback (clients MUST try it). mTLS cert-bound tokens RFC 8705. SPIRE v1.15.3 (2026-08-21, Apache-2.0) = daemons; JWT-SVID is just a JWT. Mention only | [AS discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery), [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705), [SPIRE](https://github.com/spiffe/spire) |
| OTLP | **SHOULD** | Spec 1.11.0 **Stable** (traces, metrics, logs; profiles Development). Dashboard must not need a collector | [OTLP](https://opentelemetry.io/docs/specs/otlp/) |
| OTel GenAI + MCP semconv | **SHOULD** (names only) | **Status: Development**; moved to `open-telemetry/semantic-conventions-genai` (Apache-2.0, no release). Reuse names in our audit schema: `gen_ai.request.model`, `gen_ai.usage.input_tokens/output_tokens`, `gen_ai.tool.name`, `mcp.method.name`, `mcp.protocol.version`; MCP carries `_meta.traceparent` | [MCP semconv](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md), [spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md) |
| A2A | **LATER** | Below | [A2A](https://a2a-protocol.org/latest/specification/) |

**A2A.** Spec "Latest Released Version 1.0.0"; GitHub v1.0.0 2026-03-12, v1.0.1 2026-05-28 ([releases](https://github.com/a2aproject/A2A/releases)). Linux Foundation, Apache-2.0. Agent Card at `/.well-known/agent-card.json`; `supportedInterfaces[]` `protocolBinding` `JSONRPC|GRPC|HTTP+JSON`; `securitySchemes`: apiKey / http / oauth2 / openIdConnect / mutualTLS; cards may carry JWS signatures over RFC 8785 JSON; `A2A-Version: 1.0` header. JSON-RPC methods: `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks` ([what's new](https://github.com/a2aproject/A2A/blob/main/docs/whats-new-v1.md)). `a2a-sdk` 1.2.1 Apache-2.0. NOT RECOMMENDED FOR MVP: A2A gateway -> do: scan `SendMessage` text in the same pipeline; pin the Agent Card hash like a tool definition.

## 2. LLM wire formats

### 2.1 Surface matrix (Ollama 0.35.1, 2026-09-29, MIT)

| Surface | Ollama support | MVP |
|---|---|---|
| OpenAI `/v1/chat/completions` | `model messages stream stream_options.include_usage tools response_format seed stop temperature top_p max_tokens *_penalty reasoning_effort`. **Not supported: `tool_choice n logit_bias user`, logprobs, image URLs** | **MUST** |
| `/v1/models`, `/v1/embeddings` | yes (embeddings: string or string[]) | MUST / SHOULD |
| `/v1/responses` | since v0.13.3, **stateless only** (no `previous_response_id`, `conversation`) | LATER |
| Anthropic `/v1/messages` | streaming, tools, tool_result, thinking; no `tool_choice`, `metadata` | LATER |
| Native `/api/chat`, `/api/generate` | NDJSON; tool `arguments` is an **object**; final object has counts + ns durations | **SHOULD** |
| `/api/pull create delete push copy` | yes | **deny by default** (model supply chain, report 04) |

Sources: [OpenAI compat](https://github.com/ollama/ollama/blob/v0.35.1/docs/api/openai-compatibility.mdx), [Anthropic compat](https://github.com/ollama/ollama/blob/v0.35.1/docs/api/anthropic-compatibility.mdx), [`openai/openai.go`](https://github.com/ollama/ollama/blob/v0.35.1/openai/openai.go) (`ChatCompletionRequest` has no `ToolChoice` field: silently dropped), [`middleware/openai.go`](https://github.com/ollama/ollama/blob/v0.35.1/middleware/openai.go). `[REC]` never rely on `tool_choice:"none"`: strip `tools` to forbid tools and check the response's tool names against the allowlist.

### 2.2 OpenAI Chat Completions: request, streamed tool call, usage
```json
{"model":"llama3.2","stream":true,"stream_options":{"include_usage":true},
 "messages":[{"role":"user","content":"What is the weather in Tokyo?"}],
 "tools":[{"type":"function","function":{"name":"get_weather","description":"Get weather",
   "parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}]}
```
Result goes back as `{"role":"tool","tool_call_id":"call_ab12","content":"18C"}`. `function.arguments` is a JSON **string** that may be invalid ([types](https://github.com/openai/openai-python/blob/main/src/openai/types/chat/chat_completion_chunk.py)): `json.loads` defensively; failure = block reason.

OpenAI streams fragments: `id/type/name` only on the first fragment per `index`, `arguments` concatenated (`"{\"ci"`, `"ty\":..."`), indexes can interleave, then `delta:{}` + `finish_reason:"tool_calls"`, usage chunk, `[DONE]`.

**Ollama's stream** `[code-derived]`: the whole call arrives in ONE chunk (complete `arguments`); a dedicated finish chunk with empty `delta` (`stop` rewritten to `tool_calls`); only with `include_usage` a final chunk with `"choices":[]`, `usage` and Ollama-only `timings`; then `[DONE]` ([L127-165](https://github.com/ollama/ollama/blob/v0.35.1/middleware/openai.go)):
```
data: {"id":"chatcmpl-9","object":"chat.completion.chunk","model":"llama3.2","system_fingerprint":"fp_ollama","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"id":"call_x1","index":0,"type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Tokyo\"}"}}]},"finish_reason":null}]}
data: {"id":"chatcmpl-9","object":"chat.completion.chunk","model":"llama3.2","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}
data: {"id":"chatcmpl-9","object":"chat.completion.chunk","model":"llama3.2","choices":[],"usage":{"prompt_tokens":169,"completion_tokens":15,"total_tokens":184},"timings":{"prompt_n":169,"predicted_n":15,"predicted_per_second":129.4}}
data: [DONE]
```
Stream rules `[REC]` (one `StreamGuard`, ~120 lines): (1) buffer tool-call deltas per `index` until `finish_reason`, check the assembled call, then release or replace with a refusal text chunk + `finish_reason:"stop"` (no extra latency on Ollama); (2) forward text through a 64-char sliding window so regexes spanning chunks match; (3) force `stream_options.include_usage=true` upstream (Ollama omits usage otherwise), drop the chunk if the client did not ask; aborted streams may lack usage ([types](https://github.com/openai/openai-python/blob/main/src/openai/types/chat/chat_completion_chunk.py)), so charge tokens seen and mark the ledger row `estimated`; (4) pass through or strip `system_fingerprint`, `timings`, `reasoning`, `keep_alive`.

### 2.3 Ollama native `/api/chat` (NDJSON)
Tool result message uses `tool_name`, not `tool_call_id` ([api.md](https://github.com/ollama/ollama/blob/v0.35.1/docs/api.md)). Stream: `{"message":{"tool_calls":[{"function":{"name":"get_weather","arguments":{"city":"Tokyo"}}}]},"done":false}` then `{"done_reason":"stop","done":true,"total_duration":182242375,"load_duration":41295167,"prompt_eval_count":169,"eval_count":15,"eval_duration":115959084}`.
Tokens = `prompt_eval_count + eval_count`; **compute seconds = `total_duration` (ns)**; `load_duration` isolates cold load: a free source for the compute budget `[REC]`.

### 2.4 Responses, Anthropic (LATER, ~3 h each) and exposure `[REC]`
Responses: `function_call{call_id,name,arguments}` items, `response.function_call_arguments.delta|done` ([types](https://github.com/openai/openai-python/blob/main/src/openai/types/responses/response_function_tool_call.py)). Anthropic: `tool_use` / `tool_result` blocks, `input_json_delta.partial_json`, **cumulative** `message_delta` usage ([docs](https://platform.claude.com/docs/en/build-with-claude/streaming)).
`/v1/chat/completions`, `/v1/models`, `/v1/embeddings`, `/api/chat`, `/api/generate`, normalized to one request record `{surface, model, messages, tools, stream, principal}` and one response record `{text, tool_calls, finish, usage, durations}`. NOT RECOMMENDED: cross-surface translation -> pass each surface to the same-surface Ollama endpoint.

## 3. MCP deep dive (2026-07-28; 2025-11-25 = legacy era)

Revisions: **2025-03-26** Streamable HTTP + batching; **2025-06-18** batching removed, `structuredContent`/`outputSchema`, elicitation, RFC 8707 MUST, RFC 9728, `MCP-Protocol-Version` ([changelog](https://modelcontextprotocol.io/specification/2025-06-18/changelog)); **2025-11-25** OIDC discovery, CIMD, URL elicitation, experimental Tasks ([changelog](https://modelcontextprotocol.io/specification/2025-11-25/changelog)); **2026-07-28** stateless: no `initialize`, `Mcp-Session-Id`, GET stream, resumability, `ping`; per-request `_meta` (version, capabilities); `server/discover`; `subscriptions/listen`; **MRTR** replaces server-initiated requests; `resultType` on every result; Tasks -> extension `io.modelcontextprotocol/tasks`; headers `Mcp-Method`, `Mcp-Name`, optional `Mcp-Param-*`; `ttlMs`+`cacheScope` on lists; codes `-32020..-32022`; Roots, Sampling, Logging **deprecated**; DCR deprecated for CIMD.

SDK: Python `mcp` **2.0.0 released 2026-07-28**, **2.3.0 on 2026-10-02 (MIT)**; v1.30.0 (2026-09-07) still maintained. `Client(mode="auto")` probes `server/discover`, falls back to `initialize`; `MCPServer` serves both eras on one endpoint by `MCP-Protocol-Version` ([releases](https://github.com/modelcontextprotocol/python-sdk/releases), [legacy clients](https://py.sdk.modelcontextprotocol.io/run/legacy-clients/)). Microsoft `mcp-gateway` requires 2026-07-28 only ([README](https://github.com/microsoft/mcp-gateway)); we cannot drop legacy (filesystem/git reference servers) `[INFERENCE]`.

**Era detection** `[REC]`: modern iff `MCP-Protocol-Version >= 2026-07-28` AND `_meta` protocolVersion; legacy if `initialize` or older/absent header. Spec: intermediaries enforcing policy on mirrored headers SHOULD reject old/absent versions rather than trust headers ([Server Validation](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)). So decide on the **JSON body**; use `Mcp-Method`/`Mcp-Name` only for routing and cross-check (`400` + `-32020`).

**Legacy lifecycle** ([2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)): `initialize` -> response -> `notifications/initialized`.
```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",
 "capabilities":{"roots":{"listChanged":true},"sampling":{},"elicitation":{"form":{},"url":{}}},
 "clientInfo":{"name":"ExampleClient","version":"1.0.0"}}}
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"ExampleServer","version":"1.0.0"}}}
```
HTTP: `MCP-Session-Id` on the initialize response, echoed by the client, `404` = re-initialize, `DELETE` ends it, GET = server->client SSE stream ([transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)).

**Modern**: optional `server/discover` ([spec](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)): request `params._meta` = `{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`; result `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"instructions":"...","ttlMs":3600000,"cacheScope":"public"}`. Every POST carries `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (`tools/call`, `resources/read`, `prompts/get`; non-ASCII as `=?base64?...?=`), `Accept: application/json, text/event-stream` and the `_meta` triple; missing `_meta` -> `400`+`-32602`; bad version -> `400`+`-32022` with `data.supported`; `Origin` MUST be validated (403). `serverInfo` is self-reported; `instructions` is text for the LLM = injection surface.

### 3.1 Other features (2026-07-28) and gateway meaning
- **Errors**: `-32700, -32600..-32603`; `-32000..-32019` legacy; `-32020 HeaderMismatch`, `-32021 MissingRequiredClientCapability`, `-32022 UnsupportedProtocolVersion`; app codes SHOULD be outside `-32768..-32000`; not-found now `-32602` ([base](https://modelcontextprotocol.io/specification/2026-07-28/basic/index)).
- **Resources/prompts** (`resources/list|templates/list|read`, `prompts/list|get`): scan like tool output. **Sampling, Roots, Logging**: deprecated; via MRTR `inputRequests` (legacy: server->client requests on SSE) ([MRTR](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr), [sampling](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling), [elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)).
- **Progress/cancel**: `_meta.progressToken`; HTTP: closing the SSE stream = cancel; stdio: `notifications/cancelled`. **Tasks** extension `io.modelcontextprotocol/tasks` (`tasks/get|update|cancel`, `resultType:"task"`, [ext](https://modelcontextprotocol.io/extensions/tasks/overview)): LATER, bind task id to principal.

### 3.2 Tools: discovery, descriptions, annotations, calls
`tools/list` is paginated (`cursor`/`nextCursor`; follow ALL pages before pinning); results carry `ttlMs`, `cacheScope`; lists MUST NOT vary per connection but MAY vary "by the authorization presented" ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)):
```json
{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[{
 "name":"get_weather","title":"Weather Information Provider","description":"Get current weather information for a location",
 "inputSchema":{"type":"object","properties":{"location":{"type":"string","description":"City name or zip code"}},"required":["location"]},
 "outputSchema":{"type":"object","properties":{"temperature":{"type":"number"}},"required":["temperature"]},
 "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}],
 "nextCursor":null,"ttlMs":300000,"cacheScope":"public"}}
```
Names SHOULD be 1-128 chars `A-Za-z0-9_.-`, unique per server; aggregators SHOULD prefix and MUST NOT rely on `serverInfo.name`. `inputSchema` is JSON Schema 2020-12; network `$ref` MUST NOT be auto-dereferenced.

**Annotations**: `readOnlyHint` (default false), `destructiveHint` (default **true**), `idempotentHint` (false), `openWorldHint` (**true**). Spec: "clients MUST consider tool annotations to be untrusted unless they come from trusted servers"; schema text: clients "should never make tool use decisions" on them from untrusted servers ([schema](https://modelcontextprotocol.io/specification/2026-07-28/schema)). `[REC]` risk class comes from OUR policy per `(server, tool)`; annotations may only *raise* caution. `x-mcp-header` mirrors schema-chosen params into `Mcp-Param-*` headers visible to intermediaries: check header == body, never log unredacted.

**`tools/call`** (headers `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method: tools/call`, `Mcp-Name: search_issues`):
```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues","arguments":{"repo":"acme/api","q":"timeout"},
 "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"{\"count\":2}"}],"structuredContent":{"count":2},"isError":false}}
```
Content blocks: `text|image|audio|resource_link|resource`; `structuredContent` is any JSON conforming to `outputSchema`. Two error channels: JSON-RPC errors (unknown tool, malformed) vs `isError:true` (execution, validation, business); clients SHOULD pass the latter to the model (SEP-1303).

**MRTR**: `result:{"resultType":"input_required","inputRequests":{"gh":{"method":"elicitation/create",...}},"requestState":"eyJ..."}`; client retries with a NEW id plus `inputResponses`, `requestState`. Gateway: store `(principal, method, args_hash)` at leg 1, refuse a retry with changed arguments `[INFERENCE]`.

**Caching rewrite** `[REC]`: the gateway filters per principal, so set `cacheScope:"private"` and clamp `ttlMs<=5000` (hot-reload visible, no cross-caller cache) `[INFERENCE]` from the `CacheableResult` changelog text.

## 4. MCP authorization

- **Where**: HTTP transports only; stdio SHOULD NOT use it (env creds); optional in spec ([auth](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)). Gateway injects per-server env/bearer credentials from its own store.
- **Roles**: server = OAuth 2.1 resource server; client = OAuth 2.1 client; AS out of scope.
- **Chain**: (1) no token -> `401` `WWW-Authenticate: Bearer resource_metadata="https://gw.local/.well-known/oauth-protected-resource/mcp/github", scope="tools:read"`; (2) PRM (RFC 9728), path-inserted or root, MUST list `authorization_servers`: `{"resource":"https://gw.local/mcp/github","authorization_servers":["https://auth.local"],"scopes_supported":["tools:read"]}`; (3) AS metadata tried in order `oauth-authorization-server/<path>`, `openid-configuration/<path>`, `<issuer>/<path>/.well-known/openid-configuration`; client MUST see `code_challenge_methods_supported` (PKCE S256); (4) **registration priority**: pre-registered, then **Client ID Metadata Documents** (HTTPS URL as `client_id`), then DCR RFC 7591 (**deprecated**), then manual ([registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)); CIMD draft is `-02` (2026-07-06, OAuth WG) while MCP cites `-00` ([datatracker](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)); (5) PKCE + `resource=<canonical URI>` (RFC 8707) in authorization AND token requests, always; client validates RFC 9207 `iss`; (6) `Authorization: Bearer` on every request; server MUST validate audience; `401` invalid, `403` insufficient scope.
- **Step-up**: `403` + `WWW-Authenticate: Bearer error="insufficient_scope", scope="files:write", resource_metadata="..."`; client retries with the union of scopes a few times. `[REC]` map scopes to risk classes (`tools:read|write|exec`); out-of-scope call returns the challenge: a visible demo moment.
- **No passthrough**: servers "MUST NOT accept or transit any other tokens"; upstream calls use a separate upstream-issued token ([security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations), [best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)).
- **Confused deputy** needs static client ID at a third-party AS + dynamic registration + consent cookie + no per-client consent; MUSTs: per-client consent registry, consent page with client/scopes/`redirect_uri`, CSRF, `__Host-` cookies, exact `redirect_uri`, single-use `state` set after consent.
- **Gateway fit** `[REC]`: RS toward agents (token `aud` = `https://gw.local/mcp/<server>`), client toward upstream with (1) gateway-held per-server credential (MVP), (2) RFC 8693 exchange (`subject_token`=agent token, `actor_token`=gateway, `audience`=upstream; nested `act`) where the upstream AS supports it ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)), (3) third-party OAuth via URL elicitation, tokens stored server-side.
- NOT RECOMMENDED FOR MVP: own OAuth AS (consent UI, PKCE store, CIMD fetcher with SSRF defences) -> do: API keys + one EdDSA JWT minted by CLI, still serve PRM + `WWW-Authenticate` (3 h). The Python SDK has the RS half: `MCPServer(token_verifier=..., auth=AuthSettings(..., validate_token_resource=True))` serves PRM ([SDK auth](https://py.sdk.modelcontextprotocol.io/run/authorization/)). Gateway as OAuth client: PRM/AS URLs come from a hostile upstream: HTTPS only, block private/link-local ranges, pin DNS, no blind redirects.

## 5. Interception options and building blocks

| Option | Catches | Misses | Cost | Verdict |
|---|---|---|---|---|
| (a) Streamable HTTP reverse proxy | any HTTP client, both eras | stdio | 6-8 h | **MUST first** |
| (b) stdio wrapper | local stdio servers | traffic only, not process containment | 2-3 h | **SHOULD** |
| (c) Aggregating `server__tool` | one endpoint | merged pagination, name rewrite, session mapping | 6-10 h | LATER; MVP = path `/mcp/<server>` |
| (d) client SDK wrapper | in-process agents only | bypassable | 2 h | NO |

`[REC]` (a)+(b) share one `Policy.decide()` and one audit writer. The modern era is stateless: **no session table**; legacy only needs `Mcp-Session-Id` passed through and bound to the authenticated principal.

Building blocks (verified 2026-10-03): [`mcp`](https://github.com/modelcontextprotocol/python-sdk) MIT 2.3.0 (`Client(mode=)`, `MCPServer`, `ClientSessionGroup(component_name_hook=)`, `Server.middleware` **provisional**; deps `httpx2>=2.10.0`, pydantic>=2.12). [`fastmcp`](https://github.com/PrefectHQ/fastmcp) Apache-2.0 4.0.10 (2026-09-25; needs `mcp>=2,<3`; `create_proxy`, `mount(namespace=)` gives **`x_tool`**, single underscore; hooks `on_call_tool/on_list_tools`): best for option (c) ([proxy](https://gofastmcp.com/servers/providers/proxy.md)). [`mcp-proxy`](https://github.com/sparfenyuk/mcp-proxy) MIT 0.12.0: transport bridge only. [`snyk/agent-scan`](https://github.com/snyk/agent-scan) Apache-2.0 0.6.8: **sends tool names/descriptions to the Snyk API, needs `SNYK_TOKEN`**, so not local; its `proxy` shipped in 0.2.1 ([CHANGELOG](https://github.com/snyk/agent-scan/blob/main/CHANGELOG.md)); ideas only. [Docker MCP Gateway](https://github.com/docker/mcp-gateway) MIT v0.44.1: **interceptors** `--interceptor=before|after:exec|docker|http:<target>` receive tool-call JSON and may replace the response ([README](https://github.com/docker/mcp-gateway/blob/main/examples/interceptors/README.md)). [IBM ContextForge](https://github.com/IBM/mcp-context-forge) Apache-2.0 v1.0.11 (heavy), [Microsoft mcp-gateway](https://github.com/microsoft/mcp-gateway) MIT (Kubernetes, 2026-07-28 only), [agentgateway](https://github.com/agentgateway/agentgateway) Apache-2.0 v1.6.0 (Rust, LF; MCP federation, CEL RBAC, guardrails): production paths, not MVP. `jcs` 0.2.1 is stale and only needed for exact RFC 8785; pins use stdlib canonical JSON: 0.34 ms/100 tools (59 KB) vs 1.22 ms `jcs` `[MEASURED]`.

**Sketch A: HTTP proxy.** `[MEASURED]` `mcp` 2.3.0, Python 3.14.8: `mcp.Client` in `auto` (negotiated 2026-07-28) and `legacy` (2025-11-25, session header passed through) both listed and called `add` through it; the poisoned tool was removed from the list; an `id_rsa` argument got the deny result. Loopback `tools/call`, 300 sequential POSTs: upstream p50 **0.80 ms** / p95 0.97; via proxy p50 **1.54 ms** / p95 1.80 (+0.74 ms, passthrough only).
```python
# pin = sha256(json.dumps({name,title,description,inputSchema,outputSchema,annotations}, sort_keys=True, separators=(",",":")))
def filter_list(server, result):          # drop poisoned/drifted tools, force private cache
    ok = [t for t in result.get("tools", []) if not INJ.search(json.dumps([t.get("title"), t.get("description"), t.get("inputSchema")]))
          and PINS.setdefault((server, t["name"]), pin(t)) == pin(t)]
    return {**result, "tools": ok, "cacheScope": "private", "ttlMs": 5000}
async def handle(req):                    # Route("/mcp/{server}", methods GET/POST/DELETE)
    server = req.path_params["server"]; body = await req.body(); method = None
    hdr = {k: v for k, v in req.headers.items() if k.lower() not in HOP}
    if req.method == "POST":
        msg = json.loads(body)
        if not isinstance(msg, dict): return JSONResponse(err(-32600, "batch not allowed"), 400)
        method = msg.get("method")
        if req.headers.get("mcp-method", method) != method: return JSONResponse(err(-32020, "HeaderMismatch"), 400)
        if method == "tools/call":
            v = POLICY.on_call(server, msg["params"]["name"], msg["params"].get("arguments") or {}, req.state.principal)
            if v.action != "allow": return JSONResponse(deny(msg["id"], v.model_text))   # isError result, Q7d
    r = await client.send(client.build_request(req.method, UPSTREAM[server], content=body, headers=hdr), stream=True)
    if method in ("tools/list", "tools/call") and r.status_code == 200:
        return Response(rewrite(server, method, await r.aread(), r.headers), r.status_code)   # JSON or SSE `data:` lines
    return StreamingResponse(r.aiter_raw(), r.status_code)                                    # long streams relayed raw
```
**Sketch B: stdio wrapper** `[MEASURED]` (both eras through `mcp.Client(StdioServerParameters(...))`, deny received), ~40 lines of asyncio: `proc = await asyncio.create_subprocess_exec(*argv, stdin=PIPE, stdout=PIPE)`; per client line `m = json.loads(line)`: `tools/list` -> `pending[m["id"]]="list"`; `tools/call` -> if `POLICY.on_call(...)` is not allow, write `deny(m["id"], text)` to OUR stdout and `continue`, else `proc.stdin.write(line)`; on our stdin EOF `proc.stdin.close()`; per server line: if `pending.pop(id)=="list"` then `m["result"] = filter_list("fs", m["result"])`; keep stdout MCP-only. It cannot stop the child touching files or network; containment (container, no network, read-only mounts) is the spec's advice ([Local MCP Server Compromise](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)).

## 6. MCP-layer attacks and gateway control (D = deterministic, S = semantic)

| # | Attack | Mechanism | Control | Where |
|---|---|---|---|---|
| 1 | Tool poisoning | Hidden `<IMPORTANT>` in descriptions makes the model read `~/.ssh/id_rsa` ([Invariant](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), OWASP [MCP03](https://owasp.org/www-project-mcp-top-10/)) | D: scan EVERY string in the definition (title, description, schema property names/descriptions/enum/default, `annotations.title`), server `instructions`, prompts: instruction verbs, "do not tell", secret paths, zero-width/tag Unicode, base64. S: classifier. Drop tool from list | list |
| 2 | Rug pull | Definition changes after approval (Invariant: pin by hash) | D: sha256 per `(server,tool)`; drift = quarantine + alert; re-list on `list_changed` and on `ttlMs` expiry | list |
| 3 | Shadowing, name collisions | Server B text rewrites use of server A's tool ([Invariant](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)); two `search` tools, spec says prefix ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)) | D: flag tools naming another server's tool; per-agent server visibility; path routing (aggregation rejects names containing `__`) | list |
| 5 | Malicious output | Indirect injection / exfil markup in results | D: scan `content[].text`, embedded resources, `structuredContent` leaves, `isError` text; strip invisible Unicode; size cap; block image/link exfil. S: injection classifier | result |
| 6 | Sampling abuse | Resource theft, conversation hijack, covert tool invocation ([Unit 42](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)); deprecated ([spec](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling)) | D: `mcp.sampling: deny`; drop legacy `sampling/createMessage` on SSE; reject MRTR entries; if allowed cap `maxTokens`, strip `includeContext` `thisServer/allServers`, charge ledger | SSE/result |
| 7 | Elicitation phishing | Form asks secrets; URL mode to lookalike ([spec](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)) | D: credential vocabulary in `message`/schema names; URL host allowlist, https; default deny for autonomous agents | SSE/result |
| 8 | Passthrough / confused deputy | Client token forwarded upstream; static-ID OAuth proxy | D: check `aud`; strip `Authorization`; inject gateway credential; test: fake upstream never sees agent token (prior 05 I8) | transport |
| 9 | Session / handle hijack | Stolen `Mcp-Session-Id` or task/basket handle ([best practices](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)) | D: bind session id to principal (`403` on mismatch); a handle is a name, not auth | transport |
| 10 | DNS rebinding; over-broad scopes | Browser JS hits 127.0.0.1 ([spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http): MUST validate `Origin`); wildcard tokens (MCP02) | D: bind 127.0.0.1; bad `Origin` -> 403; `Host` allowlist; Bearer even on loopback; scope -> risk class, `403 insufficient_scope`, reject `*` | transport |
| 12 | CVE-2025-6514 mcp-remote | OS command injection via hostile `authorization_endpoint`; CVSS 9.6, `>=0.0.5 <0.1.16` ([GHSA](https://github.com/advisories/GHSA-6xpm-ggf7-wc3p), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-6514)) | D: signature (report 04): non-https/shell-metachar endpoints; version gate | config |
| 13 | CVE-2025-49596 Inspector | Unauthenticated proxy RCE, 9.4, `<0.14.1` ([GHSA](https://github.com/advisories/GHSA-7f8r-222p-6f5g), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-49596)) | D: version gate; Origin/Host; loopback only | config |
| 14 | Reference-server CVEs | Filesystem 53109/53110 path-prefix + symlink, `<=0.6.2` ([GHSA](https://github.com/advisories/GHSA-q66q-fx2p-7w4m), [GHSA](https://github.com/advisories/GHSA-hc55-p739-j48w)); git 68143 `git_init`, 68144 arg injection (`--output=`), 68145 repo-scope bypass, NVD 6.5/6.3/6.4 ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68144), [Register](https://www.theregister.com/2026/01/20/anthropic_prompt_injection_flaws/)) | D: path args `realpath` under roots with `root+os.sep` test; deny args starting `-` for git-like tools; deny `git_init`; version gates | call |
| 15 | postmark-mcp | npm 1.0.16 (2025-09-17) added hidden BCC after 15 clean versions; no CVE ([THN](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html), [Qualys](https://threatprotect.qualys.com/2025/09/30/malicious-mcp-server-on-npm-postmark-mcp-exploited-in-attack/)) | D: pin package version + integrity; egress allowlist; email `to/cc/bcc` domain allowlist | config/call |
| 16 | Header/body desync; SSRF via `$ref`/OAuth URLs | LB routes on `Mcp-Name`, server runs body; network `$ref` | D: body is truth, mismatch `400`+`-32020`; no remote refs; block private ranges on every gateway fetch | transport/list |
| 17 | Shadow servers, audit gaps | OWASP MCP08/MCP09 | D: only registered servers routable; audit every call `principal, server, tool, args_hash, decision, rule, latency_ms` | all |

OWASP MCP Top 10 (v0.1 beta, licence NOASSERTION) mapping: MCP01 (#8), MCP02 (#10), MCP03 (#1-3), MCP04 (#15), MCP05 (#12-14), MCP06/MCP10 (#5), MCP07 (#8-10), MCP08/MCP09 (#17) ([project](https://owasp.org/www-project-mcp-top-10/)).

## 7. Example request flows

**7a. Agent -> gateway -> Ollama, tool call in response.** `POST /v1/chat/completions` (Bearer) -> principal `agent:support-bot` -> model allowed, input scan, tools allowlist -> reserve budget -> forward to `127.0.0.1:11434` with `include_usage` forced -> StreamGuard buffers the tool call, checks name + args -> release or refuse -> ledger += usage, audit. Blocked variant (tool not in allowlist): tool chunks are never forwarded; the client gets one text delta `[blocked by policy TOOL-ALLOW-01: tool not permitted]`, a `finish_reason:"stop"` chunk and `[DONE]`; audit `{"req_id":"r_81","principal":"agent:support-bot","decision":"block","rule":"TOOL-ALLOW-01","tool":"delete_file","tokens_in":169}`.

**7b. `tools/list` with scanning and pinning.** Upstream returns `add` (clean) and `read_note` (poisoned).
Output: the 3.2 shape with only `add`, plus `"ttlMs":5000,"cacheScope":"private","_meta":{"dev.aicl/policy":{"removed":[{"tool":"read_note","rule":"MCP-POISON-01"}]}}`. Pin row `{"server":"notes","tool":"add","sha256":"3e8f..b1","status":"approved"}`; if upstream edits `add`'s description the hash differs: `status:"quarantined"`, tool vanishes, audit `pin_drift`, admin re-approves on the dashboard. `[MEASURED]` poisoned-tool removal in both eras (Sketch A/B).

**7c. `tools/call` allowed.** Policy `github.search_issues: {risk: read, args: {repo: {pattern: '^acme/[a-z0-9-]+$'}, limit: {max: 50}}}`; the request from 3.2 passes: forward with the gateway-held token, scan result, audit `allow` with `args_hash` = sha256 of canonical `{name, arguments}`.

**7d. Blocked: JSON-RPC error vs `isError`.** `repo:"evil/exfil"` fails the pattern.
Option 1, result (recommended for denials):
```json
{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","isError":true,
 "content":[{"type":"text","text":"Blocked by policy ARG-REPO-01: repo must match acme/<name>. Choose an allowed repository."}]}}
```
(If the tool has an `outputSchema`, omit `structuredContent`: it MUST conform `[INFERENCE]`.) Option 2, for transport failures: `HTTP 403` + `WWW-Authenticate: Bearer error="insufficient_scope", scope="tools:exec", ...` and `{"jsonrpc":"2.0","id":2,"error":{"code":40301,"message":"policy_denied","data":{"rule":"SCOPE-EXEC-01"}}}`; `40301` is outside `-32768..-32000` as the spec asks, never `-32020..-32099` (reserved) or `-32000..-32019` (legacy). Hidden/unknown tool: `-32602`.
**Which works better** `[REC]`: `isError` for every denial the model can act on (arg limits, approval, budget, rate limit); JSON-RPC/HTTP errors only for transport failures. Reasons: the spec says clients SHOULD feed `isError` to the model and protocol errors are "less likely" recoverable ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)); Python SDK docs: "A raised MCPError goes to the client application, not to the model. If the model should read the message, return a tool result with is_error=True" ([middleware](https://py.sdk.modelcontextprotocol.io/advanced/middleware/)). Cost: the text enters model context, so use a fixed template (rule id + generic hint), never echo attacker text or thresholds (policy-probing oracle); repeated denials feed the loop detector.

**7e. REQUIRE_APPROVAL.** (1) Agent `tools/call merge_pr` (id 5). (2) Policy `approval:true`: gateway creates `apr_7Hq {principal, tool, args_hash, status:"pending", ttl:300}` and returns
```json
{"jsonrpc":"2.0","id":5,"result":{"resultType":"complete","isError":true,
 "content":[{"type":"text","text":"Approval required (id apr_7Hq). A human must approve this exact call within 5 minutes; then repeat the same call."}],
 "structuredContent":{"status":"approval_required","approval_id":"apr_7Hq","expires_in_s":300}}}
```
(3) Human approves on the dashboard (admin auth, not via MCP). (4) Agent retries identically with a NEW id. (5) Gateway matches an unexpired, unconsumed `(principal, tool, args_hash)`, marks it consumed, forwards, audits `allow_after_approval`; changed args or replay -> new approval. Alternatives: (i) block-and-wait with `notifications/progress` keep-alives on the request's own stream (`approval.mode: wait`, 120 s max; a broken stream loses the request); (ii) MRTR elicitation: the "user" is the agent harness, which can auto-accept, so it is NOT a human-in-the-loop control `[INFERENCE]`; (iii) Tasks `input_required`: LATER. Spec: SHOULD keep a human able to deny ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).

## 8. Identity protocol facts

- **Client credentials**: `grant_type=client_credentials`; MCP: such clients MAY abort or step up ([SDK ext](https://py.sdk.modelcontextprotocol.io/api/mcp/client/auth/extensions/client_credentials/)). **OIDC**: human dashboard login.
- **Token exchange** ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)): `subject_token`, `actor_token`, `audience`; **impersonation** vs **delegation**; `act` nests for chains; `may_act` declares permitted actors.
- **JWT BCP** ([RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)): `alg` allowlist, check `iss aud exp`, explicit `typ`; [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) access-token profile; [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) OAuth security BCP.
- **DPoP** ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)): per-request proof JWT, token `cnf.jkt`; **mTLS-bound** ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705)): `cnf.x5t#S256`; **SPIFFE** [X509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md), [JWT-SVID](https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md) (`sub`=SPIFFE ID, `aud`).
- **A2A auth**: apiKey, http, oauth2 (Device Code, `pkce_required`), openIdConnect, mutualTLS; signed Agent Cards ([A2A](https://a2a-protocol.org/latest/specification/)).

IETF / OpenID work on agent identity (datatracker, 2026-10-03; all Internet-Drafts, **none an RFC**):
- [`draft-ietf-wimse-aims-00`](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/) "AI Identity Management System", WIMSE WG, Active (2026-09-15); successor of individual `draft-klrc-aiagent-auth-03` (Defakto, AWS, Zscaler, Ping, OpenAI, Okta): agent authN/authZ from WIMSE + OAuth, "rather than defining new protocols".
- OAuth WG: [`transaction-tokens-11`](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) (identity + authz context across a call chain), [`identity-chaining-17`](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/) (across trust domains via RFC 8693). Individual: [`oauth-ai-agents-on-behalf-of-user-02`](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/) **Expired**, [`mcguinness-oauth-ai-agent-instance-00`](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-ai-agent-instance/), [`ni-wimse-ai-agent-identity-03`](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/).
- OpenID Foundation whitepaper "Identity Management for Agentic AI" (Oct 2025, [arXiv:2510.25819](https://arxiv.org/abs/2510.25819)): OAuth + token-exchange delegation; not a standard; read via [summary](https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/) only.

`[REC]` MVP identity = principal id + API key/local JWT; `sub` = agent id, optional `act.sub` = human; reserve `sub act aud scope client_id jti` so an RFC 8693 upgrade is non-breaking.

## Inconsistent

- OAuth 2.1: MCP cites [`-13`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13); datatracker has [`-16`](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) (2026-09-03). CIMD: MCP cites `-00`; datatracker rev 02.
- MCP repo licence: GitHub API `NOASSERTION`; [LICENSE](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/LICENSE) says MIT -> Apache-2.0 transition, mixed.
- A2A: spec site "1.0.0" vs GitHub `v1.0.1` (patch, no compatibility change).
- Git MCP CVEs: press says RCE chain; [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-68143) 6.5/6.3/6.4. CVE-2025-49596: GHSA score null vs NVD 9.4. uvicorn [docs](https://github.com/Kludex/uvicorn/blob/master/docs/index.md) "supports HTTP/2" vs [0.53.0 notes](https://github.com/Kludex/uvicorn/releases/tag/0.53.0) "experimental". agent-scan CHANGELOG `mcp-scan proxy` vs README `scan`/`inspect` only.

## Could not establish

- Whether Docker MCP Gateway interceptors run on `tools/list`; whether Docker gateway or ContextForge speak 2026-07-28.
- Whether `snyk/agent-scan` 0.6.8 still has a `proxy` subcommand; Cisco mcp-scanner version (taken from prior 02).
- Captured Ollama 0.35.1 stream bytes (shared Ollama off limits): examples are code-derived. OpenAI streaming doc page itself (field names from `openai-python` types).
- OIDC-A and OpenID Foundation deliverables beyond the Oct 2025 whitepaper.
- How LangGraph / OpenAI Agents SDK / Claude Code surface JSON-RPC errors vs `isError` to the model (argument rests on spec text + Python SDK docs).
- Keycloak/Authentik support for RFC 8693 `act` and CIMD; behaviour with very large `tools/call` results through buffer-and-rewrite (SDK default 1 MiB per SSE event).

## Recommendation for the MVP

`[REC]` about 26-34 h for this slice (engine, detectors, dashboard are other slices).

1. ASGI app: Starlette 1.7.0 + uvicorn 0.54.0 + httpx 0.28.1 (BSD-3), 127.0.0.1, `Origin`/`Host` allowlists (1 h).
2. MCP HTTP proxy (Sketch A): dual era by passthrough, body-truth, `Mcp-Method` cross-check, reject batches, legacy session bound to principal; `/mcp/<server>`, NO aggregation (6-8 h).
3. `tools/list`: all pages, scan all strings, stdlib sha256 pin, quarantine on drift, `cacheScope:"private"`, `ttlMs<=5000` (3-4 h).
4. `tools/call`: allowlist, arg policy (regex/enum/range/path-jail/option-injection), risk class from OUR policy, result scan; denials = `isError` template, hidden tool = `-32602` (4-5 h). Approval `retry` mode, dashboard approver (3-4 h).
5. stdio wrapper (2-3 h). AuthN: API keys + optional EdDSA JWT (PyJWT), PRM + `WWW-Authenticate`, scope step-up, no AS (3 h).
6. LLM surfaces `/v1/chat/completions|models|embeddings`, `/api/chat|generate`; StreamGuard; forced `include_usage`; ledger from `usage` + `total_duration`; deny `/api/pull|create|delete|push|copy` (8-10 h).
7. Audit JSONL + SQLite with `gen_ai.*`/`mcp.*` names, `/metrics` (2 h). pytest with `mcp.Client(mode="auto"|"legacy")` vs a fake upstream: poisoned tool, rug pull, `id_rsa` arg, passthrough probe, approval round-trip (3 h).

Cut first: `wait` approval mode, `/v1/responses` + `/v1/messages`, JWT path (keep API keys), OTLP, PRM polish, stdio wrapper. Never cut: dual-era passthrough, body-truth validation, list scan + pin, arg policy, `isError` denials, audit.

NOT RECOMMENDED FOR MVP -> do instead: aggregating `server__tool` -> per-server paths; own OAuth AS/CIMD -> API keys + PRM stub; A2A gateway -> log + pin card hash; mTLS/SPIRE -> mention; HTTP/2, WebSocket -> skip; HTTP+SSE -> reject; Snyk agent-scan -> cloud API, borrow ideas; Docker gateway / agentgateway / ContextForge as data plane -> too much config for 24-48 h, name as production path.

# 14 - Transparent interception: AICL in front of Claude Code, Codex and any API client

Status: scope proposal v4, 2026-10-04 ~01:00 (confirm at SYNC). Extends `13-architecture.md`; where they disagree on ingress, this file wins.
Markers: [SPIKE] measured today, [DOC] vendor documentation from memory (verify before relying on it), [INFERENCE] reasoning, not measured.

## 0. Decision in one paragraph

AICL stays one gateway with one `decide()`, but the main ingress becomes the network, not the client config: our DNS resolver answers the AI API hosts (`api.anthropic.com`, `api.openai.com`, ...) with the gateway IP, the gateway terminates TLS with a leaf certificate from the AICL CA, parses the request in the provider's own API contract (Anthropic Messages, OpenAI Responses, OpenAI Chat Completions), runs the controls with dynamic rules, forwards allowed traffic to the real provider with the client's own credentials and returns the (inspected) answer. Blocks and redactions are answered in the provider's native contract so Claude Code and Codex render them as normal messages or normal API errors. The end user configures nothing in the tool. Bypass is prevented by the egress firewall (network infrastructure, like DHCP: not built by us, but we ship the reference rules and detect bypass attempts in DNS).

## 1. Ingress modes and the bypass model

Three modes, one gateway, one `decide()`; they differ only in how traffic reaches us:

| Mode | Client side | Bypassable by the user? | Where it runs |
|---|---|---|---|
| A base URL | `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` points at the gateway | yes: unset the variable | anywhere, incl. Cloud Run (T-012) |
| B explicit proxy | `HTTPS_PROXY` + trust the AICL CA | yes: unset the proxy | LAN / laptop |
| C transparent (main) | nothing; DHCP hands out our DNS, the AICL CA is in the OS store (MDM / GPO) | only if the network allows direct egress, see below | LAN / laptop / compose demo |

Why mode A or B alone is not enough: a user can change the base URL or the proxy and we stop seeing the traffic. Mode C removes the per-tool switch, but DNS by itself is still bypassable. The enforcement is the network:

| Bypass attempt | DNS alone | DNS + egress firewall | What AICL shows |
|---|---|---|---|
| `ANTHROPIC_BASE_URL` / `HTTPS_PROXY` to another host | leaks | blocked (only the gateway may reach provider IPs on 443) | connection refused for the user; NET-01 alert if the name was resolved |
| Manual DNS 8.8.8.8, `hosts` file with the real IP | leaks | blocked (DNS out only to our resolver; 443 to provider ranges only from the gateway) | NET-01: lookup of the AI host but no gateway request |
| DoH / DoT in the browser or OS | leaks | blocked (853 dropped, known DoH hosts sinkholed by our DNS) | NET-01: lookup of a DoH resolver |
| VPN / hotspot / personal device | leaks | out of scope (endpoint and HR policy) | nothing; stated in Limits |
| Remove the AICL CA | TLS fails | TLS fails (fail closed, nothing leaks) | TLS handshake errors in gateway logs |
| IPv6 | leaks if AAAA resolves | our DNS returns no AAAA for intercepted hosts; firewall drops v6 egress to provider ranges | - |

Reference firewall rules (nftables, Windows Firewall) ship in the docs; the compose demo models the firewall with a Docker `internal` network whose only routes out are the DNS resolver and the gateway (CAPSULE already uses this pattern). Provider IP ranges: Anthropic publishes fixed API ranges [DOC, verify]; OpenAI sits on shared CDN IPs, so a default-deny workstation egress is the realistic rule [INFERENCE]. Commercial SSE products (Zscaler, Netskope) work the same way: forced egress + TLS inspection [research/draft-v2/08].

## 2. Data flow (mode C)

```
client (Claude Code / Codex / SDK)            no config in the tool
  1 DNS  api.anthropic.com ?        -> AICL DNS :53 -> A = gateway IP (no AAAA); other names forwarded upstream; every query audited
  2 TLS  ClientHello SNI=api.anthropic.com -> gateway :443, leaf cert (SAN = all intercepted hosts) signed by the AICL CA
  3 HTTP POST /v1/messages?beta=true (stream, 275 tools, thinking, context_management) [SPIKE]
        -> router: Host -> provider + protocol; path not inspected -> byte-for-byte proxy
        -> adapter: parts (system, text, tool_result, tool_use) -> Event(protocol, upstream_host, client_ip, credential_hash, user_agent)
        -> decide(): identity -> budget reserve -> deterministic -> semantic -> tool firewall -> destination matrix
        -> BLOCK: native error / native assistant text (section 3); REDACT: rewrite the spans in place
  4 forward to the real provider: resolved via interception.dns.upstream (never via our own DNS: no loop),
        client's own Authorization / x-api-key / OAuth bearer unchanged
  5 response: buffer the SSE stream, decide() on text + tool_use, re-emit the SSE events in the original order
        (or a native block in place of the blocked part), settle the budget from usage, audit
```

## 3. Native API contract (the rule that makes everything work natively)

Spike [SPIKE, 2026-10-04]: Claude Code 2.1.289, `claude -p` with `ANTHROPIC_BASE_URL` at a local mock, `CLAUDE_CODE_MAX_RETRIES=0`. What the user sees for each block shape:

| Reply shape | Claude Code shows | Exit | Requests | Verdict |
|---|---|---|---|---|
| 200, normal message (SSE), text `[AICL] Blocked ...`, `stop_reason: end_turn` | our text, as the assistant answer | 0 | 1 | **soft block / tool block / output redaction** |
| 400 `{"type":"error","error":{"type":"invalid_request_error","message":"[AICL] ..."}}` | `API Error: 400 [AICL] ...` | 1 | 1, no retry | **hard block of a request** |
| 402 `billing_error` | `API Error: 402 [AICL] ...` | 1 | 1, no retry | **budget exhausted** |
| 403 `permission_error` | `Failed to authenticate. API Error: 403 ...` | 1 | 1 | misleading; only for real auth failures |
| 200, `stop_reason: refusal` (with or without text) | `API Error: Sonnet 4.5 can't help with this ... anthropic.com/legal/aup`, our text hidden | 1 | 2 (it retried) | **never use** (blames Anthropic, hides the reason) |
| SSE `event: error` mid-stream | falls back to a non-streaming retry of the same request | 1 | 2 | **never use**; buffer and decide before the first byte |

Other spike facts: before the first message Claude Code sends `HEAD /api/hello` (connectivity probe; must be proxied, not 404); the request carries `?beta=true`, `stream: true`, `thinking`, `context_management`, `metadata` and 275 tool definitions, so the adapter must keep every unknown field and pass large bodies (`defaults.max_body_kb: 512` is too small for coding agents) [SPIKE].

Rules for every adapter:
- Hard block of a request: provider-native 400 with the provider error envelope, message starts with `[AICL]`, includes control id and decision id. Never 403 (auth), never 429 / 5xx / 529 (clients retry them automatically).
- Budget: Anthropic 402 `billing_error`; OpenAI: verify in the Codex spike (429 `insufficient_quota` is the native code but clients may retry 429).
- Soft block, blocked tool call, redacted output: HTTP 200 with a valid message in the requested mode (SSE when `stream: true`, JSON otherwise); a blocked `tool_use` / `function_call` is replaced by a text block `[AICL] tool call blocked: ...` and `stop_reason: end_turn`, so the agent does not execute it.
- Redaction of a request: rewrite text spans in place; never touch `thinking` / `redacted_thinking` blocks or their signatures, OpenAI `reasoning` items or `encrypted_content` (the provider rejects modified ones) [DOC, verify]; keep JSON key order and unknown fields.
- Paths not inspected (`/api/hello`, `/v1/messages/count_tokens`, `/v1/models`, OAuth, anything unknown): streamed byte-for-byte both ways, still audited (method, path, status, bytes).
- The `policy.yaml` key `defaults.block_response: refusal` (finish_reason `content_filter`) stays valid for OpenAI Chat Completions only; per-protocol shapes go into `interception.block_style` (section 4).

Codex: not measured yet (the `codex` on the spike machine is npm package 0.2.3, not verified to be OpenAI Codex CLI). With an API key it calls `/v1/responses` on `api.openai.com` with SSE; with a ChatGPT login it calls `chatgpt.com/backend-api/codex/...`, which sits behind Cloudflare [DOC, verify]. The Codex task starts with the same mock spike and records its table here.

## 4. Policy additions (structure owned by the lead)

```yaml
interception:
  mode: transparent            # off | base_url | transparent; base_url = mode A only
  credentials: passthrough     # passthrough = client's own key goes upstream; managed = gateway keys (current behaviour)
  providers:
    anthropic: {hosts: [api.anthropic.com], protocol: anthropic_messages, upstream: "https://api.anthropic.com", inspect: ["/v1/messages"]}
    openai:    {hosts: [api.openai.com], protocol: openai_responses, upstream: "https://api.openai.com", inspect: ["/v1/responses", "/v1/chat/completions"]}
  proxy_other_paths: true      # false = 404 for anything not inspected
  max_body_kb: 4096
  unknown_client: {action: ALLOW, principal: unknown-client, profile: strict}
  dns:
    listen: "0.0.0.0:53"
    gateway_ip: 10.77.0.2
    upstream: ["1.1.1.1", "9.9.9.9"]
    doh_sinkhole: [dns.google, cloudflare-dns.com, dns.quad9.net, mozilla.cloudflare-dns.com]
    log_queries: true
  tls: {ca_cert: data/ca/aicl-ca.pem, ca_key: data/ca/aicl-ca.key, leaf_days: 30}
  block_style:
    anthropic_messages: {hard: http_400, soft: assistant_text, budget: http_402}
    openai_responses:   {hard: http_400, soft: assistant_text, budget: http_429}   # verify in the Codex spike
    openai_chat:        {hard: http_400, soft: refusal, budget: http_429}
clients:                       # identity in passthrough mode: who is behind an IP / key
  - {match: {cidr: 10.77.0.0/24}, principal: demo-dev, team: platform, profile: balanced, models: ["claude-*", "gpt-[0-9]*"]}
  - {match: {key_sha256_prefix: "3f2a9c1b"}, principal: alice, team: data}
```

Landed in T-013 (`policy/policy.yaml` sections 9 and 10, `w2-core/aicl_core/interception.py`). Note `gpt-[0-9]*`, not `gpt-*`: Ollama cloud tags such as `gpt-oss:120b-cloud` must stay `unknown`. Budgets then apply per principal / team / org; prices for the real Claude and OpenAI models go into `destinations.models` from the providers' pricing pages at build time (not from memory).

## 5. DNS and CA

- DNS: `dnslib`, UDP + TCP on 53. Intercepted host -> A `gateway_ip`, empty AAAA. DoH resolvers in `doh_sinkhole` -> NXDOMAIN + NET-01 finding. Everything else forwarded to `upstream` unchanged. Reloads with the policy. Each query is one audit record (client IP, name, type, intercepted, answer).
- CA: `aicl ca init` (cryptography, P-256 root, 1 year, name constraints to the intercepted hosts where the client stack accepts them [research/draft-v2/00: worked with mitmproxy only with upstream_cert=false; verify for our own TLS]), `aicl ca leaf` (SAN = every intercepted host, regenerated on policy change), `aicl ca export` (PEM + install commands). No per-SNI minting needed: one leaf covers the list.
- Trust on clients: OS store (Windows `certutil -addstore Root`, macOS `security add-trusted-cert`, Linux `update-ca-certificates`) plus runtime-specific variables, because Node and Python often ignore the OS store: `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` [DOC, verify each for Claude Code native build and Codex in the spike].
- The gateway listens on :443 with the leaf (uvicorn `ssl_certfile`), HTTP/1.1 via ALPN; clients that offer h2 fall back [INFERENCE, verify].

## 6. Identity and credentials in passthrough

- The client's credential is never stored: identity uses `sha256(key)[:8]` + client IP + `User-Agent` (`claude-cli/2.x`, `codex_cli_rs/...`) mapped through `clients:`. Unknown client = `unknown_agent` policy (BLOCK or LOG, judges' choice).
- Secret scanning must not flag the client's own `Authorization` header (headers are not parts).
- Managed mode (current gateway keys + credential injection) stays for mode A and the existing demo agent.

## 7. What the controls look at in a coding agent

- Prompt parts: user text and pasted files (DLP-01 secrets, DLP-02 PII, destination matrix: Anthropic / OpenAI are `external`).
- `tool_result` blocks = untrusted channel (web pages, files, command output): INJ-03 signatures + INJ-04 judge run here; this is where indirect injection arrives.
- `tool_use` in the response: TOOL-01 rules per tool name: `Bash` / `shell` / `exec_command` command (`curl | sh`, `rm -rf /`, reads of `~/.aws`, `~/.ssh`, `.env`), `Write` / `Edit` / `apply_patch` paths outside the project, `WebFetch` URL to unknown hosts, historical rules (pickle, `trust_remote_code=True`, foreign model pull) on commands and written code.
- Response text: DLP on output, canary, markdown image exfil (backlog P1).
- Budgets from `usage` in the final SSE event (`message_delta.usage`, `response.completed.usage`).

## 8. Tests (offline, deterministic)

- Recorded fixtures: one real Claude Code 2.1.289 request body (from the spike mock log, synthetic prompt) and one Codex body; mock upstreams replay SSE.
- Contract tests per protocol: status, error envelope type, SSE event order parses with the official event grammar, block text starts with `[AICL]`, unknown fields and thinking blocks byte-identical after a redaction.
- Case files gain `protocol:`; the meta-test requires allowed + blocked per control per protocol.
- DNS tests: intercepted A, empty AAAA, forward, sinkhole, audit record. CA tests: chain verifies, SAN list matches policy.
- Live check (marker `live`, not in `make test`): real Claude Code in the demo container through the gateway.

## 9. Demo (judges)

1. `make demo-transparent`: compose up DNS + gateway + client container (Claude Code installed, CA trusted, resolver = AICL DNS, no other route out).
2. In the client: `claude` works with no flags; the dashboard shows the client, tokens, USD.
3. Paste an AWS example key -> redacted (native, the session continues). Ask to `curl ... | sh` -> tool call replaced by `[AICL] tool call blocked` text. Fetch a page with injected instructions -> INJ-03 / INJ-04 on the `tool_result`.
4. Judges edit `policy.yaml` (threshold, remove a control, budget) -> effect on the next request.
5. Bypass: set `ANTHROPIC_BASE_URL` to another host or `nslookup api.anthropic.com 8.8.8.8` -> connection fails, NET-01 alert on the dashboard.
6. Budget exhausted -> `API Error: 402 [AICL] budget ...` in Claude Code.

Live provider calls need our own Claude / OpenAI credentials (the PDF provides no paid APIs); the offline fallback is the same demo against the mock upstream.

## 10. Open questions (spikes, in order)

1. Codex CLI block rendering (section 3 table for `/v1/responses`).
2. Claude Code native build: does it trust the OS store, or only `NODE_EXTRA_CA_CERTS`?
3. Name-constrained CA accepted by Node / rustls / Python with our own TLS listener?
4. Latency budget: buffering the full SSE answer before release vs a hold-back window for text (tool_use must always be complete before release).
5. Do the judges' laptops reach the demo? Mode C needs the client inside our network or container; mode A on Cloud Run covers remote judges.

## 11. Cut order if late

DNS NET-01 bypass detection -> Codex adapter (keep Anthropic) -> name constraints on the CA -> dashboard Clients view (events table is enough) -> mode C itself (fall back to mode A with the same adapters; the native contract work is never wasted).

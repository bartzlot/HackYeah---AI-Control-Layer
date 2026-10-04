#!/usr/bin/env bash
# One-shot: add the v4 transparent-interception tasks (research/14) to TASKS.md through task.sh.
# Run once, from main, AFTER the v4 docs (CAPSULE.md, research/14, brief, README) are on origin/main.
# Every add is its own atomic commit + push; ids are read back so deps point at the real ids.
set -euo pipefail
cd "$(dirname "$0")/.."

add() {
  local out id
  out="$(scripts/task.sh add "$1")"
  printf '%s\n' "$out" >&2
  id="$(printf '%s\n' "$out" / tail -n 1 / grep -o 'T-[0-9]\{3\}' / head -n 1)"
  [ -n "$id" ] || { echo "could not read the new task id" >&2; exit 1; }
  printf '%s' "$id"
}

L1=$(add "[lead] (T1) v4 contracts + policy: Event gains protocol (anthropic_messages / openai_responses / openai_chat), upstream_host, client_ip, credential_hash, user_agent; policy.yaml interception: block (providers hosts + protocol + inspected paths, proxy_other_paths, max_body_kb 4096, dns, tls, block_style per protocol) and clients: identities; prices for the real Claude / OpenAI models from the pricing pages; policy/README; deps dnslib [14 s.4, s.6] | deps: -")

W_ANT=$(add "[w1] (T1) Anthropic Messages adapter POST /v1/messages (stream + non-stream): parts from system / text / tool_result (untrusted channel) / tool_use; in-place redaction keeping unknown fields and never touching thinking / redacted_thinking blocks; buffer the upstream SSE, decide() on text + tool_use, re-emit events in the original order; native shapes: hard block = 400 invalid_request_error, budget = 402 billing_error, soft block / blocked tool_use = 200 assistant text [AICL] with stop_reason end_turn; never refusal, 403, 429/5xx or mid-stream error events; recorded Claude Code 2.1.289 request fixture + mock upstream; cases [14 s.3, s.7] | deps: $L1")

W_RT=$(add "[w1] (T1) passthrough router: Host / SNI -> provider + protocol from interception.providers; client Authorization / x-api-key / OAuth bearer forwarded unchanged (credentials: passthrough; managed mode keeps current gateway keys); every non-inspected path (HEAD /api/hello, /v1/messages/count_tokens, /v1/models, unknown) proxied byte-for-byte with streaming and audited; upstream resolved via interception.dns.upstream, never via our DNS; identity = client_ip + sha256(key)[:8] + user agent -> clients: map; real Claude Code works in mode A (ANTHROPIC_BASE_URL) [14 s.2, s.6] | deps: $L1")

W_TLS=$(add "[w1] (T1) TLS + CA: aicl ca init / leaf / export (cryptography; P-256 root; one leaf with SAN = every intercepted host, regenerated on policy change); gateway TLS listener :443 with the leaf; install guide per OS (Windows certutil, macOS security add-trusted-cert, Linux update-ca-certificates) + NODE_EXTRA_CA_CERTS / SSL_CERT_FILE / REQUESTS_CA_BUNDLE; tests build a CA in tmp and verify the chain + SAN list [14 s.5] | deps: $L1")

W_DNS=$(add "[w1] (T1) DNS resolver (dnslib, UDP + TCP :53): intercepted hosts -> A gateway_ip, empty AAAA; doh_sinkhole names -> NXDOMAIN; everything else forwarded to interception.dns.upstream; reload with the policy; every query = one audit record (client ip, name, type, intercepted, answer) [14 s.5] | deps: $L1")

W_TOOL=$(add "[w2] (T1) coding-agent tool firewall: TOOL-01 rules per tool name for Claude Code / Codex (Bash / shell / exec_command: curl|sh, rm -rf /, reads of ~/.aws ~/.ssh .env; Write / Edit / apply_patch paths outside the project; WebFetch to unknown hosts; historical rules on commands and written code); tool_result parts run INJ-03 + INJ-04 as an untrusted channel; Authorization headers never scanned as parts; cases [14 s.7] | deps: $L1")

W_RUN=$(add "[w2] (T1) runner v4: case files gain protocol: (anthropic_messages / openai_responses / openai_chat) and drive the gateway through a mock upstream; assert the native contract (status, error envelope type, SSE event sequence parses, block text starts with [AICL], unknown fields + thinking blocks byte-identical after redaction); meta-test: allowed + blocked per control per implemented protocol [14 s.8] | deps: $W_ANT")

D_COMP=$(add "[lead] (T1) compose transparent demo: internal network (no route out) with dns (static ip) + gateway (static ip, :443, second network with egress) + demo-client container (Node + Claude Code CLI, resolver = AICL DNS, CA via NODE_EXTRA_CA_CERTS + OS store); make ca, make demo-transparent; .env.example documents ANTHROPIC_API_KEY for the live demo only (never in tests); tests/test_transparent_compose.py [14 s.1, s.9] | deps: $W_TLS, $W_DNS, $W_RT")

W_CDX=$(add "[w1] (T2) OpenAI Responses adapter POST /v1/responses for Codex (stream + non-stream): input items, function_call / local_shell_call / custom tool items, never touch reasoning encrypted_content; native block shapes; start with the mock spike (real Codex CLI against a mock, record its block-rendering table in research/14 s.3, pick the budget status) [14 s.3] | deps: $W_ANT")

W_NET=$(add "[w2] (T2) NET-01 bypass detection: DNS lookup of an intercepted host by a client with no gateway request within 30 s, or a lookup of a doh_sinkhole name -> WARN finding on the dashboard; cases [14 s.1] | deps: $W_DNS")

W_UI=$(add "[w1] (T2) dashboard v4: Clients view (address, tool from user agent, key fingerprint, tokens, USD, blocks), DNS panel (queries, intercepted, NET-01 alerts), protocol + upstream host columns in live events [14 s.9] | deps: $W_RT, $W_DNS")

DOCS=$(add "[any] (T1) docs v4: README quick start for mode A and mode C, CA install per OS, reference egress firewall rules (nftables + Windows Firewall: provider ranges only from the gateway, DNS only to AICL, 853 dropped), PDF criteria -> where we show it table; keep research/14 in sync with what landed [14 s.1, s.9] | deps: $D_COMP")

add "[any] (T1) v4 rehearsal: research/14 s.9 demo end to end (Claude Code live with our own key + offline fallback against the mock upstream, recorded); judge edits of policy.yaml applied live; bypass attempt shown | deps: $D_COMP, $W_ANT, $W_TOOL, $DOCS" >/dev/null

echo "v4 tasks added. Humans at SYNC: cut T-101 (GCP VM, superseded), cut T-006 (duplicate of T-007), fold T-902 into the v4 docs + rehearsal tasks; T-012 Cloud Run stays as mode A only." >&2

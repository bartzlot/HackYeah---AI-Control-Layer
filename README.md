# AICL - AI Control Layer

**A self-hosted control layer on the network path of every AI API client: Claude Code, Codex, SDKs and agents pass through it without changing a single setting.**

AICL answers the DNS lookups for the AI API hosts (`api.anthropic.com`, `api.openai.com`, ...) with its own address, terminates TLS with an organization CA, and reads each request in the provider's own API contract. It identifies who is calling, meters the spend, inspects prompts, tool results, tool calls and answers with fast deterministic checks and a local AI judge, and decides in milliseconds whether to allow, log, warn, redact or block. Allowed traffic goes to the real provider with the user's own credentials; blocks come back in the provider's native format, so the tools show them as ordinary messages. One policy file governs all of it and reloads live; every decision is explained, audited and visible on a dashboard. Built for the HackYeah 2026 "AI Control Layer" challenge.

## The problem

- **Agents execute natural language.** A sentence hidden in a web page, a file, a tool result or a memory entry can redirect a coding agent (prompt injection), and the agent then acts with the developer's credentials.
- **Data leaves through prompts and tool arguments.** Secrets, customer data and internal code end up in external models.
- **Agents run commands.** `curl ... | sh`, `rm -rf`, reading `~/.aws`, loading pickles or `trust_remote_code=True` are one tool call away.
- **Agents loop and spend**, and nobody sees per-person cost.
- **Opt-in gateways are easy to skip.** If the control depends on `ANTHROPIC_BASE_URL`, a user who changes one variable leaves the control.

## What AICL does

1. **Intercepts transparently** (mode C): DHCP hands out the AICL DNS, the AICL CA is trusted by the OS; the AI API hosts resolve to the gateway, everything else resolves normally. Also works as an explicit proxy (mode B) or with a base URL (mode A).
2. **Speaks the native contracts**: Anthropic Messages, OpenAI Responses and Chat Completions, streaming included. Hard blocks are native `400` errors, budget stops are `402`, soft blocks and blocked tool calls are a normal assistant message `[AICL] ...`. Every other path is proxied byte-for-byte.
3. **Detects**: secrets, PII with checksum validation (PESEL, IBAN, cards), injection signatures EN + PL, historical exploit rules (code execution, unsafe deserialization, model-repo supply chain), coding-agent tool rules, and a local LLM judge (Ollama) on the gray band and on untrusted tool results.
4. **Decides per destination and identity**: the same prompt can pass to a local model, be redacted for an external one and be blocked for an unknown host; identity = client address + key fingerprint + tool.
5. **Governs resources**: token and USD budgets per agent and org, loop guard.
6. **Reports**: audit log (JSONL, CSV export), live event stream with the explain trace, `Server-Timing` per request, dashboard with posture, blocked threats, cost and a playground.
7. **Detects bypass attempts**: DNS lookups of AI hosts that never reach the gateway, and DNS-over-HTTPS resolvers, raise an alert. The bypass itself is stopped by the egress firewall (reference rules in the docs).

## Architecture

```mermaid<br/>flowchart LR<br/>  subgraph client[Developer machine or agent container]<br/>    CC[Claude Code / Codex / SDK]<br/>  end<br/>  DHCP[(DHCP: DNS = AICL)] -.-> CC<br/>  CC -- "1 DNS api.anthropic.com?" --> DNS[AICL DNS :53\nAI hosts -> gateway\nothers forwarded\nqueries audited]<br/>  CC -- "2 TLS SNI api.anthropic.com\nAICL CA leaf" --> GW<br/>  subgraph aicl[AICL]<br/>    GW[Gateway :443\nrouter + provider adapters\nAnthropic / OpenAI native contract] --> D{"decide()\nidentity, budget,\ndeterministic, judge,\ntools, destinations"}<br/>    D --> GW<br/>    POL[(policy.yaml + local.d\nlive reload)] --> D<br/>    D --> AUD[(audit JSONL + SSE)]<br/>    AUD --> UI[Dashboard /console]<br/>    DNS --> AUD<br/>    J[Ollama local judge] <--> D<br/>  end<br/>  GW -- "3 allowed: client's own key" --> API[(api.anthropic.com\napi.openai.com)]<br/>  FW[[Egress firewall: provider IPs only from the gateway,\nDNS only to AICL, DoT/DoH blocked]] -.-> client<br/>```

| Piece | Dir | Role |
|---|---|---|
| Gateway | `w1-gateway/` | provider adapters, router, TLS + CA, DNS, budgets, judge, dashboard, `cloud-sim` mock |
| Core | `w2-core/` | policy engine, `decide()`, detectors, tool rules, test runner |

Design and rationale: `research/14-transparent-interception.md` (ingress, native contract, bypass model), `research/13-architecture.md` (engine, policy, controls). Issuer requirements: `research/brief.md`. Work process and task board: `AGENTS.md`, `CAPSULE.md`, `TASKS.md`.

## Limits (stated up front)

- AICL sees only traffic that crosses it. Without the egress firewall a user can bypass DNS; VPNs, hotspots and personal devices are endpoint and HR policy, not ours.
- Web apps (claude.ai, chatgpt.com) and certificate-pinned desktop apps are out of scope; API clients only.
- Classifiers and judges are evidence, not a boundary: deterministic rules, budgets and the network path never depend on them.
- No paid APIs are provided in this challenge: the test suite and the offline demo use mock upstreams; the live demo uses our own provider credentials.

## Status

| Feature | State |
|---|---|
| Policy engine, `decide()`, detectors, tool rules, test runner | built |
| OpenAI-compatible gateway (Chat Completions), budgets, loop guard, judge, dashboard, containers | built |
| Policy + budget editor in the console, Cloud Run deploy (mode A) | in progress |
| Anthropic Messages + OpenAI Responses adapters, native block contract | planned (`research/14` s.3) |
| TLS listener + AICL CA, DNS resolver, transparent compose demo (mode C) | planned (`research/14` s.5, s.9) |
| Bypass detection (NET-01), clients and DNS views | planned |

Quick start, CA install guide and the reference firewall rules land with the docs task in `TASKS.md`.

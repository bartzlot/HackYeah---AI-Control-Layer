# AICL - AI Control Layer

**A self-hosted, local-first control layer that every AI agent interaction has to cross.**

AICL sits between agents and everything they touch: LLMs (local Ollama or a commercial API), MCP servers, tools, memory and other agents. It authenticates the agent, meters its spend, inspects prompts, tool calls, tool results and answers with fast deterministic checks and local AI models, and decides in milliseconds whether to allow, log, warn, redact, ask a human or block. One policy file governs all of it and reloads live; every decision is explained, audited and visible on a dashboard. Built for the HackYeah 2026 "AI Control Layer" challenge.

## The problem

- **Agents execute natural language.** A sentence hidden in a web page, a PDF, a tool description or a memory entry can redirect an agent (prompt injection), and the agent then acts with real credentials.
- **Data leaves through prompts, tool arguments and rendered output.** Secrets, customer data and internal documents end up in external models, MCP servers or markdown image URLs (EchoLeak, CVE-2025-32711).
- **Tools and MCP servers are a supply chain.** Tool descriptions can be poisoned or silently changed after approval (rug pull); model files can execute code (pickle); packages get typosquatted or compromised.
- **Agents loop and spend.** Runaway agents burn tokens and GPU time; local models are usually treated as free and escape every budget.
- **Security teams cannot see any of it.** There is no single audit trail of which human, app and agent chain did what, under which rule.

## What AICL does

1. **Intercepts** agent traffic at three enforcement points that share one decision function: an OpenAI-compatible LLM gateway, an MCP gateway (Streamable HTTP and stdio, spec 2026-07-28 and 2025-11-25), and a small SDK for in-process tools, memory and agent-to-agent messages. Agents run on an internal network whose only exit is the gateway and never hold upstream credentials.
2. **Detects** in a cost-ordered cascade: normalization and deobfuscation, signed signature rules, secrets, PII with checksum validation (incl. PESEL, NIP, IBAN), tool-argument validators (SQL, shell, paths, SSRF), MCP tool pinning, pickle and package checks in about 1-4 ms; a local injection classifier, exemplar search and a local LLM judge only where they pay off.
3. **Decides** per destination and identity: the same prompt can pass to a local model, be redacted for an external model and be blocked for an unknown host; destructive or external actions wait for a human approval bound to the exact arguments.
4. **Governs resources**: budgets in tokens, USD and local GPU-seconds per org, team, agent and session, with a downgrade ladder, rate limits, loop detection and a kill switch.
5. **Reports**: hash-chained audit (content stored as keyed hashes), Prometheus metrics, per-stage timing, and a dashboard for management (posture, cost, attacks) and security teams (live threats, explain trace, replay, exports), plus a playground for ad-hoc prompts.

## Why this is different

- **One file, one second, one diff:** guardrails, thresholds, models, budgets, MCP pins and identities in one `policy.yaml`; edits apply live, invalid edits keep the last good policy, and each edit is simulated over recent traffic.
- **Local models are not free:** GPU-second budgets from Ollama timings, where other gateways price local models at zero.
- **Destination-aware DLP**, **provenance-aware tool firewall** (pinning + identity chain + taint), **verifiable defense** (signed feed whose rules carry inline tests; explainable decisions with counterfactuals).
- **Local-first:** no prompt leaves the machine to be guarded.

## Limits (stated up front)

- A gateway only sees what crosses it: unmediated egress, side effects inside `pip install`, and timing side channels are out of scope.
- Classifiers are evidence, not a boundary: adaptive attacks evade published detectors, so authorization, budgets, canaries and taint never depend on them.
- The "commercial" model in the demo is a priced mock (no paid APIs in this challenge).

## Architecture

```
agents (internal net) -> AICL :18080 [PEP A LLM | PEP B MCP | PEP C SDK]
                           -> decide(): identity, budget, L0-L1 deterministic, L2-L4 semantic, tool authz, destination DLP
                           -> Ollama (host) | priced mock LLM | MCP servers
policy.yaml + local.d (live reload) | signed feed :18100 -> decide()
audit (hash chain) + /metrics + SSE -> console :18000 (dashboard, playground, policy, approvals)
```

| Piece | Dir | Role |
|---|---|---|
| Gateway | `w1-gateway/` | LLM and MCP gateways, SDK, identity, credential broker |
| Core | `w2-core/` | policy engine, decision core, tool firewall, approvals, destination DLP, test runner |
| Deterministic | `w3-detect/` | normalization, rules engine, secrets, PII, validators, MCP pins, supply chain, signed feed |
| Semantic + resources | `w4-semantic/` | classifier, exemplar kNN, local judge, calibration, budgets, loop guard |
| Console | `w5-console/` | audit, metrics, dashboard, playground, demo kit, docs |

Design and rationale: `research/13-architecture.md` (decisions) and `research/00-summary.md` (facts, measurements). Work process and task board: `AGENTS.md`, `CAPSULE.md`, `TASKS.md`.

## Status

Research and plan landed; build in progress per `TASKS.md`. A quick start (`docker compose up -d && make test`) and the AI and tools disclosure are added with task T-510.

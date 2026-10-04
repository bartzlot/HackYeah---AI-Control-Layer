# AICL - AI Control Layer

**A self-hosted control layer on the network path of every AI API client. Claude Code, Codex, SDKs and agents pass through it without changing a single setting.**

AICL answers DNS lookups for the AI API hosts (`api.anthropic.com`, `api.openai.com`) with its own address, terminates TLS with an organization CA, and reads every request in the provider's own API contract. It identifies who is calling, meters spend, and inspects prompts, tool results, tool calls and answers. Fast deterministic checks run first, a local AI judge (Ollama) handles the gray band, and the outcome is allow, warn, redact or block, decided in milliseconds. Allowed traffic goes to the real provider with the user's own credentials. Blocks come back in the provider's native format, so Claude Code and Codex show them as ordinary messages or API errors. One policy file governs everything and reloads live. Every decision is explained, audited and visible on a dashboard. Built for the HackYeah 2026 "AI Control Layer" challenge.

```
$ claude -p "Read notes.txt and summarize it"            # inside the demo laptop, no AICL config at all
API Error: 400 [AICL] request blocked by policy: INJ-03 rule HIST-010: BLOCK ... classic instruction override: untrusted channel
$ claude -p "Read the .env file and list the variables"
[AICL] tool call blocked (Read): TOOL-01 rule CODE-AG-002: BLOCK - Read: argument matches dotenv secrets file read. The command was not executed.
```

## Quick start

Requirements: Python 3.13 with [uv](https://docs.astral.sh/uv/), Docker. No paid API is needed for the tests or the offline demo.

| Goal | Command |
|---|---|
| Run the offline test suite (1009 tests, about 30 s) | `uv sync && make test` |
| **Requirements report**: every PDF requirement -> its tests, PASS / FAIL (`reports/requirements_report.md`) | `make verify` (offline) or `make verify-live` (+ real Claude Code, Codex CLI, console UI in Chrome) |
| Performance telemetry (`reports/bench.json`) | `make bench` |
| **Transparent demo**: corp network in miniature with a developer laptop running Claude Code, DNS pointing at AICL, AICL CA trusted, no route around the gateway | `make demo-transparent` (uses your local Claude Code login: access token only), or `make demo-transparent-offline` (Anthropic mock, no tokens) |
| Use the demo laptop | `docker compose -f docker-compose.transparent.yml exec devbox claude -p "hello" --model claude-haiku-4-5` |
| Dashboard (also the policy, budget, control and AI-domain editor) | http://127.0.0.1:18080/console |
| Classic demo stack with your own Ollama on the host | `make demo-local` |
| Public demo on Cloud Run (base-URL mode) | `GCP_PROJECT=<project> make cloudrun` |
| Base-URL mode on your own machine | `uv run python -m aicl_gateway.serve`, then `ANTHROPIC_BASE_URL=http://127.0.0.1:18080 claude` |
| Codex in base-URL mode | `codex -c model_provider=aicl -c 'model_providers.aicl={name="aicl",base_url="http://127.0.0.1:18080/openai/v1",env_key="OPENAI_API_KEY",wire_api="responses"}'` |
| Live tests with the real CLIs | `make live` (Claude Code, base URL), `make live-transparent` (Claude Code in the demo laptop), `tests/live/test_live_codex.py` (Codex CLI) |

### Try it (in the demo laptop or through the playground)

- Paste `AKIAIOSFODNN7EXAMPLE` or a PESEL into a prompt: the value is redacted before it leaves, and the session keeps working.
- `Read notes.txt` where the file hides "ignore all previous instructions ...": the next request is blocked natively (injection in a tool result).
- Ask Claude Code to read `.env` or `cat ~/.aws/credentials`, or to pipe a script into `sh`: the tool call is replaced by `[AICL] tool call blocked` before Claude Code runs it.
- Edit `policy/policy.yaml` (switch a control to `off`, change `profile`, lower a budget) and send the next prompt: the change is live within about 1 s. A broken edit is rejected and the last good policy stays. The same from the console: Controls page switches (off / shadow / enforce per profile), Policy page YAML editor and budget table, Network page AI domains (a new host is answered by DNS and gets a TLS certificate at once, no restart). Every edit is a `POLICY_CHANGED` audit record; writes need `AICL_ADMIN_TOKEN`.
- Try to get around it: `dig @1.1.1.1 api.anthropic.com`, DNS-over-HTTPS, `ANTHROPIC_BASE_URL=https://elsewhere`, or a lookup without a connection. There is no route, and the Network page raises an alert (NET-01).

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/01-topology.dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/diagrams/01-topology.light.svg">
  <img src="docs/diagrams/01-topology.light.svg" alt="Deployment: developer laptop, DHCP and egress firewall, AICL DNS, gateway and console, AI providers and the Ollama judge">
</picture>

**Topology.** DHCP points the laptop at the AICL resolver, the egress firewall lets only AICL talk to DNS and the providers, and the gateway sends the gray band to a local Ollama judge.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/02-sequence.dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/diagrams/02-sequence.light.svg">
  <img src="docs/diagrams/02-sequence.light.svg" alt="Sequence of one request: DNS, TLS with the AICL CA leaf, decide() on the request, upstream call, decide() on the response, native answer or block">
</picture>

**One request.** DNS and TLS land on the gateway, `decide()` checks the request, the upstream call uses the client's own credential, `decide()` checks the response, and the client gets a native answer or a native block.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/03-decide.dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/diagrams/03-decide.light.svg">
  <img src="docs/diagrams/03-decide.light.svg" alt="The decide() pipeline: event, identity and budget, controls, findings, severity lattice, decision and audit">
</picture>

**The `decide()` pipeline.** Each control runs in its policy mode, enforced findings are combined on the ALLOW < LOG < WARN < REDACT < BLOCK lattice, and any engine error fails closed.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/04-bypass.dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/diagrams/04-bypass.light.svg">
  <img src="docs/diagrams/04-bypass.light.svg" alt="Bypass attempts, the network control that stops each one, and what NET-01 shows">
</picture>

**Bypass.** Each way around the gateway is stopped by the egress firewall, DNS sinkholing or a failed TLS handshake, and the resolver raises NET-01 when a name is looked up without a request.

Detail and measurements: [`research/14-transparent-interception.md`](research/14-transparent-interception.md). Sources and regeneration: [`docs/diagrams/`](docs/diagrams/README.md).

There are three ways traffic can reach AICL, and all of them share one gateway and one `decide()`:
- **Explicit proxy** (main mode): device management (MDM, GPO or a PAC URL) sets `HTTPS_PROXY` to AICL and trusts the AICL root CA. Works on any network; AI hosts are inspected, other hosts are tunnelled or denied by policy.
- **Transparent**: DHCP hands out the AICL resolver and the AICL root CA is trusted. Nothing is configured in the tool; for devices that cannot be managed.
- **Base URL**: `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`, useful where DNS cannot be controlled.

Bypass is stopped by the egress firewall ([reference rules](deploy/firewall/)) and detected by the resolver. Design and measurements: [`research/14-transparent-interception.md`](research/14-transparent-interception.md).

### Transparent mode on a host machine (macOS / Linux / Windows)

The demo runs the corp network in containers. To point a real machine at it, `scripts/demo-transparent.sh` PRINTS the resolver and CA trust commands for macOS, Linux and Windows and never runs them: they need admin rights and change the whole machine, so you copy and run them yourself (each has an undo). Set `AICL_TRANSPARENT_HTTP_PORT` (default 18080) to move the console host port so the stack runs next to the base-URL compose and a local serve. With `AICL_OFFLINE=1` the script ends with a smoke check: a devbox `claude -p` through the mock must answer and add exactly one audit record.

**Native contract** (measured on Claude Code 2.1.289 and Codex CLI 0.160):

| Situation | Answer | What the developer sees |
|---|---|---|
| Hard block of a request | `400 invalid_request_error` | `API Error: 400 [AICL] ...` |
| Budget exhausted | `402` | `API Error: 402 [AICL] budget exceeded ...` |
| Blocked tool call or answer | `200` with assistant text | `[AICL] tool call blocked ...` (the command never runs) |
| Redaction | the request or answer rewritten in place | normal answer without the secret |

`stop_reason: refusal`, 403, 429 and mid-stream errors are never used: the clients either blame the provider, retry, or hide the text.

**Per request, `decide()` runs:**
1. Identity: client address, key fingerprint and tool are mapped to a principal through `clients:`.
2. Model allowlist and a budget reservation.
3. Deterministic controls: secrets (DLP-01), PII with checksums including PESEL, IBAN and cards (DLP-02), the destination matrix that puts data class against local / external / unknown (DLP-05), and signature rules with inline tests: injection EN + PL, historical exploits, coding-agent rules.
4. The local semantic cascade (INJ-04) on user turns and untrusted tool results: an ONNX prompt-injection classifier on CPU, a multilingual kNN over labelled EN + PL examples as the second opinion, and the local LLM judge only where the two disagree.
5. The tool firewall (TOOL-01) on every tool call the model wants to run.
6. The final action is the maximum on the lattice ALLOW < LOG < WARN < REDACT < BLOCK. Redaction and audit follow.

## PDF criteria -> where to look

| Requirement (CRIETRIA PDF) | Where it is |
|---|---|
| 3.1 Control layer that is easy to integrate (agent to model, agent to tools) | Transparent DNS + TLS interception, base URL or proxy; native Anthropic and OpenAI contracts; [demo](docker-compose.transparent.yml) with the real Claude Code; managed OpenAI-compatible gateway for own agents |
| 3.1b Architecture diagram | above, plus [`research/14`](research/14-transparent-interception.md) |
| 3.2 Documented policy with strictness levels and budgets | [`policy/policy.yaml`](policy/policy.yaml) (profiles strict / balanced / permissive, matrix, controls, budgets, interception, clients) + [`policy/README.md`](policy/README.md) |
| 3.3 Interactive dashboard | Console: posture, blocked threats, spend, clients, network and bypass, performance, policy, live events with explain, playground |
| 3.4 / 4.6 Executable test suite, positive and negative | `make test`: 1009 offline tests including per-control case files with allowed and blocked cases, mutation proof and native-contract tests; `make live*`: the real Claude Code and Codex CLIs |
| 4.1 Centralized policy engine | one file plus `local.d/` overlays and `rules/*.yaml`, hot reload, last good on error, version hash on every decision |
| 4.2.1 Deterministic controls | DLP-01 secrets, DLP-02 PII with checksums, DLP-05 destination matrix, INJ-03 signatures, TOOL-01 tool firewall, ACCESS-01 identity and models, KILL-01 |
| 4.2.2 Semantic controls | INJ-04 local LLM judge (Ollama `qwen3.5:2b`, JSON-schema verdicts, cache, fail-degrade) |
| 4.3 Budgets (tokens, money, compute) | BUD-01 per principal and org; prices from the official pricing pages including prompt-cache multipliers; native 402 at the cap; loop guard |
| 4.4 Historical attack mitigation | signed signature feed from an external publisher (`python -m aicl_gateway.feed`: Ed25519, pinned key, no rollback, inline tests gate activation); `policy/rules/historical.yaml` (curl or wget piped to a shell, pickle, `trust_remote_code`, foreign model pulls) and `coding_agent.yaml` (credential reads, exfiltration, reverse shells, persistence), each with inline tests |
| 4.5 Reporting and exportable audit | JSONL audit (spans as hashes, no raw text), JSONL and CSV export, live SSE, per-request `Server-Timing` |
| 6 Live config edits, ad-hoc prompts, telemetry | edit the YAML or use the console editors (validated, atomic, live at once, audited); playground; `make bench` and the Performance page |
| 8 Robustness | normalization against zero-width, homoglyph, Unicode tag and fullwidth tricks; canonical-path and duplicate-key checks; fail-closed PEP; findings from two fresh-session security reviews fixed with regression tests |

## Numbers

Performance (`make bench`, laptop CPU):

| | p50 |
|---|---|
| Small chat prompt, full policy | 0.08 ms |
| Tool call check | 0.05 ms |
| Claude Code sized turn (400 KB of system, history and tool results), cold | 81 ms |
| Gateway overhead on a 222 KB Claude Code request (Server-Timing) | 30 ms |
| Local judge on a new untrusted text (CPU, 2B model) | 1-3 s, then cached |

Tests:
- `make test`: 1009 offline tests pass; `make verify-live` (2026-10-04): 1001+ tests, 0 failed, all 16 PDF requirements PASS.
- Live with the real CLIs:
  - Claude Code in base-URL mode: 7 of 7.
  - Claude Code in transparent mode: 9 of 9.
  - Codex CLI through AICL to the OpenAI mock: 5 of 5 (no OpenAI subscription is provided in the challenge).
  - Console in a real Chrome (puppeteer): editor rejects a bad edit and applies a good one, budget saved, control switched off, AI domain added, all pages, playground, no JS errors.

## Policy and rules

```yaml
# policy/rules/coding_agent.yaml: a new rule is one entry; its tests gate the reload
- id: CODE-AG-002
  name: dotenv secrets file read or copied
  category: tool_abuse
  scope: tool_args                   # command / path rule, not a text signature
  pattern: '(^|[\s/=''"])\.env(\.(local|production|prod|dev|development|staging|secret))?([\s''"]|$)'
  action_untrusted: BLOCK
  match: ['file_path=/work/app/.env', 'command=cat .env']
  no_match: ['command=cat .env.example', 'command=python -m venv .venv']
```

To roll this out in an organization:
1. DHCP option 6 points at the AICL resolver.
2. Install the root CA once: `python -m aicl_gateway.ca export` prints the commands for Windows, macOS, Linux, Node, Python and Rust.
3. Apply the egress rules: [`deploy/firewall/nftables-aicl.conf`](deploy/firewall/nftables-aicl.conf) or [`windows-firewall-aicl.ps1`](deploy/firewall/windows-firewall-aicl.ps1).

## Limits

- AICL sees only traffic that crosses it. Without the egress firewall, a user can bypass DNS; VPNs, hotspots and personal devices are endpoint and HR policy.
- Web apps (claude.ai, chatgpt.com) and certificate-pinned desktop apps are out of scope, as is Codex logged in through ChatGPT (it talks to chatgpt.com behind Cloudflare). This is about API clients.
- Classifiers and judges are evidence, not a boundary: deterministic rules, budgets and the network path never depend on them. A benign judge verdict never blocks (lesson from the live test: the 2B judge once marked Claude Code's own context as high risk).
- No paid APIs are provided in the challenge. The offline demo and the tests use mocks; the live Claude tests use our own login.

## Repository

| Path | What |
|---|---|
| `w1-gateway/aicl_gateway/` | `passthrough.py` (PEP), `openai_adapters.py`, `dns.py`, `ca.py`, `serve.py`, managed gateway `app.py`, budgets, judge, console |
| `w2-core/aicl_core/` | policy engine, `decide()`, controls, detectors, interception and clients policy |
| `policy/` | `policy.yaml`, `rules/*.yaml`, `local.d/` overlays |
| `tests/`, `*/tests/`, `*/cases/` | offline suites, case files per control, `tests/live/` for the real CLIs |
| `deploy/` | devbox image, firewall reference rules |
| `research/` | design: `14-transparent-interception.md` (v4), `13-architecture.md`, `brief.md` (PDF verbatim) |

Process: `AGENTS.md`, `CAPSULE.md`, `TASKS.md`. Built with Claude Code (Claude Opus) as a coding agent; every change went through tests and fresh-session reviews.

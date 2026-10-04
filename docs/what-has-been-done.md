# What has been done

Status of AICL (AI Control Layer) at the end of HackYeah 2026, for the "AI Control Layer" challenge (CRIETRIA PDF). How to run it: [README](../README.md). Design detail: [`research/14-transparent-interception.md`](../research/14-transparent-interception.md) and [`research/13-architecture.md`](../research/13-architecture.md).

## In one paragraph

AICL is a self-hosted security and cost control layer that sits on the network path of AI API clients: Claude Code, Codex, OpenAI / Anthropic SDKs and custom agents. It is **transparent**: the agent applications are not integrated, patched or reconfigured. AICL reads every request in the provider's own API format, decides in milliseconds whether to allow, warn, redact or block it, forwards allowed traffic to the real provider with the user's own credentials, and answers blocks in the provider's native format so the tools show them as ordinary messages. Its AI detection runs on a **local model** on CPU, it needs **no paid API and no GPU**, and it enforces **token and money budgets** per person, team and organization.

## 1. Transparent: no integration with agent applications

Nothing is installed in, or changed in, the agent tool. Traffic reaches AICL through the network:

| Mode | How traffic arrives | Who it is for | Status |
|---|---|---|---|
| Transparent DNS + TLS | The AICL DNS resolver (handed out by DHCP) answers `api.anthropic.com`, `api.openai.com` with the gateway address; AICL terminates TLS with the organization root CA | any device on the network, zero configuration in the tool | done, demo `make demo-transparent` |
| Explicit proxy | `HTTPS_PROXY` + AICL root CA, pushed by MDM, GPO or a PAC file | managed company laptops | designed (v5 main mode), CONNECT listener open (T-125) |
| Base URL | `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` | remote demo, own agents | done, also on Cloud Run |

What makes it work without integration:
- **Native API contracts.** Adapters for Anthropic Messages (`/v1/messages`), OpenAI Responses (`/v1/responses`, Codex) and OpenAI Chat Completions, streaming (SSE) included. Unknown fields and model reasoning blocks pass byte-identical; only redacted spans change. Every non-inspected path (token counting, model lists, probes) is proxied byte-for-byte.
- **Native blocks.** A hard block is `400 invalid_request_error`, an exhausted budget is `402`, a blocked tool call or answer is a normal assistant message starting with `[AICL]`. The contract was measured on the real Claude Code 2.1.289 and Codex CLI 0.160: `refusal`, `403`, `429` and mid-stream errors are never used, because the clients retry or blame the provider.
- **Identity without login.** Client address, a hash of the API key and the user agent map to a principal (`clients:` in the policy), so spend and blocks are attributed per person and per tool.
- **CA tooling.** `python -m aicl_gateway.ca` creates the root CA and one leaf certificate for every intercepted host, reissued live when a host is added; `python -m aicl_gateway.ca export` prints the trust commands for Windows, macOS, Linux, Node, Python and Rust.
- **Bypass resistance.** DNS-over-HTTPS resolvers are sinkholed, reference egress firewall rules ship in `deploy/firewall/` (nftables and Windows Firewall), and a DNS lookup of an AI host without a matching gateway request raises a bypass alert (NET-01) on the dashboard.

## 2. Security controls

One function, `decide(event, policy)`, runs for every request, response and tool call, in every mode:

| Control | What it does | Layer |
|---|---|---|
| ACCESS-01 | known principals and allowed models only | deterministic |
| DLP-01 | secrets (AWS keys, GitHub tokens, PEM keys, JWT, `api_key=`) redacted or blocked | deterministic |
| DLP-02 | personal data with validators: PESEL checksum + date, IBAN mod-97, card Luhn, e-mail, phone | deterministic |
| DLP-05 | destination matrix: what data class may go to the local model, an external model or an unknown host | deterministic |
| INJ-03 | prompt-injection, jailbreak and historical exploit signatures, EN + PL, each rule with inline tests | deterministic |
| INJ-04 | local AI cascade for the gray band (section 3) | AI, local |
| TOOL-01 | coding-agent tool firewall: `curl \| sh`, `rm -rf /`, reads of `.env`, `~/.aws`, `~/.ssh`, writes outside the project, fetches to unknown hosts | deterministic |
| BUD-01 | token and USD budgets, loop guard | deterministic |
| KILL-01 | emergency stop for all AI traffic | deterministic |

- Findings combine on the lattice ALLOW < LOG < WARN < REDACT < BLOCK; any engine error fails closed.
- Tool results and fetched files are treated as an **untrusted channel**: an injection hidden in a file the agent reads blocks the next request.
- Input is normalized against zero-width, Unicode tag and fullwidth tricks before matching.
- **Signed attack-signature feed:** new rules arrive as Ed25519-signed bundles from an external publisher, with a pinned key, no rollback, and activation only if every rule passes its inline tests.

## 3. Local AI model

The AI part of the detection never leaves the machine:
1. **ONNX prompt-injection classifier** (`protectai/deberta-v3-base-prompt-injection-v2`, Apache-2.0) on CPU through onnxruntime, deterministic (same text, same score), cached by text hash.
2. **Multilingual kNN** (`intfloat/multilingual-e5-small`, MIT) over labelled EN + PL attack examples, as the second opinion where the classifier is unsure. The classifier is English-centric, so the kNN arbitrates Polish text.
3. **Local LLM judge** (Ollama, `qwen3.5:2b-q4_K_M`, `think: false`, JSON-schema verdict) only for what is still uncertain. A benign verdict never blocks; a timeout degrades to WARN instead of failing the request.

The model files are pinned and fetched once (`make models-onnx`); tests use fakes and never download anything. Clean traffic does not reach the judge at all.

## 4. Low cost

- **Cheap to run.** CPU only, no GPU, small quantized models, no paid API for detection. Deterministic checks handle almost all traffic in well under a millisecond; the AI stages only see the gray band. On Cloud Run the judge runs `qwen3.5:0.8b` on CPU.
- **Low overhead.** Measured with `make bench`:

  | | p50 |
  |---|---|
  | small chat prompt, full policy | 0.08 ms |
  | tool call check | 0.05 ms |
  | gateway overhead on a 222 KB Claude Code request (Server-Timing) | 30 ms |
  | local judge on a new untrusted text (CPU, 2B model) | 1-3 s, then cached |

- **Spend under control.** Token and USD budgets per principal, team and organization, priced from the official Anthropic and OpenAI price lists (including prompt-cache multipliers): reserve before the call, settle on the real usage, native `402` at the cap. A loop guard stops an agent that repeats the same call. The dashboard shows who uses which tool and model and what it costs.

## 5. Policy and control plane

- One file, `policy/policy.yaml`, plus `local.d/` overlays and `policy/rules/*.yaml`: profiles strict / balanced / permissive, agents, destinations, controls, budgets, `interception:` (hosts, protocols, DNS, TLS, block styles) and `clients:`.
- Hot reload in about 1 s; an invalid edit is rejected and the last good policy stays live; every decision carries the policy version (sha256).
- Every edit made from the console is validated on a candidate file, applied atomically, live at once, written to the audit as `POLICY_CHANGED`, and needs the admin token.

## 6. Dashboard and reporting

The console (`/console`) shows:
- **Overview:** requests, blocked, redacted, spend against budget, protections enforced, gateway overhead, bypass attempts, the local judge state, top blocking rules and charts.
- **People & spend:** per client tool, models, tokens, USD and blocks.
- **Activity:** every decision live (SSE) with pop-up notifications for new events; a click opens the explanation: which checks ran, which rule fired, the per-stage timing (`Server-Timing`), with sensitive spans shown as hashes, never as raw text.
- **Network & bypass:** intercepted AI domains (add / remove a host live: DNS answers and the TLS certificate follow without a restart), DNS statistics, bypass alerts and a diagram of the last request's path.
- **Protections:** on / watch-only (shadow) / off per control and per profile.
- **Policy & budgets:** YAML editor, budget table, signed feed status, plain-language names for every control and rule.
- **Try it:** a playground and a one-click demo batch of 11 preset prompts, each caught by a different control, with the latency and the detection layer (deterministic or AI) per prompt.

Audit: JSONL with spans stored as hashes, JSONL and CSV export.

## 7. Verification

- `make test`: 1009 offline tests (no network, no Ollama, no paid API), including case files per control with an allowed and a blocked example and a mutation step (a blocked case must pass once its control is off).
- `make verify`: every CRIETRIA requirement mapped to its positive, negative and live tests in `tests/requirements.yaml`, report in `reports/requirements_report.md`; all 16 requirements PASS.
- Live with the real tools: Claude Code in base-URL mode 7/7, Claude Code in transparent mode 9/9, Codex CLI 5/5 (OpenAI mock upstream), console UI in real Chrome.
- Every change went through its piece's acceptance check and a fresh-session review.

## 8. Deployment

| Option | Command |
|---|---|
| Transparent "corporate network in miniature": a devbox with Claude Code, DNS pointed at AICL, CA trusted, no other route out | `make demo-transparent` (offline: `make demo-transparent-offline`) |
| Local demo with the host's Ollama | `make demo-local` |
| Docker compose stack (gateway, priced external-model mock, Ollama) | `make up` |
| Public demo on Google Cloud Run (base URL mode, one multi-container service) | `GCP_PROJECT=<project> make cloudrun` |
| Public demo through ngrok | README, "Public demo through ngrok" |

## 9. Open items and limits

Open on the task board ([`TASKS.md`](../TASKS.md)):
- explicit proxy listener (T-125) and its demo stack (T-020);
- loop guard on the passthrough path (T-128);
- DLP-02 e-mail redaction of Claude Code's own system prompt (T-210) and Cyrillic / Greek lookalike folding for INJ-03 (T-211);
- judge latency in Docker on macOS (T-023), hardening of the CA and of the public console (T-129).

Limits by design:
- AICL only sees traffic that crosses it; the egress firewall is what makes bypass impossible.
- Web apps (claude.ai, chatgpt.com) and certificate-pinned desktop apps are out of scope.
- Classifiers and judges are evidence, not the boundary: deterministic rules, budgets and the network path never depend on them.
- Single instance (SQLite + JSONL), demo CA, no SSO on the console: a production rollout needs SSO, a vault and SIEM export.

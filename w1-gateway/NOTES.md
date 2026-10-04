# w1-gateway notes (requests to the lead, local workarounds)

## Console is host-only by default (T-105)
- `/console/*` (UI, audit API, exports, playground demo key) answers 403 to non-loopback clients and to any
  request carrying `X-Forwarded-For` / `Forwarded`, unless `config["console"]["remote"]` is true
  (env `AICL_CONSOLE_REMOTE=1`).
- Inside docker compose the browser arrives from the bridge address, not loopback, so the gateway service
  needs `AICL_CONSOLE_REMOTE=1` AND a host-only port mapping `127.0.0.1:18080:18080` (lead, T-005), or the
  VM firewall limiting 18080 to the demo IP (T-101 / T-902). Never set remote with a public mapping.
- The entrypoint that builds `create_app` from `policy/policy.yaml` should pass
  `console={"policy": <callable returning the current raw policy dict>, "demo_key": <playground agent key>}`
  so the controls table, posture and the org USD budget follow live policy edits.

## Budgets from policy (T-104)
- `aicl_gateway.budget.config_from_policy(raw_policy)` returns the gateway config keys `budgets`, `budget`,
  `prices`, `loop_limits`. The policy-driven entrypoint (T-901) must merge it into `create_app(config=...)`;
  the Dockerfile's bare `create_app` factory caps nobody. Budget limits are read at startup (a policy edit
  to budgets needs a restart until the entrypoint re-applies them on reload).
- One uvicorn worker only: open reservations live in process memory (the cap guarantee is per process).
- Prompt repeats count toward the loop guard only with an `X-Session-Id`; tool-call repeats always count.

## INJ-04 judge (T-106)
- `aicl_gateway.judge.install(aicl_core.engine.register, ollama_url)` registers the judge with the w2 engine
  after INJ-03; the entrypoint (T-901) must call it once at startup. Not registered = INJ-04 never runs.
- The judge reads `controls.INJ-04.judge.timeout_ms` from the policy (8000 since T-008; default 3000 when
  absent) and calls the policy's judge model, renamed by `AICL_OLLAMA_MODEL` like the chat route.
- The gateway runs a sync decide() in its own thread pool so a judge call never blocks the event loop; the
  judge itself makes one Ollama call at a time (compose OLLAMA_NUM_PARALLEL=2 leaves chat a slot).

## Walking skeleton entrypoint (T-901) - requests to the lead
- T-009 (lead): switch the Dockerfile CMD to `uvicorn --factory aicl_gateway.main:create_app_from_env ...`
  in the SAME commit as tests/test_containers.py line 128 (it pins the old factory, so switching CMD alone turns
  main red), and drop the stale comment above CMD. Until then the container serves the bare create_app()
  (no agents, every request 401); `uv run uvicorn --factory aicl_gateway.main:create_app_from_env --port 18080`
  runs the policy-driven gateway locally.
- docker-compose.yml cloud-sim service: add `AICL_CLOUDSIM_SCRIPT: demo` (built-in demo script that makes the
  external model request a `curl ... | bash` tool call, repeatable), otherwise scenario S6 cannot show a block.
- The gateway reads its agent keys from env: `AICL_KEY_DEMO` (agent analyst-agent + console playground) and
  per-agent `AICL_KEY_` + agent id upper-cased (support-bot -> SUPPORT_BOT). Compose loads `.env` only if it
  exists, so without `cp .env.example .env` no agent can authenticate (every request 401). Either document the
  copy step in the README quick start or pass `AICL_KEY_DEMO` in the gateway service environment.
- No new variable names: everything main.py reads is already in .env.example.
- Demo run: `uv run python -m aicl_gateway.demo_agent` (needs AICL_KEY_DEMO; prints PASS/FAIL per scenario).

## Network page diagram (T-118)
- `GET /console/api/network` carries `last_request`: the newest request (max decision over its records) with `dns_seen` (an intercepted DNS_QUERY of the same client and host stored before it), `decision`, `outcome` (`upstream` | `block` | `response_block` = the provider was reached, its answer was blocked), host, tool, client. `null` before any request.
- The diagram is one self-contained `<svg id="flow">` in index.html. `app.js paintFlow()` only toggles classes (`on`, `dim`, `ok`, `warn`, `bad`) on its `data-node` (laptop, dns, gateway, upstream, block, firewall) and `data-edge` (dns, tls, upstream, block) groups. A replacement SVG (T-908) keeps those hooks and nothing else needs to change.

## Console overview (T-117)
- The overview judge tile reads `GET /console/api/judge` = `Judge.state(live policy)`: status idle (not called yet) / warm (last
  model call answered) / degraded (last call failed or the unreachable breaker is open) / off (disabled in policy), model (the
  tag Ollama really runs), p50 / p95 of the model-call wall time, verdict-cache hits. Counters are per process and reset on restart.
- `summary.top_rules` lists the rules whose BLOCK finding decided a blocked record (shadow-mode findings do not count).

## Demo batch, display names, detection layer (T-123)
- `aicl_gateway/demo_batch.py`: 11 presets (B1..B11) through `/v1/chat/completions`, each shown by a different control: clean, DLP-01 AWS key, DLP-02 PESEL,
  DLP-05 confidential project, INJ-03 EN + PL in a tool result, TOOL-01 curl | sh and .env read (cloud-sim demo script), INJ-04 judge on a paraphrase,
  ACCESS-01 unknown model, BUD-01 loop burst. One row per prompt: final action, control + rule (+ display names), layer, decide() ms, judge ms + model +
  verdict + confidence; summary = p50 / p95 + throughput. Console: Try it -> Run demo batch (`POST /console/api/demo/batch`, runs inside the gateway process,
  one at a time, host-only like the console). Terminal: `uv run python scripts/demo_batch.py [--url ...] [--json]` (needs the stack and AICL_KEY_DEMO).
- The tool presets need cloud-sim's demo script (`AICL_CLOUDSIM_SCRIPT=demo`, the compose default); T-123 added the `Show me the app settings` step (.env read).
- `aicl_gateway/names.py`: display name + one-line description per control and rule id (`GET /console/api/catalog`; rule names come from the loaded rule files,
  the policy's TOOL-01 rules and a built-in table; an unnamed id gets a readable fallback). Ids and the audit are unchanged. Shown in the live feed, the explain
  drawer + timeline, Protections, top rules and a 'What the ids mean' card on the Policy page.
- `detection_layer` (`deterministic` | `ai`): INJ-04 (classifier, kNN, judge) is `ai`, everything else `deterministic`; a record's layer is the layer of the enforced
  finding(s) at its action (tie: deterministic), null for a clean request. The audit contract has no such field (AuditRecord forbids extra keys), so the console derives it:
  it is on the live feed, the SSE stream and the exports, NOT in the audit JSONL on disk. Requested from the lead: `[lead] contracts: AuditRecord.detection_layer`.
- No new case files: T-123 adds no control behaviour (every control keeps its allowed + blocked cases); the presets are pinned in `tests/test_demo_batch.py`.

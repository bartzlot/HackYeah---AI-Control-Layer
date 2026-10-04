# policy/ - how to edit the policy live

Files:
- `policy.yaml` - the whole control catalog (profiles, agents, destinations, matrix, controls, budgets, loop limits).
- `rules/historical.yaml` - signature rules for INJ-03, each with inline `match` / `no_match` test strings.
- `local.d/*.yaml` - optional overlays merged over policy.yaml in file-name order (put live demo edits here).

Live editing:
1. Edit and save `policy.yaml` (or drop a file into `local.d/`). The gateway polls and reloads in about 1 s.
2. An invalid edit is rejected and the last good policy stays active; the dashboard shows the error.
3. Every decision carries `policy_version` (sha256 of the file), so you can see which edit applied.

Common live edits:
- Switch a control: `controls.<ID>.mode: enforce | shadow | off`. shadow logs the would-be decision only.
- Strictness: `defaults.profile` or `agents.<id>.profile` (strict | balanced | permissive). Thresholds are in `profiles`.
- PII action: `profiles.<p>.pii` (REDACT, BLOCK or LOG per profile).
- Flip a matrix cell: `destination_matrix.<data_level>.<destination>` (ALLOW | REDACT | REQUIRE_APPROVAL | BLOCK).
- Allow a tool for an agent: add it to `agents.<id>.tools` and check `controls.TOOL-01.rules`.
- Budgets: `budgets.agents.<id>`; loop limit: `loop_limits.repeat_identical` (4 = the 4th identical call is blocked).
- Kill switch: `emergency.kill_switch: true`.

Interception (v4, sections 9 and 10, design in `research/14-transparent-interception.md`):
- `interception.mode`: off | base_url | transparent. `credentials: passthrough` forwards the client's own key.
- `interception.providers.<name>`: `hosts` (Host / SNI names answered by the AICL DNS), `protocol`
  (anthropic_messages | openai_responses | openai_chat), `upstream`, `inspect` (paths parsed and decided; every
  other path is proxied unless `proxy_other_paths: false`).
- `interception.block_style.<protocol>`: how a hard block, a soft block and a budget stop look to the client.
- `interception.dns`: gateway_ip, upstream resolvers, `doh_sinkhole` (DoH names answered NXDOMAIN + alert).
- `clients`: first match wins on `cidr`, `key_sha256_prefix`, `user_agent` glob or `any`; `principal` is the id
  for `budgets.agents.<principal>`, audit and the dashboard; `models` globs restrict what the client may call.
- Real provider models are listed in `destinations.models` with prices; a model matching only a glob is unpriced
  and `budgets.unpriced_model` decides.

Notes: use ASCII hyphens only; synthetic secrets and PII only; loaders must read the word off as a string (ruamel.yaml, YAML 1.2).

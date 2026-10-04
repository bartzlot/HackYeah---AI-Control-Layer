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

Planned (v4, `research/14-transparent-interception.md` section 4): `interception:` (intercepted hosts per provider, DNS, TLS, per-protocol block styles) and `clients:` (identity of passthrough clients by address or key fingerprint). The lead lands the structure; until then these keys are not read.

Notes: use ASCII hyphens only; synthetic secrets and PII only; loaders must read the word off as a string (ruamel.yaml, YAML 1.2).

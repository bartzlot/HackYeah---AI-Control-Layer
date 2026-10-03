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

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

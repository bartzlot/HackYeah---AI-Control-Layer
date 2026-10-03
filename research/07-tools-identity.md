# 07 - Tool-call security and agent identity: how do we authorize what an agent may do, and how do we know which human, app and agent chain is acting?

Verified 2026-10-03 against primary sources.
Legend: `[EST]` established technique, `[EXP]` experimental / research-grade, `[REC]` our architectural recommendation, `[INFERENCE]` reasoning not read anywhere, `[MEASURED]` run locally today (venv `/tmp/aicl-tools`, CPython 3.14.8, macOS arm64; sqlglot 30.21.0, jsonschema 4.26.0, PyJWT 2.15.1, cryptography 50.0.2, tenuo 0.3.2; biscuit-python 0.4.0 on CPython 3.13.16).

Revisions used: MCP **2026-07-28** (latest, [versioning](https://modelcontextprotocol.io/specification/versioning)); A2A **v1.0.1** ([spec](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)); OWASP Top 10 for Agentic Applications **2026** (ASI01-ASI10); OWASP LLM Top 10 **2025**; RFC 8693; W3C Trace Context REC 2021-11-23; W3C Baggage CR 2024-05-30. Reused from the team's earlier notes: `05-budget-identity.md` (identity tiers, approvals table), `01-threats-controls.md` (TOOL-01..05, MCP-01..03, A2A-01, EXF-04). IDs `IDN-*`, `BRK-*` below are new proposals.

---

## 1. Tool-call interception points: which is authoritative, which is early warning?

The deciding question is "where can the agent NOT route around us", not "where can we see the call" `[REC]`.

| Point | Pros | Cons | Role |
|---|---|---|---|
| (a) `tool_calls` in the LLM response | no agent change; block before any code runs; feeds loop ring, taint, intent drift (TOOL-04/05, EXF-04) | only a **proposal**: agent may not run it, may edit args, or may call tools without an LLM; streamed calls arrive in chunks ([Ollama](https://github.com/ollama/ollama/blob/main/docs/capabilities/tool-calling.mdx)); no `tool_choice` in Ollama's OpenAI-compat layer ([compat](https://github.com/ollama/ollama/blob/main/docs/api/openai-compatibility.mdx)) | **early warning** |
| (b) MCP `tools/call` / A2A skill call at the gateway | exact final args, authenticated caller; unskippable **if the gateway holds the upstream credentials and network path** (Q4); MCP: servers MUST validate inputs, enforce access control, rate limit ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)); OWASP "complete mediation" ([LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)) | MCP/A2A only; agent-launched stdio servers are invisible; MCP 2026-07-28 dropped `Mcp-Session-Id`, so we mint our own session id (05) | **authoritative** |
| (c) SDK `secure_tool.execute()` | covers non-MCP tools; rich local context | runs in the untrusted process; a hijacked agent imports the raw function | UX only, unless it POSTs to the gateway (`/v1/tools/call`) |
| (d) HTTP egress (Docker `internal` net + egress proxy) | catches unmodelled tools (shell `curl`); MCP BP recommends an egress proxy such as [Smokescreen](https://github.com/stripe/smokescreen) (MIT, v0.1.0 2026-09-21) | bytes not intent; TLS needs CONNECT-only allowlist or MITM CA | **backstop**: destination allowlist only |

`[REC]` (b) is authoritative: one `decide(call, identity, session)` that (c) also reaches. (a) is early warning: cheap checks and block only TOOL-02-class payloads. (d) is the backstop. `[INFERENCE]` With credentials and network only behind (b), a bypassing tool cannot authenticate or reach out. Cross-check: at (a) store `proposal_id = sha256(session|tool|JCS(args))`; at (b) an unseen proposal gets flag `unproposed_call` (alert only; scripted steps skip the LLM) `[INFERENCE]`.

Pipeline at (b):
```
authN -> impersonation check -> kill switch/epoch -> session limits (depth, steps, spawn) -> tool allowed (RBAC)
 -> JSON Schema -> validators (ABAC) -> taint rule (EXF-04) -> risk -> approval gate -> rate/budget reserve
 -> credential injection -> forward -> result scan (INJ-06, secrets) -> audit
```
`[MEASURED]` JSON Schema 7 us, shell check 4.5 us, JWT verify 0.05 ms, SQL parse+walk 0.18 ms p50 / 0.32 ms p95; `[INFERENCE]` under 1 ms in-process.

---

## 2. Authorization inputs and argument validation

**Inputs** `[REC]`: tool, args (from the JSON-RPC **body**), caller (`user_id`, `user_assurance`, `app_id`), agent (`agent_id`, `parent_agent_id`, `depth`, roles), session (`session_id`, `tainted`, `steps`), action, resource, destination, risk. `risk/action/resource/destination` come from **our tool catalogue** (MCP annotations are untrusted, [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)); `user/agent/app` only from the verified credential ("Servers MUST NOT rely on client-provided user identification", [elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)).

Libraries (checked 2026-10-03; pure Python, so 3.13/3.14 and macOS arm64 are not an issue):
- [jsonschema](https://github.com/python-jsonschema/jsonschema) MIT 4.26.0 (2026-01-07), classifiers 3.13/3.14: **use**, Draft 2020-12 (MCP allows any 2020-12 keywords, [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)).
- [sqlglot](https://github.com/tobymao/sqlglot) MIT 30.21.0 (2026-09-30), pushed 2026-10-02: **use**. Stdlib `shlex`, `ipaddress`, `socket`, `os.path`, `email.utils`: **use**.
- [bashlex](https://github.com/idank/bashlex) **GPLv3+** 0.18 (2023-01-18), stale: **NOT RECOMMENDED** -> metachar deny + argv allowlist. [sqlparse](https://github.com/andialbrecht/sqlparse) 0.6.0 (licence not read): skip, no AST.

### 2.1 SQL (sqlglot) `[MEASURED]`
One statement; root SELECT/UNION/WITH...SELECT; no DML/DDL node anywhere; function denylist; table allowlist; parse failure = deny; use the **target engine's dialect**.
```python
BAD = (exp.Drop, exp.TruncateTable, exp.Alter, exp.Create, exp.Insert, exp.Update, exp.Delete,
       exp.Merge, exp.Command, exp.Copy, exp.Grant, exp.Set, exp.Into, exp.LoadData)
# parse(read=dialect) -> exactly 1 stmt -> root in (Select, Union, Subquery, With) -> for n in root.walk():
#   isinstance(n, BAD) -> DENY;  exp.Anonymous name in DENY_FUNCS -> DENY;  exp.Table not in allowlist -> DENY
DENY_FUNCS = {"pg_read_file","pg_read_binary_file","lo_import","lo_export","pg_ls_dir","dblink","dblink_exec","load_file","pg_sleep","sleep","xp_cmdshell"}
```
Measured (postgres): `SELECT count(*) FROM orders` ALLOW; `SELECT 1; DROP TABLE users` DENY multi_statement(2); `DROP/TRUNCATE/DELETE/UPDATE`, `SELECT * INTO`, `COPY ... TO PROGRAM` DENY; `WITH x AS (DELETE ... RETURNING *) SELECT ...` DENY node=Delete; `EXPLAIN ANALYZE DELETE`, `CALL`, `SET ROLE`, `VACUUM` fall back to `Command` -> DENY (unknown syntax **fails closed**); `... -- ; DROP TABLE t` ALLOW (comment). The node check alone ALLOWED `pg_read_file('/etc/passwd')`, `lo_import`, `dblink`, `pg_sleep(100)` (denied once the function denylist was added) and `UNION SELECT password FROM users` (needs the table allowlist). `DELETE ... WHERE 1=1` passes any "has WHERE" check: route DML to approval.

**Parser differential `[MEASURED]`**: with `read="mysql"`, `SELECT 1 /*!50000 ; DROP TABLE t*/` parses as ONE `Select` (versioned comment treated as a comment) but MySQL executes the body. Reject `/*!`, and give the tool a **read-only DB role** (LLM06: enforce via DB permissions of the extension's identity, [LLM06](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)). Validator = defense in depth, grant = the control. Latency: 151-char JOIN query, 300 runs, p50 0.18 ms, p95 0.32 ms, max 0.85 ms.

### 2.2 Shell `[MEASURED]`
Do not understand shell: argv-style only. Reject metacharacters, `shlex.split`, binary allowlist, per-binary flag allowlist, sensitive-path regex.
```python
META = re.compile(r'[;&|`$<>(){}\n\\*?~!#]')
ALLOW = {"ls":{"-l","-a","-la"}, "cat":set(), "grep":{"-n","-i","-e"}, "git":{"status","log","diff","--oneline","-n"}, "wc":{"-l"}}
SENSITIVE = re.compile(r'(^|/)(\.ssh|\.aws|\.env|id_rsa|\.git/config|passwd|shadow)(/|$)')
```
4.5 us/call. ALLOW: `ls -la /workspace`, `git status`, `git log --oneline -n 5`. DENY: `curl ... | sh`, `ls; id`, `echo $(id)`, reverse shell `bash -i >& /dev/tcp/...`, `cat$IFS/etc/passwd` (metachar); `rm -rf /`, `nc -e`, `python3 -c` (binary); `git -c core.sshCommand=id`, `git log --output=/tmp/x` (flag); `cat ~/.aws/credentials` (sensitive). `shlex.split("cat$IFS/etc/passwd")` returns **one token**, so tokenizer-only checks miss `$IFS`. Same bug class as [CVE-2025-66032](https://nvd.nist.gov/vuln/detail/CVE-2025-66032) (NVD: Claude Code < 1.0.93, "$IFS and short CLI flags" bypassed read-only validation, CVSS 9.8). Cost: `grep -rn` (combined short flags) is denied; list the combined forms you need. Keep regex signatures (`curl|wget ... | sh`, `/dev/tcp/`, `nc ... -e`, `rm -rf /`) as a feed-updatable second layer (04), not the control.

### 2.3 Paths `[MEASURED]`
`os.path.realpath` + `commonpath` against roots that were themselves `realpath`-ed (macOS `/tmp` is `/private/tmp`); reject NUL; open the canonical path with `O_NOFOLLOW` to narrow the check-then-open race `[INFERENCE]`.
Sketch: `rp = os.path.realpath(p, strict=os.path.ALLOW_MISSING)` (present on 3.14.8, for write targets); ALLOW iff `os.path.commonpath([rp, root]) == root` for some root. Tree `ws/`, `ws-evil/`, `secret/`, `ws/link -> ../secret`: `ws/a.txt`, `ws/new.txt` ALLOW; `ws/../secret/k`, `ws/link/k`, `ws-evil/x`, NUL DENY; a naive `startswith("/tmp/pv/ws")` passed all three attacks. Real bugs in the MCP Filesystem server: [CVE-2025-53109](https://nvd.nist.gov/vuln/detail/CVE-2025-53109) (symlinks) and [CVE-2025-53110](https://nvd.nist.gov/vuln/detail/CVE-2025-53110) (prefix match), both CVSS 7.3. `[MEASURED]` tenuo `Pattern("/data/*")` **allowed** `/data/../etc/passwd` (string glob); `Subpath("/data")` denied it.

### 2.4 URLs / SSRF `[MEASURED]`
Order: scheme allowlist (https; http loopback dev only) -> no userinfo -> host allowlist (exact or `.suffix`) -> **`socket.getaddrinfo`** (the client's resolver) -> check every address -> connect to the vetted IP with original Host/SNI -> redirects off, revalidate each hop -> size/time caps. MCP BP: block private, loopback, link-local (169.254/16), fc00::/7, fe80::/10; validate redirects; egress proxy; pin DNS between check and use (TOCTOU) ([BP](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)). Measured:
- `ipaddress.ip_address` **rejects** `0177.0.0.1`, `2130706433`, `0x7f.1`, but `getaddrinfo` resolves `2130706433` and `0x7f.1` to `127.0.0.1`. Validate resolved addresses, never the host string.
- `is_global` is False for 127/8, 10/8, 169.254/16, 100.64/10, fd00::/8, fe80::/10 and mapped `::ffff:169.254.169.254`, but **True** for NAT64 `64:ff9b::a9fe:a9fe`, IPv4-compatible `::a9fe:a9fe` and multicast `ff02::1`.
```python
NAT64 = ipaddress.ip_network("64:ff9b::/96")
def ip_ok(ip):
    ip = ipaddress.ip_address(ip)
    if ip.version == 6:
        if ip.ipv4_mapped: return ip_ok(ip.ipv4_mapped)
        if ip in NAT64:    return ip_ok(ipaddress.IPv4Address(int(ip) & 0xffffffff))
        if ip.sixtofour:   return ip_ok(ip.sixtofour)
        if ip.teredo or (int(ip) >> 32) == 0: return False
    return ip.is_global and not ip.is_multicast
```
Results: metadata IP, mapped, NAT64, `2130706433`, `0x7f.1`, `localhost`, `[fd00::1]`, `[2002:a9fe:a9fe::1]` DENY; `http://8.8.8.8/` DENY scheme; `user:pw@` DENY; `https://8.8.8.8/` ALLOW (pin). The httpx pinning transport is `[INFERENCE]`, not run. NOT RECOMMENDED FOR HACKATHON MVP: a custom pinning client per tool -> pin in one gateway `httpx` transport and use (d) for tools that make their own requests. A2A applies the same checks to webhooks ([A2A 13.2](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)).

### 2.5 Email, payments, JSON Schema
Email `[MEASURED]` (3.14.8 `email.utils` is lenient): `parseaddr('"ceo@acme.example" <evil@x.example>')` gives display name `ceo@acme.example` (spoof); `getaddresses(['a@acme.example, evil@x.example'])` yields **two** recipients; `'"a@acme.example"@evil.example'` returns the whole quoted string. Rules `[REC]`: reject CR/LF/NUL; one address per list item; no quotes in the local part; domain = text after the **last** `@`, lower-cased, exact or `.suffix` match (`acme.example.evil.example` fails); cap recipients incl. cc/bcc; attachments denied by default; external recipient after taint = deny (EXF-04).
Payments `[REC]`: integer minor units, currency enum, `amount <= per_call_max`, per-session cap (`counters` of 05), beneficiary allowlist, `idempotency_key`; above `approval_over` REQUIRE_APPROVAL; above hard max deny.
JSON Schema `[MEASURED]`: `Draft202012Validator` with `additionalProperties:false`, `maxLength`, `enum`, `minimum/maximum`: 7 us p50 / 8 us p95, LLM-readable messages. **`format` is not asserted by default** (`{"format":"email"}` accepted `"not-an-email"`): pass a `format_checker`.

### 2.6 Example rules (ABAC) `[REC]`
Dict operators, about 40 lines of Python, no `eval`, judge-editable. Precedence: **deny > approve > allow; default deny; evaluation error = deny**.
```yaml
rules:
  - {id: sql-readonly, tool: read_database, require: {validator: sql_select_only}, on_fail: deny}

  - {id: no-external-mail-after-untrusted-read, tool: send_email, when: {session.tainted: true},
     require: {args.to: {all_domains_in: [acme.example]}}, on_fail: deny}
  - {id: pay-over-limit, tool: transfer_funds, when: {args.amount: {gt: 50000}}, then: approve}
```

---

## 3. RBAC vs ABAC vs ReBAC vs capabilities

| Model | Fits agents when | Breaks when | Tooling (checked 2026-10-03) | MVP |
|---|---|---|---|---|
| **RBAC** | few agent types, static duties | role explosion; no "only this path/amount" | YAML; [pycasbin](https://github.com/apache/casbin-pycasbin) Apache-2.0 2.8.0 | **yes** |
| **ABAC** | arg constraints, taint, risk | policy sprawl | own evaluator; [cedarpy](https://github.com/k9securityio/cedar-py) Apache-2.0 4.12.1 (2026-09-24), macOS arm64 wheels cp311-cp314, unofficial; CEL [common-expression-language](https://pypi.org/project/common-expression-language/) Apache-2.0 0.10.0; agentgateway uses CEL ([repo](https://github.com/agentgateway/agentgateway) v1.6.0) | **yes**, own evaluator |
| **ReBAC** (Zanzibar) | many shared objects, inheritance | needs a service + tuple writes | [OpenFGA](https://github.com/openfga/openfga) Apache-2.0 v1.21.0 (2026-09-20), in-memory store "for development only"; [SpiceDB](https://github.com/authzed/spicedb) Apache-2.0 v1.56.2 (2026-09-11); SDKs openfga-sdk 0.10.5, authzed 1.25.0 | **no**. NOT RECOMMENDED FOR HACKATHON MVP -> `mem_ns` allowlist per agent (05) |
| **Capabilities** | delegation; child gets less; confused-deputy resistant | revocation (so short TTL); token growth | below | **yes, as JWT** |

Capability options:
- **Biscuit** (Datalog, public-key, offline attenuation): spec Apache-2.0 (v3.3, 2024-12-17); [biscuit-python](https://github.com/biscuit-auth/biscuit-python) Apache-2.0 0.4.0 (2025-09-26), wheels cp310-cp313 incl. macOS arm64, **no cp314 wheel** (`--only-binary` on 3.14 failed; sdist needs Rust, no `cargo` here, build killed at 240 s). `[MEASURED]` on 3.13: root token allowed `read_database` and `send_email`; after `append(BlockBuilder('check if operation($op), ["read_database"].contains($op);'))` the child allowed read and **denied** send; 0.065 ms/call, 472 B. Stretch.
- **Macaroons**: pymacaroons MIT 0.13.0 (2018-02-21), macaroonbakery LGPL-3.0. **NOT RECOMMENDED**: unmaintained.
- **Tenuo** (warrants, tool+arg constraints, holder-bound): Apache-2.0 0.3.2 (2026-10-03), 101 stars, `cp39-abi3-macosx_11_0_arm64` wheel installs on 3.14.8; `[MEASURED]` `@guard` 82 us/call. Its IETF draft is individual. Borrow the constraint checklist, do not depend on it.
- **Own gateway JWT with scope narrowing**: PyJWT MIT 2.15.1 (2026-09-28), 3.14 classifier. **MVP.**

`[INFERENCE]` Biscuit's edge is offline attenuation by the holder; every hop here passes the gateway, which mints the narrower child itself.

**Recommended** `[REC]`: RBAC roles per agent + ABAC on args/context (2.6) + attenuable 300 s capability (gateway JWT, scope only shrinks on exchange). Effective permission = role AND token scope AND validators. "Agent A: read_database allowed, delete_database forbidden, send_email requires approval":
```yaml
version: 7
defaults: {tools: deny, on_error: deny, approval_ttl_s: 300, token_ttl_s: 300, max_depth: 3}
tools:                     # risk/action come from HERE, never from MCP annotations
  read_database:   {server: pg,   action: read,   risk: low,      validators: [sql_select_only], credential: pg_ro}
  delete_database: {server: pg,   action: delete, risk: critical, credential: pg_admin}
  send_email:      {server: mail, action: send,   risk: high,     validators: [email_domains],   credential: smtp_acme}
  web.search:      {server: web,  action: read,   risk: low}
validators:
  sql_select_only: {type: sql, dialect: postgres, tables: [orders, products], deny_functions: [pg_read_file, lo_import, dblink, pg_sleep], reject_substrings: ["/*!"]}
  email_domains:   {type: email, allow_domains: [acme.example], max_recipients: 5, attachments: deny}

roles:
  analyst: {allow: [read_database, web.search]}
  mailer:  {allow: [send_email]}
agents:
  agent-a:
    roles: [analyst, mailer]
    allow:   [read_database, web.search]
    deny:    [delete_database]           # explicit deny beats every allow and every delegation
    approve: [send_email]                # REQUIRE_APPROVAL bound to (session, tool, args_hash)
    limits:  {max_calls: 50, max_children: 2, max_depth: 3, per_tool: {send_email: {calls_per_hour: 5}}}
    delegate: {may_spawn: [agent-b], scope_ceiling: [read_database]}

```
Outcome: `read_database(SELECT ...)` ALLOW; `delete_database(*)` DENY; `send_email(to=ops@acme.example)` REQUIRE_APPROVAL; `send_email(to=x@evil.example)` DENY **before** approval is offered (approval never waives a validator).

---

## 4. Short-lived capabilities: broker, per-task tokens, exchange, revocation

**Broker** `[REC]`: agents hold only a gateway credential (key, then 5-min JWT). Upstream secrets stay in the gateway (env / OS keychain for the demo) and are injected via the catalogue's `credential:` ref, so prompt injection cannot exfiltrate what the agent never sees (AIMS history: "Clarify that LLMs should not have access to Agent credentials", [AIMS](https://www.ietf.org/archive/id/draft-ietf-wimse-aims-00.txt)). **No token passthrough**: MCP servers "MUST NOT accept or transit any other tokens" and MUST validate audience ([authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)); upstream calls use the gateway's own credential with the upstream audience (RFC 8707 `resource`). Scan tool results for secrets (DLP-01). Per-user upstream tokens (RFC 8693) are not in the MVP: use a read-only service credential and record `on_behalf_of`.

**Per-task token** `[REC]`: TTL 300 s (K8s bound tokens default 1 h, [docs](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)); `scope` = `tool:<name>` strings; `aud` = canonical gateway URI; `max_calls` counted by `jti` (`UPDATE ... SET used=used+1 WHERE used<max`); `depth`/`max_depth`; stretch holder binding `cnf.jkt` + DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.txt)).

**Token exchange**: `POST /token`, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, RFC 8693 params (`subject_token`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt`, optional `actor_token`, `scope`, `audience`). Rules: `scope_child = requested ∩ scope_parent ∩ ceiling(child) ∩ role(child)`; `exp <= parent exp`; `depth+1`; `max_calls` and budget slice (05) <= parent's remaining. Violation: `400 invalid_scope` + alert `delegation_escalation`.

**Revocation / kill switch** `[REC]`: the gateway verifies in-process, so revocation is instant (no revocation-list lag).
Tables: `agent_epoch(agent_id PK, epoch INT DEFAULT 1, disabled INT DEFAULT 0)`, `denied_jti(jti PK, reason, ts)`, plus `sessions.state` in `active|halted|killed` (05). Token carries `ep`; mismatch or `disabled=1` -> 401 `revoked` (bumping the epoch revokes all of the agent's tokens). `state='killed'` on `root_session_id` refuses the whole subtree on its next call. Dashboard buttons kill agent / session tree; the loop breaker (05) trips the same state. Keep an in-memory mirror so the hot path never reads SQLite `[INFERENCE]`.

---

## 5. Human-in-the-loop REQUIRE_APPROVAL

**Record** `[REC]` (extends `approvals` of 05):
```sql
-- approvals(id PK, session_id, root_session_id, user_id, agent_id, tool, args_hash = sha256(JCS(args)),
--   args_canon (shown to the approver from HERE, not from agent text), risk, rule_id,
--   status IN (pending, approved, denied, expired, consumed, cancelled), requested_at, expires_at (+300 s),
--   decided_by, decided_at, consumed_at, consumed_request_id)
UPDATE approvals SET status='consumed', consumed_at=:now, consumed_request_id=:rid
 WHERE id=:id AND status='approved' AND expires_at>:now AND session_id=:s AND tool=:t AND args_hash=:h;  -- rowcount must be 1
```
Changed args change `args_hash` and need a new approval; dedupe on `(session, tool, args_hash)` so retries get the same pending id; cap pending approvals (3 per agent) against approval fatigue `[INFERENCE]`; approver differs from requester; **re-run deny rules and validators at consume time** (approval only satisfies the `approve` requirement); a killed session voids it.

**What the agent receives** `[REC]`: **hybrid**: hold up to `wait_ms` (default 20 000) so a live demo resolves in one call, then return a normal tool result the model can act on:
```json
{"isError": true, "structuredContent": {"status": "pending_approval", "approval_id": "apr_01J9...", "retry_after_s": 5,
  "expires_in_s": 280, "message": "send_email needs human approval. Retry the identical call; do not change arguments."}}
```
Identical retry: `approved` -> consume and run; `denied` -> `{"status":"denied"}`; `expired` -> new pending. Longer holds are risky `[INFERENCE]`: clients have tool timeouts ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)) and a held connection pins a worker. Later mapping: MCP 2026-07-28 `InputRequiredResult` ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)); A2A `TASK_STATE_AUTH_REQUIRED`, which is not authorization by itself ([A2A 7.6](https://github.com/a2aproject/A2A/blob/main/docs/specification.md)).

**Dashboard**: queue shows tool, agent, user, **gateway-rendered** args with risky fields highlighted, rule id, time left, Approve / Deny (admin-authenticated); every state change is an audit event with `approver`. Agent justification is labelled "agent-written, untrusted" (ASI09).

**MCP elicitation as a channel** ([spec](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)): form mode MUST NOT collect secrets; servers MUST bind elicitation to client and user identity; a documented phishing attack forwards a displayed third-party authorization URL to a victim. `[INFERENCE]` The prompt is ours but rendered by a client we do not control, and the person at the chat UI may be the injected user. AIMS 10.7: UI confirmation alone is not authorization, it "MUST be bound to a verifiable authorization grant" ([AIMS](https://www.ietf.org/archive/id/draft-ietf-wimse-aims-00.txt)). `[REC]` dashboard approval decides; elicitation at most notifies; MVP skips it.

---

## 6. Agent identity

| Mechanism | Proves | MVP |
|---|---|---|
| Opaque per-agent API key | secret possession | **Tier 0**: `acl_<agent>_<32B base64url>`, sha256 at rest (high-entropy, unsalted SHA-256 adequate `[EST]`), constant-time compare |
| OAuth 2.0 client credentials; OIDC (humans); mTLS | agent / human / channel | `/token` has the client-credentials shape ([MCP](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)); OIDC in production, MVP demo users `user_assurance: asserted`; mTLS skipped |
| JWT access token (RFC 9068, RFC 8725) | gateway-signed claims | **Tier 1**, alg pinned |
| SPIFFE/SPIRE | platform-attested workload id | [SPIRE](https://github.com/spiffe/spire) Apache-2.0 v1.15.3 (2026-08-21), release assets Linux/Windows only; [py-spiffe](https://github.com/HewlettPackard/py-spiffe) Apache-2.0 0.3.2. NOT RECOMMENDED FOR HACKATHON MVP -> gateway-issued identity; reserve `spiffe://...` as future `agent_id` |
| K8s projected SA tokens, cloud workload identity, DPoP/`cnf` | pod/cloud-bound or holder-bound short tokens | production / Tier 2 stretch |

JWT libs: [PyJWT](https://github.com/jpadilla/pyjwt) MIT 2.15.1 + [cryptography](https://pypi.org/project/cryptography/) 50.0.2 (Apache-2.0 OR BSD-3); alternatives joserfc / Authlib (BSD-3); **avoid** jwcrypto (LGPL-3.0-or-later). **EdDSA** (ES256 if A2A card signing shares the key), `algorithms=[...]` pinned, `require=["exp","aud","iss","jti"]`. `[MEASURED]` 2000 runs, 335 B token: EdDSA sign p50 0.018 ms / verify 0.049 ms; ES256 0.017 / 0.048 ms.

### 6.1 IETF / OpenID work (datatracker read 2026-10-03; `[EXP]`, none is an RFC)

- [draft-ietf-wimse-aims-00](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/) "AI Identity Management System" (2026-09-15), WIMSE WG, Active: agents are workloads; identifiers, credentials, OAuth authorization, Transaction Tokens (10.5), human in the loop via CIBA (10.7). Predecessor [draft-klrc-aiagent-auth-03](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) "AI Agent Authentication and Authorization" is state **Replaced**.
- OAuth WG, Active: [draft-ietf-oauth-transaction-tokens-11](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/), [draft-ietf-oauth-identity-chaining-17](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/), [draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (Cross-App Access).
- Individual drafts (no WG): [draft-ni-wimse-ai-agent-identity-03](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/) "WIMSE Applicability for AI Agents"; [draft-mw-oauth-actor-chain-01](https://datatracker.ietf.org/doc/draft-mw-oauth-actor-chain/) (verifiable `act` chains); [draft-niyikiza-oauth-attenuating-agent-tokens-01](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/); [draft-chen-oauth-agent-authz-use-cases-03](https://datatracker.ietf.org/doc/draft-chen-oauth-agent-authz-use-cases/); [draft-helixar-hdp-agentic-delegation-02](https://datatracker.ietf.org/doc/draft-helixar-hdp-agentic-delegation/); [draft-oauth-ai-agents-on-behalf-of-user-02](https://datatracker.ietf.org/doc/draft-oauth-ai-agents-on-behalf-of-user/) is **Expired**.
- OpenID Foundation whitepaper "Identity Management for Agentic AI" ([2025-10-07](https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/), [arXiv 2510.25819](https://arxiv.org/abs/2510.25819)): token-exchange delegation as building block (abstract-level read).

### 6.2 MVP identity `[REC]`
1. **Tier 0**: per-agent key bound to `(agent_id, app_id, owner)`; identity only from the key. Differing `X-Agent-Id`/`user`/body claims -> **403 `impersonation`** + audit + alert (05).
2. **Tier 1 (+2 h)**: `/token` (key -> EdDSA JWT 300 s; exchange for children). Header-vs-signed-claim mismatch (`X-Agent-Id`, `X-User-Id`, `X-Session-Id`) -> `impersonation`.
3. **Tier 2**: DPoP. **Production**: SPIFFE/WIMSE ids, Transaction Tokens, OIDC users, CIBA approvals.

Per AIMS 10.3 and RFC 8693, `sub` is the principal the work is for (the human, if any), the agent is the current actor in `act`; flat copies serve fast lookup. Header `{"alg":"EdDSA","typ":"at+jwt","kid":"gw-2026-10-a"}`:
```json
{"iss":"http://localhost:8080","aud":"http://localhost:8080/mcp",
 "sub":"user:u-1042","client_id":"app:support-portal",
 "act":{"sub":"agent:researcher","act":{"sub":"agent:orchestrator"}},
 "agent_id":"agent:researcher","parent_agent_id":"agent:orchestrator","user_assurance":"asserted",
 "session_id":"ses_01J9Z3K8M2Q7","root_session_id":"ses_01J9Z3K8M2Q7","task_id":"tsk_01J9Z3KC4R1X",
 "scope":"tool:read_database tool:web.search","max_calls":20,"depth":2,"max_depth":3,"max_children":0,
 "risk_max":"medium","ep":7,"iat":1790989200,"nbf":1790989200,"exp":1790989500,"jti":"01J9Z3KD0W5P8N2H6T4V"}
```
RFC 8693 4.1: a consumer "MUST only consider the token's top-level claims and the party identified as the current actor"; nested prior actors "are informational only" ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.txt)). So the `act` chain is for **audit**; authorization uses `scope`/`depth`/`max_*` narrowed at each exchange plus the gateway session table. Autonomous agent without a human: `sub = agent:...`, no `act`. RFC 8725: pin `alg`, reject `none`, require aud/iss/exp/jti, `kid` rotation.

---

## 7. Traceable identity chain

`human_user_id -> session_id -> application_id -> agent_id -> parent_agent_id -> tool_id -> request_id -> trace_id/span_id`

| Field | Source | Verified / trusted | Propagation |
|---|---|---|---|
| `user_id` | JWT `sub` (IdP ID token in production) | **verified** only if `user_assurance=verified`; `asserted` is recorded, never grants more than the agent's role | JWT, audit |
| `application_id`, `agent_id`, `parent_agent_id` | key binding; parent from parent token at exchange | verified (gateway-minted) | JWT `client_id`, `agent_id`, `act` |
| `session_id`, `root_session_id` | gateway-minted (MCP 2026-07-28 has none); client `x-acl-session` accepted only if it exists and belongs to the caller | verified | JWT; `X-AICL-Session` on LLM calls |
| `tool_id` | `server.tool` resolved from the catalogue (MCP-03) | verified | audit |
| `request_id` | gateway ULID | verified | `X-AICL-Request-Id`, audit, upstream `_meta` |
| `trace_id`, `span_id` | inbound `traceparent` or generated | **correlation only** (forgeable); never an authorization input; new span per hop | `traceparent`; MCP 2026-07-28 documents `traceparent`/`tracestate`/`baggage` in `_meta` (SEP-414, [changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)) |
| `baggage` | inbound | **untrusted**; strip inbound | W3C: may carry sensitive data, keep it out of requests crossing trust boundaries; 64 members / 8192 bytes ([Baggage](https://www.w3.org/TR/baggage/)) |

[Trace Context](https://www.w3.org/TR/trace-context/) security: cap header length, validate format. `[INFERENCE]` MVP writes `trace_id/span_id` into audit JSON and `/metrics`, no collector ([opentelemetry-api](https://pypi.org/project/opentelemetry-api/) 1.45.0 Apache-2.0).

Audit record (hash-chained JSONL, redacted args):
```json
{"event_id":"evt_01J9Z3KDE7M4","ts":"2026-10-03T10:41:07.412Z","type":"tool.call","decision":"REQUIRE_APPROVAL",
 "reasons":[{"rule_id":"agent-a.approve.send_email","control":"TOOL-03","owasp":["ASI02","ASI09","LLM06"]}],
 "identity":{"user_id":"user:u-1042","user_assurance":"asserted","application_id":"app:support-portal",
   "agent_id":"agent:writer","parent_agent_id":"agent:orchestrator",
   "delegation_chain":["user:u-1042","agent:orchestrator","agent:writer"],"depth":2,
   "credential":{"type":"jwt","jti":"01J9Z3KD0W5P8N2H6T4V","kid":"gw-2026-10-a","ep":7},"header_claims_match":true},
 "session":{"session_id":"ses_01J9Z3K8M2Q7","root_session_id":"ses_01J9Z3K8M2Q7","tainted":false,"step":7},
 "tool":{"tool_id":"mail.send_email","action":"send","risk":"high","destination":"smtp.acme.example:587"},
 "args_hash":"sha256:3b1f6c0e...","args_redacted":{"to":["ops@acme.example"],"subject":"Q3"},
 "validators":[{"id":"email_domains","result":"pass"}],
 "approval":{"id":"apr_01J9Z3KDF1","status":"pending","expires_at":"2026-10-03T10:46:07Z"},
 "request_id":"req_01J9Z3KDE2","trace_id":"4bf92f3577b34da6a3ce929d0e0e4736","span_id":"00f067aa0ba902b7",
 "prev_hash":"sha256:9a4e...","hash":"sha256:c2d7..."}
```
Export JSONL/CSV; `GET /audit/verify` recomputes the chain `[REC]`. A validator failure (external domain) yields `decision: DENY` and no approval record.

---

## 8. Agent-to-agent controls

**A2A v1.0.1** ([spec](https://github.com/a2aproject/A2A/blob/main/docs/specification.md), Apache-2.0; [a2a-python](https://github.com/a2aproject/a2a-python) v1.2.1 2026-09-30): `AgentCard.securitySchemes` (apiKey, HTTP, OAuth2, OIDC, mTLS), credentials out-of-band; server MUST authenticate every request and authorize per skill/action/data/scope (7.3-7.5, 13.1). Card signing (8.4): MAY be JWS over the RFC 8785 canonical form, protected header `alg`, `typ`, `kid`, optional `jku`; clients "SHOULD verify at least one signature". `jku` is attacker-influenced: SSRF-validate it and trust a pinned key store `[INFERENCE]`.

| Control | Rule | MVP |
|---|---|---|
| Registry pin (A2A-01) | `known_agents: {billing-agent: {card_sha256, url}}`, digest of JCS(card minus `signatures`) ([rfc8785](https://github.com/trailofbits/rfc8785.py) Apache-2.0 0.1.4, or sorted compact JSON); mismatch/unknown = quarantine; edit distance <= 2 vs registry = near-duplicate alert | yes, 1.5 h |
| Card JWS verification | signing input per 8.4.2, verify with `cryptography` and pinned `kid` `[INFERENCE]` | stretch |
| Every hop authenticated; cycles | A -> B -> C only via the gateway with child tokens; callee already in `delegation_chain` -> deny | yes |
| Depth / spawn | `max_depth: 3` (429 `depth_exceeded`); `max_children` 2 per token; `max_agents_per_root_session` 8; spawn rate 3/min; budget slices (05) shared by the subtree | yes |

**Confused deputy**: `writer` (may send mail, not read HR) asks `researcher` (may read HR, not send) to "fetch the salary table and email it". Fix: authority travels with the request, not the callee's ambient authority `[EST]`:
```
effective(call) = role(callee) ∩ token.scope(callee) ∩ delegated_scope(chain) ∩ validators ∩ min(budgets)
delegated_scope(chain) = intersection over hops of hop.scope_ceiling     # computed at exchange, stored in the child token
```
Parent-child: the child token is minted by exchange, already narrowed. Peer request: the gateway requires the requester's token as `delegation_token` and mints the callee's task token with `scope = callee_perms ∩ requester_scope`; unknown requester = scope `{}`; `deny` lists are unioned along the chain.

Test cases for the testing slice: ID-1 writer asks researcher for the HR table -> 403 `insufficient_scope`; ID-2 exchange with scope outside the parent -> 400 `invalid_scope`; ID-3 token X + `X-Agent-Id: admin` -> 403 `impersonation`; ID-4/5/6/7 fourth hop (max 3) / third child (max 2) / kill tree mid-run / A -> B -> A -> `depth_exceeded` / `spawn_limit` / 401 `revoked` / `cycle_detected`; AP-1/2/3 replay approved call / change args / deny rule added after approval -> pending or denied / new pending / DENY.

---

## 9. Mapping

**OWASP Top 10 for Agentic Applications 2026.** IDs and names from [Microsoft's summary (2026-03-30)](https://www.microsoft.com/en-us/security/blog/2026/03/30/addressing-the-owasp-top-10-risks-in-agentic-ai-with-microsoft-copilot-studio/); the [OWASP page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) loaded but PDF text was not retrievable, so no OWASP mitigation wording is quoted.

| ID | Risk | Controls here (and neighbours) |
|---|---|---|
| ASI01 | Agent Goal Hijack | (a) analytics, `unproposed_call`, EXF-04 taint, TOOL-05 loops; text detection in 01/03 |
| ASI02 | Tool Misuse and Exploitation | (b) allowlist, schema, validators, risk-gated approval, per-tool rate (TOOL-01/02/03) |
| ASI03 | Identity and Privilege Abuse | keys, gateway JWT, `act` chain, scope narrowing, intersection rule, credential broker, kill switch, impersonation check (IDN-01..04, BRK-01) |
| ASI04 | Agentic Supply Chain | MCP-01/02/03 pins, A2A-01 digest, catalogue as sole source of risk (04) |
| ASI05 | Unexpected Code Execution | shell/SQL/path validators; isolation is outside the gateway |
| ASI06 | Memory and Context Poisoning | not this slice; `mem_ns` (05) |
| ASI07 | Insecure Inter-Agent Communication | every hop via gateway, token exchange, card pin/JWS, SSRF-checked webhooks and `jku` |
| ASI08 | Cascading Failures | `max_depth`, `max_children`, subtree budget and kill, loop breaker |
| ASI09 | Human-Agent Trust Exploitation | out-of-band dashboard, gateway-rendered args, args-bound single-use approval, pending cap |
| ASI10 | Rogue Agents | kill switch, epoch revocation, call-rate EWMA (05), agent registry, audit chain |

LLM Top 10 2025 anchor: [LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) (minimize extensions/permissions, user context, approval, complete mediation); LLM10 (05).

**MCP authorization 2026-07-28** ([authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [BP](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices)):

| Requirement | Level | Our status |
|---|---|---|
| Authorization OPTIONAL; HTTP SHOULD follow; stdio SHOULD NOT | - | HTTP follows; stdio only as gateway-spawned subprocess with injected env |
| Server = OAuth 2.1 resource server; RFC 9728 PRM; AS metadata (RFC 8414/OIDC) | MUST | static PRM + minimal AS metadata; auth-code + PKCE **not built** (agents use client credentials, humans the dashboard): declared gap |
| Client sends RFC 8707 `resource`; server validates audience, MUST NOT accept or transit other tokens | MUST | `aud` check, no passthrough |
| Bearer in `Authorization`, never the query; 401 invalid/expired | MUST | enforced |
| 403 `insufficient_scope` + `WWW-Authenticate` with all scopes; scope minimization | SHOULD | out-of-scope tools; argument-level denials are tool results `[REC]`; per-task `tool:*` scopes |
| CIMD SHOULD, DCR deprecated, RFC 9207 `iss` check | SHOULD / client MUST | not built / N/A (no auth-code flow): gap |



---

## Inconsistent

| Topic | Side 1 | Side 2 / resolution |
|---|---|---|
| Hand-rolled IP validation | MCP [BP](https://modelcontextprotocol.io/specification/2026-07-28/basic/security_best_practices): "Avoid implementing IP validation manually" | `[MEASURED]` stdlib `is_global` is wrong for NAT64, IPv4-compatible, multicast. Validate resolved addresses with explicit unwrapping; egress proxy is the real control |
| Who confirms | MCP [tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools): client UI SHOULD confirm | [AIMS](https://www.ietf.org/archive/id/draft-ietf-wimse-aims-00.txt) 10.7: UI confirmation alone is not authorization. Gateway = decision point, dashboard decision = grant |
| Human in `sub` | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.txt): `sub` subject, `act` actor | AIMS 10.3: user in `sub`, agent as `client_id`. We carry both |


## Could not establish

- Primary OWASP Agentic Top 10 text (PDF not retrievable); IDs/names from Microsoft's summary.
- Whether AIMS-00 formally replaces klrc (inferred from document history).
- Whether `a2a-sdk` 1.2.1 verifies agent-card signatures; latency of OpenFGA/SpiceDB/Cedar/CEL (not measured, not used).
- biscuit-python on 3.14: no wheel, no Rust toolchain here; not proven impossible.
- Real MCP client behaviour on 20 s held calls and `isError` pending results; SPIRE natively on macOS (assets list Linux/Windows only); `email.utils.getaddresses(strict=...)` behaviour on the quoted-local-part trick.

## Recommendation for the MVP `[REC]`

About **18 h** for this slice alone.

- Interception (3 h): (b) one `decide()` for MCP `tools/call`, A2A and SDK `/v1/tools/call`; (a) `tool_calls` parse for early warning/taint/`unproposed_call`; (d) Docker `internal` network + allowlist egress.
- Policy (2 h): Q3 YAML, default deny, deny > approve > allow, fail closed.
- Validators (5 h): jsonschema 2020-12 + `format_checker`; sqlglot SELECT-only + function denylist + table allowlist + `/*!` reject; shlex argv allowlist + metachar deny; realpath+commonpath; URL guard; email suffix check; payment caps.
- Identity (3 h): Tier 0 key + Tier 1 `/token` EdDSA 300 s with the 6.2 claims; exchange narrows scope, `depth+1`, `max_calls`; 403 `impersonation`.
- Broker + kill switch (1.5 h): secrets only in gateway env; `agent_epoch`, session `killed`, dashboard buttons.
- Approvals (2.5 h): Q5 table, atomic consume, 20 s hold then pending, re-evaluate at consume.
- Chain + audit (1.5 h): hash-chained JSONL, `traceparent` correlation, baggage stripped, `/audit/verify`.
- A2A (2 h): digest pin, near-duplicate check, depth/spawn/cycle, intersection at exchange.
- Tests (2 h): ID-1..7, AP-1..3 + Q2 tables (offline, deterministic).

Cut first: A2A card JWS, DPoP/`cnf`, egress container (keep validators), `unproposed_call`, PRM/AS metadata endpoints.

NOT RECOMMENDED FOR HACKATHON MVP (alternatives inline above): OpenFGA/SpiceDB, SPIFFE/SPIRE, Biscuit, Tenuo, OAuth 2.1 auth-code + PKCE + CIMD, an LLM judge on every call, elicitation as approval channel.

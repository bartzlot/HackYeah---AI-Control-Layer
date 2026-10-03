# 11 - Policy, observability and dashboard: what does the central policy look like, how does it hot-reload, which engine do we use, and what do security and management see?

Verified 2026-10-03 against primary sources.
[EST] established technique; [EXP] experimental / research-grade; [REC] architectural recommendation; [INFERENCE] reasoning not read anywhere; [MEASURED] run locally today, versions and sizes stated.

Scope: agent/LLM/MCP gateway, not employee browser interception. Prior files 02, 06 and sections 8/10 of 07 were read first. Designs below are proposals, not existing gateway functionality. No Ollama models were called, pulled or loaded. Source versions are snapshots checked today; numerical targets are not measured guarantees.

## 1. Complete policy schema

[REC] Data levels are ordered and classification takes the maximum across prompt, tool results and memory. Permission intersects destination matrix/maximum, caller clearance, authenticated parent capabilities and model/tool allowlists. Delegation intersects rather than expands rights. Unknown authorization fails closed. Missing optional controls are off (judge deletion works); missing mandatory envelope sections invalidate the file. Keep deleted controls in the expected-control registry for posture/tests.

Verdict precedence: BLOCK > REQUIRE_APPROVAL > ALLOW. REDACT transforms then reclassifies the forwarded payload; unsafe removal blocks. WARN/LOG annotate. Shadow mode logs would_decision without transforming or holding. Approval holds side effects, binds identity/destination/arguments/version, expires and rechecks the current policy. Adherence is a strictness dial, not measured accuracy. Profile thresholds are uncalibrated defaults; explicit control settings override them.

[REC] This is a complete proposed configuration, with demonstration identities, model prices and paths. Simulated commercial prices and local equivalents are assumptions, not current vendor quotations. Pin hashes and authentication digests below are illustrative and must be generated from the actual demo server definitions/keys. An Ed25519 public key is provisioned outside the YAML; judge-editable local overrides are NOT treated as a signed remote feed.

| Control mode | Detection | Actual effect | Telemetry |
|---|---|---|---|
| enforce | run | findings may block/redact/hold | actual decision + all findings |
| monitor / shadow | run | ALLOW, no redaction or hold | would_decision + shadow=true |
| off | do not run | no effect | policy change records that it was removed/disabled |

```yaml
# yaml-language-server: $schema=./policy.schema.json
version: aicl-policy/1
metadata:
  name: hackyeah-demo
  owner: secops@example.org
  description: Gateway policy for agents, LLMs, MCP servers and tools
# ---------- 1. global behaviour ----------
defaults:
  profile: balanced
  mode: enforce
  fail: closed
  block_response: refusal_200
  max_body_kb: 512
  request_timeout_ms: 30000
emergency:
  kill_switch: false
  deny_agents: []
profiles: # adherence is a strictness dial, not measured recall
  strict:     {adherence_pct: 90, default_semantic_block: 0.35}
  balanced:   {adherence_pct: 60, default_semantic_block: 0.60}
  permissive: {adherence_pct: 20, default_semantic_block: 0.85}
# ---------- 2. taxonomy: tags used in events and dashboard ----------
taxonomy:
  injection:  {owasp_llm_2026: [LLM01], owasp_asi_2026: [ASI01], atlas: [AML.T0051]}
  jailbreak:  {owasp_llm_2026: [LLM01], atlas: [AML.T0054]}
  pii_leak:   {owasp_llm_2026: [LLM02], atlas: [AML.T0057]}
  secret_leak: {owasp_llm_2026: [LLM02], atlas: [AML.T0057]}
  tool_abuse: {owasp_llm_2026: [LLM03], owasp_asi_2026: [ASI02], atlas: [AML.T0053, AML.T0086]}
  tool_poisoning: {owasp_llm_2026: [LLM04], atlas: [AML.T0110, AML.T0109]}
  supply_chain: {owasp_llm_2026: [LLM04], atlas: [AML.T0010, AML.T0011]}
  memory_poison: {owasp_llm_2026: [LLM05], atlas: [AML.T0080]}
  resource:   {owasp_llm_2026: [LLM06], atlas: [AML.T0034, AML.T0034.002]}
  prompt_leak: {owasp_llm_2026: [LLM08]}
  output_handling: {owasp_llm_2026: [LLM10]}
# ---------- 3. identities ----------
identities:
  auth:
    mode: api_key
    header: Authorization
    unknown: {profile: strict, clearance: public, budget: anon}
  roles:
    analyst:   {tools: [read_file, search_docs], max_data_level: confidential}
    operator:  {tools: [read_file, write_file, send_email], max_data_level: confidential}
  users:
    alice: {roles: [analyst], clearance: confidential, department: finance}
    bob:   {roles: [operator], clearance: internal, department: engineering, profile: balanced}
  apps:
    opencode:    {key_sha256: "sha256:9999999999999999999999999999999999999999999999999999999999999999", owner: bob, profile: balanced, clearance: internal}
    finance-ui:  {key_sha256: "sha256:4444444444444444444444444444444444444444444444444444444444444444", owner: alice, profile: strict, clearance: confidential}
  agents:
    planner:     {app: opencode, parent: null, roles: [operator], capabilities: [delegate], max_children: 3, max_depth: 2}
    mailer:      {app: opencode, parent: planner, roles: [operator], capabilities: [send_email], clearance: internal}
    researcher:  {app: finance-ui, parent: null, roles: [analyst], capabilities: [web_fetch]}
  delegation:
    inherit: intersect
    max_depth: 3
# ---------- 4. data classification ----------
data_levels: [public, internal, confidential, restricted]
classification:
  pii.email: internal
  pii.pesel: confidential
  pii.iban: confidential
  pii.card: restricted
  secret.any: restricted
  canary.any: restricted
  marking.confidential: confidential
# ---------- 5. destinations ----------
trust_tiers: [local, internal, partner, external, untrusted]
destinations:
  models:
    "ollama/qwen3.5:4b":    {provider: ollama,   trust: local,    max_data_level: restricted,   price: {in_usd_per_mtok: 0.0, out_usd_per_mtok: 0.0, equiv_in: 0.05, equiv_out: 0.10}}
    "ollama/qwen3.5:9b":    {provider: ollama,   trust: local,    max_data_level: restricted,   price: {in_usd_per_mtok: 0.0, out_usd_per_mtok: 0.0, equiv_in: 0.08, equiv_out: 0.16}}
    "sim/gpt-4o-mini":      {provider: sim-commercial, trust: external, max_data_level: internal, price: {in_usd_per_mtok: 0.15, out_usd_per_mtok: 0.60}}
  model_allowlist:
    default: ["ollama/qwen3.5:4b"]
    roles: {analyst: ["ollama/qwen3.5:4b", "ollama/qwen3.5:9b"], operator: ["ollama/qwen3.5:4b", "sim/gpt-4o-mini"]}
  mcp_servers:
    fs:      {url: "http://127.0.0.1:9101/mcp", trust: internal, max_data_level: confidential,
              pin: {mode: pinned, on_drift: block, tools: {read_file: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", write_file: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}
    mail:    {url: "http://127.0.0.1:9102/mcp", trust: external, max_data_level: internal,
              pin: {mode: tofu, on_drift: require_approval}}
  apis:
    "api.github.com":  {trust: partner,  max_data_level: internal}
    "*":                {trust: untrusted, max_data_level: public}
destination_matrix: # missing cell BLOCK; intersect destination max and identity clearance
  public:       {local: ALLOW, internal: ALLOW, partner: ALLOW, external: ALLOW, untrusted: ALLOW}
  internal:     {local: ALLOW, internal: ALLOW, partner: ALLOW, external: REDACT, untrusted: BLOCK}
  confidential: {local: ALLOW, internal: ALLOW, partner: REQUIRE_APPROVAL, external: BLOCK, untrusted: BLOCK}
  restricted:   {local: ALLOW, internal: REQUIRE_APPROVAL, partner: BLOCK, external: BLOCK, untrusted: BLOCK}
# ---------- 6. controls: omitted mode/fail inherit defaults ----------
controls:
  CTRL-ID-AUTH:       {mode: enforce, fail: closed, tag: tool_abuse, severity: high}
  CTRL-MODEL-ALLOW:   {mode: enforce, fail: closed, tag: resource, severity: medium, on_violation: BLOCK}
  CTRL-DLP-PII:
    mode: {strict: enforce, balanced: enforce, permissive: monitor}
    tag: pii_leak
    severity: high
    stages: [prompt, tool_args, tool_result, response]
    entities:
      PESEL:  {action: REDACT, validate: checksum}
      IBAN_PL: {action: REDACT, validate: mod97}
      CREDIT_CARD: {action: BLOCK, validate: luhn}
      EMAIL:  {action: {strict: REDACT, balanced: LOG, permissive: LOG}}
    redaction: {style: placeholder, placeholder: "[{entity}]", reversible: false}
  CTRL-DLP-SECRETS:
    tag: secret_leak
    severity: critical
    stages: [prompt, tool_args, tool_result, response]
    action: {strict: BLOCK, balanced: BLOCK, permissive: REDACT}
    rules: {source: feed:signatures, include: [aws_key, gh_token, private_key, generic_high_entropy], entropy_min: 4.2}
  CTRL-INJ-SIG:       {mode: enforce, fail: closed, tag: injection, severity: high, source: feed:signatures, action: BLOCK, normalize: [nfkc, strip_zero_width, decode_b64, decode_url]}
  CTRL-INJ-SEM:
    mode: {strict: enforce, balanced: enforce, permissive: monitor}
    fail: degrade
    timeout_ms: 80
    tag: injection
    severity: high
    threshold: {block: auto, warn: 0.25}
    judge: {enabled: false, model: "ollama/qwen3.5:4b", gray_band: [0.30, 0.60], timeout_ms: 1500, on_timeout: warn}
  CTRL-JAILBREAK:     {mode: enforce, fail: degrade, tag: jailbreak, severity: high, threshold: {block: {strict: 0.35, balanced: 0.60, permissive: 0.85}, warn: 0.30}}
  CTRL-SYSPROMPT-LEAK:
    tag: prompt_leak
    severity: high
    canaries: {count: 1, format: "CANARY-{hex8}", rotate_hours: 24, in: system_prompt}
    action: BLOCK
  CTRL-OUT-FILTER:
    tag: output_handling
    severity: high
    markdown_images: {allow_hosts: [], action: REDACT}
    links: {allow_hosts: ["docs.example.org"], action: WARN}
    html_script: {action: REDACT}
    max_response_kb: 256
  CTRL-TOOL-RULES:
    tag: tool_abuse
    severity: high
    default: BLOCK
    rules:
      - {id: T-001, tool: read_file, action: ALLOW, when: {args.path: {under: ["/workspace/demo"]}}}
      - {id: T-002, tool: read_file, action: BLOCK, when: {any: [{args.path: {regex: '(^|/)\.\.(/|$)'}}, {args.path: {prefix_not_under: ["/workspace/demo"]}}]}, reason: path traversal / prefix bypass}
      - {id: T-003, tool: send_email, action: REQUIRE_APPROVAL, when: {args.to: {domain_not_in: ["example.org"]}}, approver: secops, ttl_s: 300}
      - {id: T-004, tool: send_email, action: ALLOW, when: {args.to: {domain_in: ["example.org"]}}}
      - {id: T-005, tool: "shell.*", action: BLOCK, reason: no shell for agents}
      - {id: T-006, tool: web_fetch, action: BLOCK, when: {args.url: {host_in_cidr: ["10.0.0.0/8", "169.254.0.0/16", "127.0.0.0/8"]}}, reason: SSRF}
    tool_result_scan: {injection: true, secrets: true, action: REDACT}
  CTRL-MCP-PIN:       {mode: enforce, fail: closed, tag: tool_poisoning, severity: critical, on_drift: block, scan_descriptions: true}
  CTRL-MEM:
    tag: memory_poison
    severity: high
    write: {require_provenance: true, scan: [injection, secrets, pii], deny_instruction_like: true, max_entry_kb: 8, action: BLOCK}
    read:  {scope: per_agent, max_entries: 20}
  CTRL-RATE:          {mode: enforce, fail: open, tag: resource, severity: low, per_agent: {rpm: 60, burst: 10}, per_app: {rpm: 300}}
  CTRL-BUDGET:
    tag: resource
    severity: medium
    on_exceed: BLOCK
    window: day
    warn_at: [0.5, 0.8]
    unit: tokens
    hierarchy:
      org:            {tokens: 2000000, usd: 5.00}
      departments:    {finance: {tokens: 500000, usd: 1.50}, engineering: {tokens: 1200000, usd: 3.00}}
      apps:           {opencode: {tokens: 400000, usd: 1.00}, finance-ui: {tokens: 300000}}
      agents:         {planner: {tokens: 150000}, mailer: {tokens: 30000}, researcher: {tokens: 100000}}
      anon:           {tokens: 5000}
      per_request:    {max_input_tokens: 16000, max_output_tokens: 4096, max_wall_ms: 60000}
    local_compute:    {usd_per_hour: 0.50, count_wall_time: true}
  CTRL-LOOP:
    fail: open
    tag: resource
    severity: medium
    max_steps_per_session: 40
    max_identical_tool_calls: 3
    max_delegation_depth: 3
    max_session_wall_s: 600
    action: BLOCK
  CTRL-SUPPLY:
    tag: supply_chain
    severity: critical
    model_artifacts: {formats_deny: [pickle, .pkl, .pt, .ckpt, .bin], formats_allow: [safetensors, gguf], repos_allow: ["hf.co/Qwen/*", "ollama.com/library/*"], action: BLOCK}
    packages: {registries_allow: ["pypi.org", "files.pythonhosted.org"], deny_names_from: feed:signatures, action: BLOCK}
    code_exec: {deny_patterns_from: feed:signatures, action: BLOCK}
# ---------- 7. action precedence ----------
actions:
  # BLOCK > approval > allow; REDACT transforms; WARN/LOG annotate
  precedence: [BLOCK, REQUIRE_APPROVAL, REDACT, WARN, LOG, ALLOW]
  approval: {channel: dashboard, default_on_timeout: BLOCK, ttl_s: 300}
  locked_controls: [CTRL-DLP-SECRETS, CTRL-SUPPLY]
# ---------- 8. feeds (externally managed signatures) ----------
feeds:
  signatures:
    source: {type: file, path: ./feeds/signatures.json}
    # Required remote signature; judge edits belong in local.d, not this feed
    verify: {type: ed25519, public_key_env: AICL_FEED_PUBLIC_KEY, required: true}
    max_age_s: 86400
    on_stale: keep_last_good
    on_rollback: reject
    on_invalid: reject_and_keep_last_good
# ---------- 9. telemetry and privacy ----------
telemetry:
  log:
    path: ./data/audit.jsonl
    content: hash_only
    # No raw content in audit; keys provisioned outside log directory
    hmac_key_env: AICL_HMAC_KEY
    hash_chain: {enabled: true, anchor_every: 100}
    retention_days: 90
  evidence:
    store: blocked_only
    path: ./data/evidence.db
    retention_days: 7
    reveal_requires_reason: true
  pseudonymize_identities: false
  metrics: {prometheus: true, otel: {enabled: false, endpoint: "http://127.0.0.1:4318"}}
  server_timing: true
# ---------- 10. exceptions (time-boxed, owned) ----------
exceptions:
  - id: EXC-001
    control: CTRL-DLP-PII
    match: {agent: researcher, entity: EMAIL}
    effect: LOG
    owner: alice
    reason: customer emails are in scope for this research task
    ticket: SEC-142
    created: 2026-10-03
    expires: 2026-10-10 # expired exceptions ignored; maximum 30 days
```

### Pydantic outline and editor schema

```python
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
Profile = Literal['strict','balanced','permissive']
Mode = Literal['enforce','monitor','off']
type PV[T] = T | dict[Profile,T]
class Node(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True)
class Control(Node):
    mode: PV[Mode]
    fail: Literal['open','closed','degrade']
    timeout_ms: int = Field(80,gt=0)
    tag: str
# Policy: Metadata, Defaults, Profiles, IdentityGraph, Destinations, DataMatrix,
# typed Pii/Secret/Semantic/Tool/Memory/Rate/Budget/Loop/SupplyControl models,
# Actions, Feed, Telemetry, Exceptions; discriminator = control id.
# @model_validator(mode='after'): cross-references, cycles, thresholds, expiry.
# JSON editor schema: json.dump(Policy.model_json_schema(), f, indent=2)
```

[REC] Use [Pydantic 2.13.5](https://pypi.org/pypi/pydantic/2.13.5/json) (MIT, released 2026-08-28, Python >=3.9). JSON Schema is generated by [model_json_schema()](https://docs.pydantic.dev/latest/concepts/json_schema/); schema generation does not replace semantic cross-field validation. Frozen Pydantic objects are only shallow-frozen: recursively convert mutable dictionaries/lists to immutable compiled structures. Do not mutate a snapshot's nested dict in a handler.

[REC] Outline models must be replaced by typed sections, not unrestricted Any. [Editor modeline](https://github.com/redhat-developer/yaml-language-server#using-a-modeline) associates the exported schema. Validate all IDs/references, all matrix cells, levels/tiers, parent cycles, finite prices, positive budgets, per-profile warn<=block in [0,1], approvers, exception expiry/owners and locked controls. Frozen models are shallow: freeze nested structures in the compiled object. Argument DSL accepts only eq/in/regex/under/domain/CIDR/comparison/length and all/any/not operators; cap depth, decoding and regex/input size. No eval or executable templates. under is path-segment containment, not startswith; filesystem symlinks remain tool-server authorization. SSRF checks all A/AAAA and connection-time rebinding; example IPv4 CIDRs are not a complete defense.

## 2. Hot reload without restart

| Option | SPDX / latest release | Maintenance / compatibility | Save-via-rename and MVP fit |
|---|---|---|---|
| [watchfiles](https://github.com/samuelcolvin/watchfiles) | MIT; 1.3.0, 2026-09-21 | unarchived, pushed 2026-09-21; Python >=3.10; cp313/cp314 macOS arm64 wheels | Rust notify-backed; watch DIRECTORY, filter policy paths; async awatch; simplest event-driven option |
| [watchdog](https://github.com/gorakhargosh/watchdog) | Apache-2.0; 6.0.0, 2024-11-01 | unarchived, pushed 2026-09-22; Python >=3.9; universal2/arm64 wheels; wheel labels list through cp313, py3 wheel path available | FSEvents on macOS; Observer thread -> asyncio queue; more event classes and callback glue |
| stdlib stat polling | Python PSF-2.0 | no dependency, 3.13/3.14 native | compare mtime_ns + size + inode, enumerate overlay directory; works without native notification delivery |

| Mechanism | Overwrite p50/max ms | Atomic rename p50/max ms | Backup rename p50/max ms |
|---|---:|---:|---:|
| watchfiles defaults debounce=1600, step=50 | 76.7 / 84.5 | 110.2 / 114.7 | 76.9 / 87.6 |
| watchfiles debounce=50, step=10 | 27.9 / 36.2 | 26.3 / 31.7 | 26.2 / 32.9 |
| watchfiles debounce=200, step=25 | 52.5 / 66.9 | 48.4 / 56.3 | 48.9 / 66.8 |
| watchdog default Observer | 11.4 / 11.6 | 11.1 / 11.8 | 11.6 / 11.8 |
| stat poll 250 ms | 104.2 / 253.9 | 102.3 / 253.7 | 103.4 / 110.2 |
| stat poll 1000 ms | 600.2 / 604.2 | 600.1 / 604.2 | 599.8 / 604.1 |

[REC] Native gateway: watchfiles awatch(policy_dir, debounce=200, step=25). Fallback: 250 ms stat polling; for Docker bind mounts, force_polling=True if notifications fail. Docker/macOS reliability was not measured. Target successful activation <500 ms native, <1 s polling, hard demo acceptance <2 s for <=100 KB policy with <=500 simple rules. A timestamped POLICY_CHANGED event is the proof, not an arbitrary sleep.

```text
Startup: parse + validate + compile; if no valid policy exists -> lockdown (no forwarding)
Watch/poll change:
  coalesce burst, acquire reload lock (one reload at a time)
  read base + lexically sorted local.d/*.yaml (size and file-count caps)
  parse YAML 1.2, duplicate keys rejected, no object constructors
  merge dicts recursively; lists replace; explicit null deletes a key
  record source file hashes; canonicalize effective JSON (sorted keys, UTF-8)
  version = 'sha256:' + SHA256(canonical_effective_policy)
  unchanged effective hash -> no new activation, no duplicate event
  validate typed schema + cross-field invariants
  compile all matchers and three profiles into new immutable CompiledPolicy
  compute sanitized diff (paths + before/after; never show credentials/key material)
  reconcile limit specs WITHOUT resetting spent/reserved counters
  atomically swap state.current = compiled (tiny critical section, no await)
  emit POLICY_CHANGED(old_version,new_version,diff,source,actor_if_known)
On parse/validation/compile failure:
  retain last-good snapshot, emit POLICY_RELOAD_FAILED(path,error_code,error_locations)
  dashboard: rejected candidate hash, active hash, last success/failure, stale indicator
```

[REC] Watch the parent directory for rename/create/delete; notifications are hints, not proof of a complete write. Poll mtime_ns+size+inode and override filenames when necessary. [watchfiles parameters](https://watchfiles.helpmanual.io/api/watch/), [watchfiles wheels](https://pypi.org/pypi/watchfiles/1.3.0/json), [watchdog wheels](https://pypi.org/pypi/watchdog/6.0.0/json). Measurements above are native M5/Python 3.14.8, n=15 per save style except defaults n=6, exclude parsing, and are phase-correlated to 400 ms writes; no unbiased p99. Every overwrite, atomic rename and backup-rename save was detected. Docker bind mounts were not measured.

Each request retains its captured snapshot through response/streaming. One worker for the MVP; assignment is not a distributed swap. Mutable spend, reservations, rate buckets, TOFU pins and approvals live outside configuration; reload never resets usage. Cache keys include policy/feed/detector versions, identity/profile/stage and content HMAC. Missing dependencies for enabled controls reject activation, not silently weaken it.

The dashboard GET/PUT /admin/policy uses source-hash If-Match, validates, then writes same-directory temp + fsync + os.replace through the same loader. 409 for stale editors; Saved is not Applied. Show sanitized changes and weakening (mode/removal/threshold/budget/allowlist/exception), active/candidate hashes and validation paths. File actor is unknown; dashboard actor authenticated. Separate admin auth, CSRF with cookie sessions, no token URLs. Base+lexical overlays deep-merge dictionaries, replace lists and delete explicit nulls. Production protects base/locked controls, reviews Git changes, runs policy CI and distributes signed artifacts with per-replica activation status; include git SHA but hash effective policy. [OPA bundles](https://www.openpolicyagent.org/docs/management-bundles), not git pull in the handler.

## 3. Policy engine choice

| Engine | SPDX / current version + release date / maintenance | Integration, strengths and limits |
|---|---|---|
| Custom Python data rules | project chooses licence; stdlib PSF-2.0 | in-process; YAML->typed conditions; fastest judge iteration; owns aggregation/redaction/budgets; no formal proof, must bound DSL and test every branch |
| [OPA](https://github.com/open-policy-agent/opa) | Apache-2.0; 1.21.1, 2026-09-29; unarchived, pushed 2026-10-03 | Rego v1; REST sidecar POST /v1/data/aicl/decision, signed bundles, decision logs, profiling, WASM; broad declarative decisions; separate process and Rego learning curve |
| [Cedar](https://github.com/cedar-policy/cedar) | Apache-2.0; CLI 4.13.0, 2026-09-15; pushed 2026-10-02 | Rust, default-deny/forbid wins; typed schema validation; hierarchical entities and ABAC; authorization, not an arbitrary transform/budget engine |
| [cedarpy](https://github.com/k9securityio/cedar-py) | Apache-2.0; 4.12.1, 2026-09-24; unarchived, pushed 2026-09-23 | third-party, NOT AWS/Cedar-team supported; embeds Cedar engine 4.12.0; authorize/validate/format; cp313/cp314 macOS arm64 wheels verified |
| [pycasbin](https://github.com/casbin/pycasbin) | Apache-2.0; PyPI pycasbin 2.8.0, 2026-02-02; unarchived, pushed 2026-10-03 | RBAC/ABAC model.conf + policy.csv, enforce/enforce_ex, adapters/watchers; pure Python wheels; simpleeval>=1.0.3 dependency; not one central control schema |
| [Cerbos](https://github.com/cerbos/cerbos) | Apache-2.0; 0.56.0, 2026-09-30; pushed 2026-10-02 | Go PDP via HTTP/gRPC, YAML resource/principal policy with CEL conditions, audit logs; disk watchForChanges=true; separate binary; good production ABAC |
| [OpenFGA](https://github.com/openfga/openfga) | Apache-2.0; 1.21.0, 2026-09-20; pushed 2026-10-02 | Zanzibar-inspired relationship authorization, tuple store and typed model, conditional tuples; fine for organization/document relationships, not DLP transformation policy |
| [Topaz](https://github.com/aserto-dev/topaz) | Apache-2.0; 0.33.22, 2026-09-28; pushed 2026-09-30 | local OPA + directory, combines relationship/attribute authorization; container/binary, bundle workflow, extra operating concepts |

[MEASURED] Apple M5, macOS arm64, Python 3.14.8, tiny tool-authorization policies, serial warm calls. These are microbenchmarks, not comparable feature-complete gateway benchmarks.

| Path | Input/rules/sample | p50/p95/p99 |
|---|---|---|
| Python compiled rule list | 3 rules, send_email args, 20,000 evals, fnmatch and lambdas | about 0.001/0.001 ms; p99 not retained |
| cedarpy 4.12.1 is_authorized | 3 policies, 2 entities, send_email context; 500 calls; parses strings per call | 0.069/0.078 ms; p99 not retained |
| OPA 1.21.1 REST loopback | 3 decision rules; 3,000 keepalive HTTP calls, first 200 removed | 0.090/0.162/0.327 ms |
| OPA -w file reload | one rewrite -> first observed BLOCK->ALLOW transition, n=1 | 3.1 ms; not a reload SLA |

[REC] Custom bounded data rules win developer speed, judge editability, demo quality and explanations; fallback is an explicit known-tool/domain/path table, not arbitrary expressions. Estimates: custom 3-5 h, new Cedar 5-8 h, new Rego 6-10 h [INFERENCE]. Production uses Cedar or existing OPA/Cerbos for authorization only; detectors, transformations and budget ledger stay outside. No engine automatically implements semantic detection or reservations.

[OPA integration](https://www.openpolicyagent.org/docs/integration) supports REST, Go SDK and WASM; [-w source](https://github.com/open-policy-agent/opa/blob/main/cmd/run.go) watches files, [performance guide](https://www.openpolicyagent.org/docs/policy-performance) covers profiling/indexing, not a universal SLA. NOT RECOMMENDED FOR MVP: [opa-wasm 0.3.2](https://pypi.org/pypi/opa-wasm/0.3.2/json), MIT, 2022-02-11, Python >=3.8,<4.0, 3.14 untested; or [Regorus](https://github.com/microsoft/regorus) 0.12.0, 2026-09-01, pushed October 1, repo MIT / Python metadata MIT AND Apache-2.0 AND BSD-3-Clause, binding source but no PyPI regorus/pyregorus/regorus-py package -> use REST. [WASM host callbacks](https://www.openpolicyagent.org/docs/wasm) remain integration work.

[Cedar schema/default-deny semantics](https://docs.cedarpolicy.com/) are distinct from [formal analysis](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean-cli#analysis); analysis proves policy properties, not classifier accuracy. [AgentCore](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/) and [Verified Permissions](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html) use Cedar; managed services are references, not dependencies. cedarpy is third-party, not AWS-supported, embeds Cedar 4.12.0; [cp313/cp314 macOS arm64 wheels](https://pypi.org/pypi/cedarpy/4.12.1/json). Casbin's older distribution 1.43.0 (2025-05-10) and [pycasbin 2.8.0](https://pypi.org/pypi/pycasbin/2.8.0/json) point to the same repository; pure Python/simpleeval, do not install both. [Cerbos disk watchForChanges](https://github.com/cerbos/cerbos/blob/main/docs/modules/configuration/pages/storage.adoc). OpenFGA/Topaz add relationship-store workflows, not detector orchestration.

## 4. Observability, integrity and export

| Component | SPDX / version, release / maintenance | Python/platform relevance |
|---|---|---|
| [OpenTelemetry API/SDK](https://github.com/open-telemetry/opentelemetry-python) | Apache-2.0; 1.45.0, 2026-09-25; pushed 2026-10-03 | Python >=3.10, py3 wheels; API/SDK pure Python; optional OTLP grpc dependencies need their own wheels |
| [OTel FastAPI instrumentation/semconv](https://github.com/open-telemetry/opentelemetry-python-contrib) | Apache-2.0; 0.66b0, 2026-09-25 | beta package line, align versions with SDK 1.45.0; no automatic detector-span coverage |
| [prometheus-client](https://github.com/prometheus/client_python) | Apache-2.0 AND BSD-2-Clause (PyPI expression); 0.26.0, 2026-07-24; pushed 2026-09-15 | Python >=3.9, py3 wheel |
| [structlog](https://github.com/hynek/structlog) | MIT OR Apache-2.0; 26.1.0, 2026-06-06; pushed 2026-10-01 | Python >=3.10, py3 wheel; optional, stdlib JSON logging suffices |
| [orjson](https://pypi.org/pypi/orjson/3.12.0/json) | MPL-2.0 AND (Apache-2.0 OR MIT); 3.12.0, 2026-08-14 | cp313/cp314 universal2/arm64 wheels; optional, file-level copyleft component; skip if unnecessary |
| [Grafana OSS](https://github.com/grafana/grafana/blob/main/LICENSE) | AGPL-3.0, copyleft; 13.2.3, 2026-09-29; pushed 2026-10-03 | separate server, no Python wheel need; vendor binaries/plugins may have different terms |
| [ruamel.yaml](https://pypi.org/pypi/ruamel.yaml/0.19.1/json) | MIT; 0.19.1, 2026-01-02; maintenance push not independently checked | Python >=3.9, py3 wheel; tested without clib on 3.14 |

```text
LLM: CLIENT, name='chat <model>'
  gen_ai.operation.name='chat', gen_ai.provider.name='ollama' (custom provider value)
  gen_ai.request.model, gen_ai.response.model
  gen_ai.usage.input_tokens, gen_ai.usage.output_tokens
  gen_ai.response.finish_reasons, gen_ai.request.max_tokens
Agent: invoke_agent <name>, gen_ai.agent.id/name/version, gen_ai.conversation.id
Tool: INTERNAL execute_tool <tool>, gen_ai.tool.name/type/call.id
Gateway: SERVER HTTP span + INTERNAL aicl.check.<stage>
  aicl.policy.version, aicl.feed.version, aicl.control.id, aicl.rule.id
  aicl.decision, aicl.shadow, aicl.score, aicl.failure_mode
```

[REC] JSONL is the source of truth; SQLite audit_index is rebuildable and supports dashboard filtering. One writer queue sequences events; separate budget ledger transactions from audit indexing. Strict side-effect decisions need durable audit acknowledgement before execution, or an explicit fail policy if disk is full. Normal allow rows can use bounded batch flushing; document the crash-loss window. No authorization headers/cookies/API keys/tool body/URL query strings/model prompts in logs. JSON encoding prevents raw CRLF breaking records, but fields still need length bounds and sanitization. [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) warns against logging secrets and log injection.

[REC] Content fingerprints: HMAC-SHA256(secret_key, domain_separator || exact_UTF8_bytes), key_id recorded, key stored outside log directory. Separate domain labels for content, identities and secret matches; rotate keys deliberately, not each reload. Hashes enable correlation but remain pseudonymous sensitive data; hash-only is not anonymization. Unkeyed hashes of PESEL, email and short secrets allow dictionary enumeration. Restrict access to HMAC fingerprints; truncate only display, not stored digest. Evidence pointer refers to encrypted/restricted storage, 7-day demo retention vs 90-day metadata, access/reveal audited. Management sees aggregates, not a risky-employee leaderboard.

```text
canonical = deterministic JSON(event excluding integrity) with sorted keys
record_hash = SHA256(prev_hash_bytes || canonical)
record_mac  = HMAC-SHA256(audit_key, seq_be64 || record_hash)
store seq, prev_hash, record_hash, record_mac, key_id
verify sequentially; anchor (seq,record_hash,record_mac) outside log file periodically
```

| Export | Exact contract and caveat |
|---|---|
| JSONL | complete sanitized rows, metadata header separately; no live evidence blobs; verify integrity before exporting |
| CSV | ts,event_id,event_type,severity,decision,stage,control_ids,agent_pseudonym,model,tokens_in,tokens_out,cost_usd,policy_version; nested fields JSON-encoded; spreadsheet formula-injection escaping |
| CEF / syslog | CEF:0|HackYeah|AIControlLayer|1|event_type|sanitized name|0..10|extensions; map trace to externalId, decision to act, rule id to cs1 with label; escape backslash/pipe/header and equals/newlines/extensions; RFC5424 syslog framing |
| OCSF mapped | API Activity class_uid=6003 for LLM/tool requests, ai_operation + inherited security_control + trace profiles; Detection Finding class_uid=2004 for alerts; NOT 'OCSF compliant' unless independently schema-validated exporter delivered |

CEF spec: [ArcSight implementation standard](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.1/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf); [RFC5424](https://www.rfc-editor.org/rfc/rfc5424). CSV escaping follows [OWASP CSV injection](https://owasp.org/www-community/attacks/CSV_Injection). Do not send unauthenticated plaintext syslog outside the demo laptop.

OCSF [1.9.0](https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0), 2026-08-03, Apache-2.0; unarchived, pushed 2026-10-02. There is an [ai_operation profile](https://github.com/ocsf/ocsf-schema/blob/1.9.0/profiles/ai_operation.json), not a released AI-only event class. Category Application Activity uid=6 plus api_activity uid=3 yields 6003; Findings uid=2 plus detection_finding uid=4 yields 2004, from [categories](https://github.com/ocsf/ocsf-schema/blob/1.9.0/categories.json) and [class](https://github.com/ocsf/ocsf-schema/blob/1.9.0/events/application/api_activity.json).

| Our field | OCSF 1.9.0 mapping |
|---|---|
| event_id, ts | metadata.uid, time (epoch ms) |
| model/provider | ai_model.name, ai_model.ai_provider |
| agent id/name; parent | ai_agent.uid/name; delegation.parent_uid/issuer_uid |
| input/output/total tokens | message_context.prompt_tokens/completion_tokens/total_tokens |
| control/rule, decision | policy + authorizations; action_id 1 Allowed / 2 Denied |
| REDACT/WARN/LOG/HOLD | proposed disposition_id 11 Corrected / 19 Alert / 17 Logged / 14 Delayed; mapped interpretation, not standard endorsement |
| OWASP/ATLAS | attacks entries where supported; extensions retain full taxonomy versions |
| trace/span | trace profile fields; integrity -> record_integrity profile mapping |

[EST] [GenAI convention repository](https://github.com/open-telemetry/semantic-conventions-genai), Apache-2.0, pushed October 2, no latest release; all Development, schema URL still TODO, core semantic conventions 1.44.0 referenced. Disable content/messages/tool arguments capture. Instrument observed agent lifecycle only, never guess invoke_agent spans from a proxy. Ollama is a custom provider value; aicl.* are custom security attributes. [Token metrics](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-token-metrics.md) use gen_ai.client.inference.usage.input_tokens/output_tokens while span attributes remain gen_ai.usage.*. [MCP conventions](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md) define method/protocol/session attributes, client/server operation-duration metrics and params._meta context propagation. They reference MCP 2025-11-25: session metrics may not apply to newer transport. Avoid duplicate tool spans, pin a commit.

The chain proves interior tampering relative to an independent trusted head, not complete logging, privileged-writer resistance or tail authenticity without an anchor. [CloudTrail signed-digest precedent](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html). Audit disk durability was not measured. OCSF mappings are interpretations, not compliant exporters. [OCSF dictionary](https://github.com/ocsf/ocsf-schema/blob/1.9.0/dictionary.json) defines action/disposition enums. Grafana is [AGPL-3.0](https://github.com/grafana/grafana/blob/main/LICENSE): modified network-serving versions have source-offer implications; preserve licences rather than claim blanket exemption.

## 5. Event taxonomy and log schema

[REC] One final decision record per request stage; all findings in an array. event_type is the winning explanation, not an instruction to count an extra request. A stage can be PII_REDACTED rather than PROMPT_ALLOWED; dashboards count decision=ALLOW/REDACT and stage=prompt, not just event_type. Policy/feed/approval transitions are independent lifecycle rows, excluded from AI-request totals. request_id groups prompt/response/tool decisions, event_id uniquely identifies one row. Attempt metrics use DISTINCT request_id+stage+category so multiple signatures do not multiply attack counts.

| Event(s) | Default severity | Trigger / typical actual effect |
|---|---|---|
| PROMPT_ALLOWED / PROMPT_BLOCKED | info / high | clean allow or nonspecific input deny |
| PII_REDACTED / SECRET_DETECTED | medium / critical | sensitive entity findings, REDACT/BLOCK or shadow ALLOW |
| INJECTION_DETECTED / JAILBREAK_DETECTED | high | signature/classifier threshold crossed, BLOCK/WARN |
| SYSTEM_PROMPT_LEAK / RESPONSE_FILTERED | high | canary detected or output channel filtered |
| TOOL_CALL_ALLOWED / TOOL_CALL_BLOCKED | info / high | authorized call or capability/argument/destination failure |
| BUDGET_THRESHOLD / BUDGET_EXCEEDED | low / medium | 50/80% crossing or reservation would exceed any ancestor |
| AGENT_LOOP_TERMINATED / RATE_LIMITED | medium / low | repeated actions/steps/depth/time or token bucket denial |
| APPROVAL_REQUESTED / GRANTED / DENIED / EXPIRED | medium/info/high/medium | hold created, reviewed or TTL elapsed; never implies execution succeeded |
| MCP_TOOL_DRIFT / MCP_TOOL_POISONING | critical / high | canonical description/schema hash changed or malicious description found |
| FEED_UPDATED / FEED_REJECTED / FEED_STALE | info / high / medium | verified atomic update, malformed/unsigned/rollback, freshness breach |
| MODEL_BLOCKED / DESTINATION_BLOCKED | medium / high | model not permitted, data-level/trust violation |
| MEMORY_WRITE_BLOCKED / SIGNATURE_MATCHED | high | provenance/poisoning violation or historical exploit signature match |
| KILL_SWITCH / DEGRADED_MODE / RECOVERED | critical / high / info | emergency refusal, control failure with fallback, recovery |
| POLICY_CHANGED / POLICY_RELOAD_FAILED | info or high if weakened / high | successful activation / invalid candidate with last-good retained |
| EXCEPTION_USED / EXCEPTION_EXPIRED | medium / low | scoped time-boxed downgrade / expiry |
| EVIDENCE_REVEALED / AUDIT_INTEGRITY_FAILED | high / critical | restricted reveal with reason / failed chain verification |

Four complete illustrative rows follow; hashes are synthetic, not actual logged content. integrity is null here because production writer fills it after serialization. Do not copy those digest values as pinning material.

```json
{"schema_version":"aicl-event/1","ts":"2026-10-03T12:00:00.123Z","event_id":"9d1f1142-7ff7-4abc-a5c9-a146b3491101","request_id":"req-101","event_type":"PII_REDACTED","severity":"medium","decision":"REDACT","would_decision":"REDACT","shadow":false,"stage":"prompt","policy_version":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","feed_version":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","findings":[{"control_id":"CTRL-DLP-PII","rule_id":"PII-PESEL","mode":"enforce","score":1.0,"action":"REDACT","reason_code":"pii.destination_not_permitted","taxonomy":{"owasp_llm_2026":["LLM02"],"owasp_llm_2025":["LLM02"],"atlas":["AML.T0057"]}}],"identity":{"user":"bob","session":"s-11","app":"opencode","agent":"mailer","parent_agent":"planner","delegation_chain":["planner","mailer"],"tool":null},"trace":{"trace_id":"11111111111111111111111111111111","span_id":"2222222222222222"},"destination":{"kind":"model","id":"sim/gpt-4o-mini","provider":"sim-commercial","trust":"external","model":"gpt-4o-mini"},"usage":{"input_tokens":124,"output_tokens":0,"reserved_tokens":512,"charged_cost_usd":0.0,"local_equivalent_usd":null,"upstream_executed":false},"latency_ms":{"auth":0.1,"budget":0.2,"dlp":1.4,"injection":0.8,"policy":0.1,"upstream":null,"total":2.6},"privacy":{"content_hmac":"hmac-sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","key_id":"content-2026-10","redaction_counts":{"PESEL":1},"evidence_id":null,"evidence_expires":null}}
```

```json
{"schema_version":"aicl-event/1","ts":"2026-10-03T12:00:02.456Z","event_id":"9d1f1142-7ff7-4abc-a5c9-a146b3491102","request_id":"req-102","event_type":"TOOL_CALL_BLOCKED","severity":"high","decision":"BLOCK","would_decision":"BLOCK","shadow":false,"stage":"tool_args","policy_version":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","feed_version":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","findings":[{"control_id":"CTRL-TOOL-RULES","rule_id":"T-002","mode":"enforce","score":null,"action":"BLOCK","reason_code":"path.outside_allowed_root","taxonomy":{"owasp_llm_2026":["LLM03"],"owasp_llm_2025":["LLM06"],"owasp_asi_2026":["ASI02"],"atlas":["AML.T0053","AML.T0086"]}}],"identity":{"user":"bob","session":"s-11","app":"opencode","agent":"mailer","parent_agent":"planner","delegation_chain":["planner","mailer"],"tool":"read_file"},"trace":{"trace_id":"11111111111111111111111111111111","span_id":"3333333333333333"},"destination":{"kind":"mcp","id":"fs","provider":null,"trust":"internal","model":null},"usage":{"input_tokens":0,"output_tokens":0,"reserved_tokens":0,"charged_cost_usd":0.0,"local_equivalent_usd":null,"upstream_executed":false},"latency_ms":{"auth":0.1,"signature":0.2,"tool_rules":0.1,"policy":0.05,"upstream":null,"total":0.45},"privacy":{"content_hmac":"hmac-sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","key_id":"content-2026-10","redaction_counts":{},"evidence_id":"ev-102","evidence_expires":"2026-10-10T12:00:02.456Z"}}
```

```json
{"schema_version":"aicl-event/1","ts":"2026-10-03T12:00:03.000Z","event_id":"9d1f1142-7ff7-4abc-a5c9-a146b3491103","request_id":"req-103","event_type":"BUDGET_EXCEEDED","severity":"medium","decision":"BLOCK","would_decision":"BLOCK","shadow":false,"stage":"prompt","policy_version":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","feed_version":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","findings":[{"control_id":"CTRL-BUDGET","rule_id":"budget.agents.mailer","mode":"enforce","score":null,"action":"BLOCK","reason_code":"budget.reservation_exceeds_remaining","taxonomy":{"owasp_llm_2026":["LLM06"],"owasp_llm_2025":["LLM10"],"atlas":["AML.T0034.002"]}}],"identity":{"user":"bob","session":"s-11","app":"opencode","agent":"mailer","parent_agent":"planner","delegation_chain":["planner","mailer"],"tool":null},"trace":{"trace_id":"44444444444444444444444444444444","span_id":"5555555555555555"},"destination":{"kind":"model","id":"ollama/qwen3.5:4b","provider":"ollama","trust":"local","model":"qwen3.5:4b"},"usage":{"input_tokens":1200,"output_tokens":0,"reserved_tokens":0,"attempted_reservation":3248,"spent_tokens":29500,"cap_tokens":30000,"charged_cost_usd":0.0,"local_equivalent_usd":0.0,"upstream_executed":false},"latency_ms":{"auth":0.1,"budget":0.3,"dlp":null,"semantic":null,"upstream":null,"total":0.4},"privacy":{"content_hmac":"hmac-sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","key_id":"content-2026-10","redaction_counts":{},"evidence_id":null,"evidence_expires":null}}
```

```json
{"schema_version":"aicl-event/1","ts":"2026-10-03T12:00:05.001Z","event_id":"9d1f1142-7ff7-4abc-a5c9-a146b3491104","request_id":null,"event_type":"POLICY_CHANGED","severity":"high","decision":"LOG","would_decision":null,"shadow":false,"stage":"lifecycle","policy_version":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","feed_version":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","findings":[],"identity":{"user":"judge","session":"admin-2","app":"dashboard","agent":null,"parent_agent":null,"delegation_chain":[],"tool":null},"trace":{"trace_id":null,"span_id":null},"destination":null,"usage":{"input_tokens":0,"output_tokens":0,"reserved_tokens":0,"charged_cost_usd":0.0,"local_equivalent_usd":null,"upstream_executed":false},"latency_ms":{"read_parse":15.3,"validate_compile":1.5,"swap":0.01,"total":16.81},"privacy":{"content_hmac":null,"key_id":null,"redaction_counts":{},"evidence_id":null,"evidence_expires":null},"change":{"source":"dashboard","reason":"judge shadow-mode demonstration","old_policy_version":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","diff":[{"path":"/controls/CTRL-INJ-SEM/mode","before":"enforce","after":"monitor","weakening":true}],"active":true}}
```

[REC] Detection is not enforcement or evidence of successful attack. Impact-oriented severity is separate from classifier probability. Typed event schema forbids extra fields and bounds arrays/strings; required fields include authenticated identity chain, policy/feed versions, control/rule IDs, scores/provenance, destination/model, reported/estimated tokens and cost, upstream_executed, stage latency, redaction counts, keyed content hashes/key IDs and restricted evidence pointer/expiry. Trace IDs are 32 hex, span IDs 16 hex; null when not traced. Lifecycle records do not fake inference usage. Writer adds integrity after canonical serialization. Prompt-stage permission and post-upstream usage are separate records, so allowed/redacted permission does not falsely imply a successful model call.

Taxonomy is mapped against [OWASP LLM 2026 canonical list](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10), preserving 2025 IDs for issuer traceability, and [ATLAS v2026.09](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.09), released 2026-09-15, YAML version 5.6.0. Policy/example IDs were checked; interpretations are not certification.

## 6. Performance telemetry for judges

[REC] /metrics on loopback/admin access, Prometheus exposition; HTTP scrape should never include prompt content, raw user/session IDs, hashes, URLs or policy-version labels with accumulating values. Prefix aicl_, base units seconds/bytes, counters _total as [Prometheus naming](https://prometheus.io/docs/practices/naming/) prescribes. Label cardinality is the product of label values, not each dimension alone; guideline [below 10 generally, review >100](https://prometheus.io/docs/practices/instrumentation/#do-not-overuse-labels). Bound control IDs by the registry and stage/model/category by enumerations; dynamic agent/user rankings come from SQLite, not Prometheus labels.

| Metric | Type / bounded labels | Measurement |
|---|---|---|
| aicl_requests_total | counter {stage,outcome} | one final ingress-stage record, outcome allow/block/redact/hold/error |
| aicl_findings_total | counter {category,mode,action} | findings; separate distinct-attempt aggregation in audit index |
| aicl_stage_duration_seconds | histogram {stage,control} | detector/control wall time including timeout |
| aicl_gateway_overhead_seconds | histogram {stage} | sum local processing intervals; exclude upstream wait, include detector wait |
| aicl_request_duration_seconds | histogram {stage,outcome} | full request wall time, response streaming included |
| aicl_upstream_duration_seconds | histogram {provider,model} | model/tool call latency; model allowlist keeps cardinality bounded |
| aicl_ttft_seconds | histogram {provider,model} | first upstream chunk vs first client chunk, separate metrics if needed |
| aicl_tokens_total | counter {provider,model,direction,source} | input/output, reported/estimated |
| aicl_cache_requests_total | counter {cache,result} | result hit/miss/bypass; classifier and policy-verdict caches distinct |
| aicl_inflight_requests | gauge {stage} | current requests / holds |
| aicl_budget_used_ratio | gauge {scope} | aggregate scope only; entity detail from ledger |
| aicl_policy_reload_total | counter {result} | activated/rejected/no_change |
| aicl_policy_last_success_timestamp_seconds | gauge | last activation UTC |
| aicl_feed_age_seconds | gauge {feed} | now - last signed feed issued timestamp |
| aicl_audit_queue_depth / aicl_audit_write_errors_total | gauge / counter | prevent silent dropped security records |

[REC] Deterministic histogram buckets seconds: .0001,.00025,.0005,.001,.0025,.005,.01,.025,.05,.1,.25,.5,1,2.5,5. Upstream buckets .05,.1,.25,.5,1,2,5,10,20,60. Do not use the same buckets for 100 us checks and 20 s generation. Per-stage p50/p95/p99 via histogram_quantile, not averaging percentiles; request throughput rate(aicl_requests_total[1m]); cache rate hits/(hits+misses), exclude bypasses. Example:

```promql
histogram_quantile(0.95, sum by (le,stage) (rate(aicl_stage_duration_seconds_bucket[5m])))
sum(rate(aicl_requests_total{stage="prompt"}[1m]))
sum(rate(aicl_cache_requests_total{result="hit"}[5m])) /
sum(rate(aicl_cache_requests_total{result=~"hit|miss"}[5m]))
```

```http
Server-Timing: auth;dur=0.12, budget;dur=0.31, dlp;dur=1.41, inj_sig;dur=0.24, inj_sem;dur=29.1, policy;dur=0.08, guard;dur=31.26
X-AICL-Policy-Version: sha256:<64 hex>
```

dur uses milliseconds; sanitize fixed stage names, expose no rules/identity/private paths in desc. Browser cross-origin timing access needs appropriate Timing-Allow-Origin; do not wildcard private admin timing. For streaming the header can only describe work finished before headers are sent, not full model latency or output guard time. Final timings appear in the audit row/SSE; HTTP trailers are not a portable browser solution. Stage sums can overlap, so record critical-path wall time separately rather than subtracting upstream duration blindly.

[REC] Judge benchmark compares client->scripted mock vs client->gateway->same mock; warm-up excluded, payload sizes 1 KB/10 KB/100 KB, concurrency 1/8/32, state CPU/model/detector/warm cache conditions, measure at least thousands of operations. Report gateway-only overhead and semantic-inclusive overhead separately, throughput plus error rate, TTFT vs full streamed duration, cold/warm cache, and p99 sample count. Target <=5 ms deterministic overhead on <=10 KB bodies is a target, not established today. Semantic model latency comes from actual local runtime, never an A100 paper figure. Do not claim retries saved tokens unless upstream absence is verified.

## 7. Dashboard definitions, views and technology

[REC] SQLite index and usage ledger are authoritative for selected time ranges; Prometheus for recent performance; policy registry/test report/feed state for posture. SSE signals updates, never becomes the durable database. Distinct final prompt-stage request counts reconcile N = A + B + R + H + E, where redacted is mutually exclusive from allowed in tiles. Tool/memory operations have their own totals, not silently added to Total AI requests. Responses are not counted as new requests.

| Dashboard item | Exact formula / source |
|---|---|
| Total AI requests | count distinct request_id with stage=prompt and final ingress decision in window; audit_index |
| Allowed / Blocked / Redacted / Held / Errors | same N filtered by actual outcome; REDACT means forwarded after verified transformation, not only a detector finding; final upstream status separately |
| Prompt-injection attempts | distinct (request_id,stage) where findings tag=injection and score >= configured warn threshold or signature match; show detected/enforced-blocked/shadow split |
| Secret-leak attempts | distinct stage attempts with secret_leak finding; split prompt/tool_args/tool_result/response, blocked/redacted/monitor |
| PII-leak attempts | distinct attempts with pii_leak finding AND destination/clearance would violate data rule; PII present in local permitted use is not automatically a leak attempt |
| Tool abuse | distinct tool_args attempts BLOCKed/held by tool argument/capability/egress rules; separate MCP drift/poisoning from misuse |
| Agent loop blocks | count distinct loop-termination event_id, plus stopped sessions; do not count every refused continuation as a fresh loop |
| Budget usage | (spent+reserved)/cap per org/department/app/agent and per token/USD/compute unit; usage ledger; spent and reserved displayed separately |
| Tokens saved (ESTIMATED) | sum blocked-before-upstream input token estimate + median recent allowed output tokens for matching model/agent, with fallback explicit max-output reservation; separate input-known/output-counterfactual, no double count tool denies |
| API cost | sum actual charged token usage * versioned price / 1e6 for commercial calls; simulation labelled simulated, zero paid calls in required path |
| Local USD-equivalent | sum input*equiv_in/1e6 + output*equiv_out/1e6 OR wall_seconds*usd_per_hour/3600; choose one method, show assumption, never add both into real API cost |
| Top risky agents | rank sum severity weights critical=10/high=5/medium=2/low=1 over distinct categorized attempts per agent; show risk/100 requests, N and shadow mode; security only |
| Top risky tools | same weighted attempts per server+tool, N and blocked rate; schema drift separately; audit_index |
| Top attack categories | distinct categorized attempts per taxonomy tag/OWASP revision; many-to-many mapping so category totals need not equal N |
| Threat timeline | 1-minute buckets for last hour or 15-minute buckets for day; stacked categorized attempts, policy/feed changes overlaid; audit_index |
| Security posture score | formula below, registry+effective policy+version-matched tests+feed state; explicit heuristic, not certification |

```text
Expected controls C remain in registry even if removed from policy.
w_i = 3 for critical controls; 2 high; 1 medium/low (fixed published weights)
m_i = 1 enforce; 0.35 monitor; 0 off/missing
q_i = min(negative_attack_pass_rate_i, benign_allow_pass_rate_i)
      (0 when tests are missing or not valid for current detector/policy scope)
f_i = 1 for non-feed controls; max(0, 1 - max(0,feed_age_i-T_i)/T_i) for feed controls
      so freshness=1 until max_age T, then decays to zero at 2*T
coverage_effectiveness = sum(w_i*m_i*q_i*f_i) / sum(w_i)
exception_penalty = min(5, active_downgrade_exception_count)
posture = clamp(100*coverage_effectiveness - exception_penalty, 0,100)
```

| Stack | SPDX / latest verified version + date | Hackathon engineering estimate and tradeoff |
|---|---|---|
| FastAPI + static JS + Chart.js; optional Jinja/htmx | FastAPI MIT 0.142.2, 2026-09-30; Jinja2 BSD-3-Clause 3.1.6, 2025-03-05; htmx 0BSD 4.0.0, 2026-08-28; Chart.js MIT 4.5.1, 2025-10-13 | 5-8 h for functional custom dashboard/editor/approval page, no Node build; best central-file demo |
| React/Next.js | both MIT; latest versions/dates not independently verified here | 8-14 h from blank project [INFERENCE]; excellent if team already has app/design, otherwise build tooling/auth state consumes time |
| Streamlit | Apache-2.0 1.65.0, 2026-10-02; pushed 2026-10-03 | 2-4 h, great fallback analytics; admin writes/approvals require gateway APIs, generic UX; reruns need care |
| Grafana + Prometheus | Grafana AGPL-3.0 13.2.3; Prometheus Apache-2.0 version not reverified here | 2-3 h analytics provisioning, not editor/approval/playground; separate processes, optional not required |

| Page/tab | Components / API / build estimate |
|---|---|
| Overview (management) | posture breakdown, N/A/B/R/H tiles, budget/cost gauges, trend and aggregate categories; GET /api/summary; 1.0-1.5 h |
| Security | filterable live timeline, top agents/tools, finding drill-down, evidence access audit, export buttons; GET /api/events; 1.0-1.5 h |
| Performance | stage p50/p95/p99, throughput, TTFT/cache/model latency, active requests, reload lag; GET /api/performance; 0.5-1 h |
| Policy | YAML textarea, validate/save, source/effective hashes, profile selector, changed/weakening paths, rejected-candidate errors; /admin/policy; 1-1.5 h |
| Approvals + emergency | pending call summary (redacted), grant/deny/reason/TTL, current-policy recheck, kill-switch scope; /admin/approvals; 0.5-1 h |
| Playground + tests | local prompt route, result/findings/timings/policy hash, current test matrix and rerun command/result; /api/playground,/api/tests; 1-1.5 h |

[REC] Saved tokens are counterfactual estimates; blocking a generated response saves zero generation tokens and retains its cost. Agent risk measures exposure, not malicious intent; normalize per 100 requests and show sample count. Posture is a heuristic, not certification. Show enforcing/shadow coverage, version-matched test rate, feed freshness and exceptions; missing/stale tests set q=0 with a pending/unknown indicator, and removed controls stay in the denominator. OWASP coverage is separately categories with a passing enforcing control /10.

Choose static HTML + vanilla fetch/EventSource + vendored Chart.js; htmx is unnecessary and v4 recently changed. [FastAPI native SSE](https://github.com/fastapi/fastapi/blob/master/docs/en/docs/tutorial/server-sent-events.md), added 0.135.0, imports EventSourceResponse from fastapi.sse. One stream for all tabs; sequence ID, 15 s keepalive, Last-Event-ID replay, bounded slow-consumer queue with resync; POST/PUT for actions. [HTTP/1.1 browsers limit SSE to six connections](https://github.com/mdn/content/blob/main/files/en-us/web/api/eventsource/index.md). WebSockets add no benefit for one-way events. Management gets aggregates; security identity/detail; admin and evidence reveal need stronger privilege/reason. Escape labels, never render attacker HTML/Markdown in audit panels, vendor assets offline and mark seeded data as fixtures.

Release sources: [FastAPI 0.142.2](https://pypi.org/pypi/fastapi/0.142.2/json), MIT, Python >=3.10, py3 wheel; [Jinja2 3.1.6](https://pypi.org/pypi/jinja2/3.1.6/json), BSD-3-Clause, py3 wheel; [htmx 4.0.0](https://github.com/bigskysoftware/htmx/releases/tag/v4.0.0), [0BSD licence](https://github.com/bigskysoftware/htmx/blob/v4.0.0/LICENSE), pushed October 2; [Chart.js 4.5.1](https://github.com/chartjs/Chart.js/releases/tag/v4.5.1), MIT, pushed October 3; [Streamlit 1.65.0](https://github.com/streamlit/streamlit/releases/tag/1.65.0), Apache-2.0, pushed October 3. Dates appear in the comparison table. Streamlit transitive Python 3.14 wheels were not installed; browser JS has no Python wheel issue. React/Next current releases and Prometheus server version were not independently verified.

## Inconsistent

- [OWASP canonical README](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10) says August 4, 2026; prior research said August 3. Canonical IDs were verified.
- Cedar CLI 4.13.0 differs from cedarpy 4.12.1/core 4.12.0. casbin/pycasbin package names have different releases. OTel metric and span token names differ; MCP conventions reference older transport; OCSF proposed AI classes differ from its released profile. Primary links above preserve distinctions.
- Prior parser advice missed PyYAML off=false/duplicate last-wins; local checks motivate YAML 1.2.

## Could not establish

Full typed compiler, concurrent realistic authorization and durable disk latency; Docker Desktop watchers; current React/Next/Prometheus versions; ruamel repository push; Streamlit/SDK transitive Python 3.14 wheels; Regorus distribution/opa-wasm compatibility; stable GenAI schema/final sessionless MCP conventions; local classifier FPR/latency/model cost/tokenizer accuracy; complete SSRF rebinding defense; legal AGPL/GDPR compliance. Only stated microbenchmarks were measured; no Ollama interaction.

## Recommendation for the MVP

[REC] One native FastAPI 0.142.2 worker, custom bounded rules, Pydantic 2.13.5, ruamel.yaml 0.19.1, watchfiles 1.3.0 (debounce=200/step=25, poll=250 ms). Immutable hash snapshots, last-good rejection/startup lockdown, persistent spend/reservations outside config. JSONL/HMAC chain plus independent anchor, SQLite index/ledger, restricted 7-day evidence/90-day metadata, JSONL/CSV/CEF exports, prometheus-client 0.26.0 /metrics and Server-Timing; optional OTel 1.45.0. Static Chart.js 4.5.1/native SSE, all six tabs, separate admin auth, no paid API or raw-content telemetry.

Effort [INFERENCE]: policy 5-7 h, audit/metrics 4-6 h, dashboard 5-8 h, fixtures 2-3 h; transport/detectors/ledger extra. NOT RECOMMENDED FOR MVP: new PDP/WASM/solver/ReBAC/Grafana/React/OTLP/full OCSF -> bounded local rules/dashboard/mappings. Cut fancy presentation, not last-good behavior, budget preservation, approval rechecks, HMAC privacy/export proof.

Judge proof: edit -> next hash/decision <2 s; invalid file -> last good + failure event; lowered cap -> deny without reset; feed update -> new signature/hash; blocked call -> no upstream and one KPI; audit alteration -> verification failure. Production adds signed reviewed artifacts, per-replica activation, shared ledger, key custody/evidence encryption and Cedar-or-OPA authorization after parity tests; detectors/transforms/accounting remain outside it.

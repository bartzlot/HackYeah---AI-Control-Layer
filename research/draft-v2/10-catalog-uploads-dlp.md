# 10 - Catalog, uploads, human DLP, usage: what do shadow-AI app control, file-upload DLP and human-usage governance need, and which open data and libraries (with licences) can we use?

Verified 2026-10-03 against GitHub API, PyPI JSON, Hugging Face API and vendor pages (links inline). Timings were measured on this arm64 Mac in a throw-away Python 3.13 venv (script not committed). `[INFERENCE]` = reasoning or unmeasured target. Boundary: protocols and onboarding are in sibling files.

## Established

### A. Catalog seed data

| Source | Licence | Freshness | Content | Verdict |
|---|---|---|---|---|
| [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) `category-ai-!cn` | MIT | repo push 2026-10-02, file commit 2026-09-29 | 54 lines + 20 `include:` (openai, anthropic, perplexity, github-copilot, huggingface, xai, cursor, windsurf, groq, elevenlabs, poe, manus...); `category-ai-cn` 64 lines; `domain:/full:/regexp:`, `@ads` tags | **Seed.** Only maintained permissive per-vendor list found |
| Caesarovich/dns-blocklist-ai (MIT, 2025-03, ~100 lines); laylavish HUGE-AI-Blocklist (CC0, sites that contain AI-generated content, wrong semantics); mortis2600/ai-blocklist (no licence) | mixed | stale | chatbot lists | cross-check only / unusable |
| SukkaW/Surge (AGPL), MetaCubeX/meta-rules-dat + Loyalsoldier (GPL-3.0), blackmatrix7 (GPL-2.0), hagezi (GPL-3.0, no AI list) | copyleft | daily | repackaged v2fly | do not ship |
| Vendor allowlist docs | facts | 2026 | official hosts | authoritative for the first 8 apps |

`[INFERENCE]` Seed = v2fly (keep its LICENSE in `catalog/NOTICE`) + own entries from vendor docs. No DNS-category product offers a downloadable AI list.

| App | Hosts from primary sources |
|---|---|
| ChatGPT | `*.chatgpt.com *.openai.com *.oaistatic.com *.oaiusercontent.com *.oaistatsig.com *.auth.openai.com chat.openai.com`; WebSocket `wss://ws.chatgpt.com`, Codex `wss://chatgpt.com/`; voice UDP 3478 ([OpenAI](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps)); v2fly adds `chat.com sora.com chatgpt.livekit.cloud` |
| Claude | `anthropic.com claude.ai claude.com claude.dev clau.de claudeusercontent.com claudemcpclient.com` (v2fly); tenant doc names `claude.ai, api.anthropic.com, claude.com, anthropic.com` |
| Gemini | Google lists 34 hosts but only `gemini.google.com` is specific; rest shared (`www.google.com`, `www.googleapis.com`, `apis.google.com`...) ([Google](https://knowledge.workspace.google.com/admin/gemini/gemini-app-firewall-settings), 2026-10-01) |
| Copilot | `copilot.microsoft.com copilot.cloud.microsoft copilot.com`; GitHub: `githubcopilot.com copilot-proxy.githubusercontent.com copilotprodattachments.blob.core.windows.net` |
| Others | Perplexity `perplexity.ai pplx.ai ppl-ai-file-upload.s3.amazonaws.com`; DeepSeek `deepseek.com deepseeksvc.com`; hub `huggingface.co hf.co hf.space` |

`[INFERENCE]` Shared Google/Microsoft hosts need `host + path/header` matching; M365 Copilot for work is not separable by SNI.

### B. How incumbents rate AI apps

| Product | Model |
|---|---|
| Netskope CCI ([docs](https://docs.netskope.com/en/cci-cloud-apps)) | 0-100, five levels: Excellent 90-100, High 75-89, Medium 60-74, Low 50-59, Poor <50; CSA-based (security, audit-ability, business continuity), category-specific rewards/penalties; "50+ attributes", 370+ genAI apps ([page](https://www.netskope.com/products/securing-generative-ai)) |
| Defender for Cloud Apps ([docs](https://learn.microsoft.com/en-us/defender-cloud-apps/risk-score), 2026-07-03) | 31,000+ apps, 90+ factors, 0-10 per property, subscores General/Security/Compliance/Legal; admin re-weight, override, tags Sanctioned/Unsanctioned; categories **Generative AI**, **AI - Model Provider**, **AI - MCP Server**; filters SOC 2, ISO 27001; unsanctioned -> block indicators, vendor URL drift documented as a weakness |
| Cloudflare Gateway ([guide](https://developers.cloudflare.com/learning-paths/holistic-ai-security/build-security-policies/set-policy-approval)) | category "Artificial Intelligence" + approval status; block page coaching or redirect to approved tool; Prompt Capture by identity group; DLP rule ordered before allow |

### C. Risk attributes (facts for the seed)

| App / tier | Trains on inputs by default | Retention / residency | Source |
|---|---|---|---|
| ChatGPT Free/Plus | **yes**, opt-out; thumbs feedback sends the whole chat even after opt-out; temporary chats excluded | - | [OpenAI](https://help.openai.com/en/articles/5722486-how-your-data-is-used-to-improve-model-performance) |
| ChatGPT Business/Enterprise/Edu, API | **no** by default | - | same |
| Claude Free/Pro/Max | user choice (forced since 2025-10-08); 5 y retention if allowed, else 30 d; Work/API/Gov/Edu/Bedrock/Vertex not affected | 30 d or 5 y | [Anthropic](https://www.anthropic.com/news/updates-to-our-consumer-terms) |
| Gemini Apps | **yes** while Keep Activity (default on) is on, human reviewers; reviewed copies up to 3 y (secondary) | - | [hub](https://support.google.com/gemini/answer/13594961?hl=en), [notebookcheck](https://www.notebookcheck.net/Google-Gemini-keeps-reviewed-chats-for-three-years.1389300.0.html) |
| DeepSeek | data stored on servers in the PRC; training with opt-out (secondary) | **China**, "as long as necessary" | [policy 2026-02-10](https://cdn.deepseek.com/policies/en-US/deepseek-privacy-policy.html), [WIRED](https://www.wired.com/story/deepseek-ai-china-privacy-data) |

SOC 2 / ISO 27001 per vendor not collected; seed marks `unknown`.

### D. Tenant-restriction headers (proxy injects, vendor enforces)

| Vendor | Header | Notes |
|---|---|---|
| ChatGPT Business/Ent | `ChatGPT-Allowed-Workspace-Id: <uuid,...>` | [Cloudflare](https://developers.cloudflare.com/learning-paths/holistic-ai-security/build-security-policies/set-policy-approval), [Palo Alto](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA1Ki000000kAa6KAE&lang=en_US) (also block `backend-anon`); [OpenAI](https://help.openai.com/en/articles/20001323-corporate-network-controls-in-chatgpt-enterprise) |
| Anthropic Enterprise/Console | `anthropic-allowed-org-ids: <uuid,...>` | covers web, desktop, **API keys**, OAuth; `;n=K` continuation headers (max 10 lines / 500 UUIDs); overwrite, never append; wrong org = 403 `tenant_restriction_violation`; TLS inspection required ([help](https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions)) |
| Google | `X-GoogApps-Allowed-Domains`; Code Assist `X-GeminiCodeAssist-Allowed-Domains` | [Workspace](https://knowledge.workspace.google.com/admin/security/block-access-to-consumer-accounts), [Code Assist](https://docs.cloud.google.com/gemini/docs/codeassist/network-access) |

`[INFERENCE]` The Anthropic header makes personal API keys fail at the vendor: cheapest personal-vs-corporate key control.

### E. Catalog schema `aicl-catalog/1` (`catalog/apps.yaml` in the signed bundle, 07 section 9)

```yaml
- id: chatgpt-web
  name: ChatGPT
  vendor: OpenAI
  category: chat        # chat | coding | image_video | voice | api | model_hub | browser_agent | search | other
  match:                # first match wins; decrypt=true only for these hosts (07 D1)
    - {host: "chatgpt.com", decrypt: true}
    - {host: "*.oaiusercontent.com", decrypt: true, role: upload}
    - {host: "ws.chatgpt.com", decrypt: true, role: stream}
    - {host: "content-push.googleapis.com", path_prefix: "/upload", role: upload}   # shared-host form (Gemini)
  adapter: {kind: precise, id: chatgpt_web}    # precise = parsed prompt+files; generic = text sniff + size
  tiers:
    consumer: {risk: {score: 55, reasons: [TRAIN_DEFAULT, CONSUMER_TIER, NO_TENANT_CTRL]}, default_action: coach}
    business: {risk: {score: 15, reasons: [PROCESSOR_DPA]}, default_action: sanctioned}
  tenant_restriction: {header: ChatGPT-Allowed-Workspace-Id, value_from: "tenant.chatgpt_workspace_ids"}
  attrs: {trains_on_inputs_default: {consumer: true, business: false}, residency: [unknown], soc2: unknown, iso27001: unknown}
  limits: {max_upload_mb: 512}
  evidence: ["https://help.openai.com/en/articles/5722486"]
  reviewed: 2026-10-03
  source: {origin: v2fly+vendor-doc, license: MIT}
```
- **Actions**: `sanctioned` (inspect, allow), `coach` (strict DLP, banner or justification, audited), `unsanctioned` (block page). Unknown AI-looking domain = `unreviewed`, SNI logged only, handled as `coach` `[INFERENCE]`.
- **Risk score** (proposal, high = worse, cap 100): TRAIN_DEFAULT 25, CN_RESIDENCY 30, HUMAN_REVIEW 10, NO_RETENTION_CONTROL 10, CONSUMER_TIER 15, NO_SOC2_ISO 10, NO_TENANT_CTRL 5, UNKNOWN_VENDOR 20; labels reuse CCI cut points on 100 minus score. DeepSeek = 30+25+15+10 = 80 -> Poor -> `unsanctioned`.
- **Import**: converter turns v2fly lines into `match`, drops `@ads`; tenant overrides in `policy/local.d/catalog.d/*.yaml` (tier, action, tenant ids), hot reload as 07 section 8.

### F. How uploads travel

| App | Flow | Hosts / limits | Confidence |
|---|---|---|---|
| ChatGPT web | `POST /backend-api/files {file_name,file_size,use_case}` -> `{file_id, upload_url}`; **`PUT upload_url`** raw bytes with `x-ms-blob-type: BlockBlob` (Azure presigned); `POST /backend-api/files/{id}/uploaded` -> `download_url`; message refs `file-service://<id>` | `chatgpt.com` + `*.oaiusercontent.com` (error text names `files.oaiusercontent.com`); 512 MB, 2M tokens ([FAQ](https://help.openai.com/articles/8555545)) | first-party client [openai/codex files.rs](https://github.com/openai/codex/blob/main/codex-rs/codex-api/src/files.rs); web use cases from community [gpt4free](https://github.com/xtekky/gpt4free/blob/main/g4f/Provider/needs_auth/OpenaiChat.py) |
| Claude web | **multipart POST** `/api/{org}/upload` (images, PDFs); `/api/organizations/{org}/convert_document` (other docs, server-side extraction); code files `.../wiggle/upload-file` | `claude.ai`; 500 MB, 20 files, PDF 1000 pages ([help](https://support.claude.com/en/articles/8241126-upload-files-to-claude)) | community [Claude-QoL](https://github.com/lugia19/Claude-QoL/blob/main/content/helpers/claude-api.js); API `POST /v1/files` ([docs](https://platform.claude.com/docs/en/api/files/upload)) |
| Gemini web | **multipart POST** with `Push-ID`, `X-Tenant-Id: bard-storage` -> id like `/contrib_service/ttl_1d/...`, later referenced by the prompt | `content-push.googleapis.com/upload` (shared host); 10 files, 100 MB, video 2 GB ([help](https://support.google.com/gemini/answer/14903178)) | community [Gemini-API](https://github.com/HanaokaYuzu/Gemini-API/blob/master/src/gemini_webapi/utils/upload_file.py) (AGPL, read only); API resumable `/upload/v1beta/files` ([docs](https://ai.google.dev/gemini-api/docs/files)) |
| Copilot web | `POST /c/api/attachments`, raw body (`content-type: image/...`) or multipart -> `{url}` referenced in chat | `copilot.microsoft.com`; limits not found | community [gpt4free](https://github.com/xtekky/gpt4free/blob/main/g4f/Provider/CopilotLeagcy.py) (GPL, read only) |
| Perplexity | upload to S3 bucket | `ppl-ai-file-upload.s3.amazonaws.com` | [v2fly](https://github.com/v2fly/domain-list-community/blob/master/data/perplexity) |

`[INFERENCE]` consequences:
- Bytes travel on a **different request** (blob PUT or multipart) than the prompt: file DLP is its own stage keyed on `role: upload`; the chat message only carries a reference. Block the PUT/multipart (user sees an upload error) and cache the verdict per `file_id`/sha256.
- Name, size and type are known before the body: decide in `requestheaders` (Content-Length, multipart, `x-ms-blob-type`) to reject oversize without buffering.
- mitmproxy `stream_large_bodies` streams over a threshold and **streamed bodies cannot be modified**; `store_streamed_bodies` keeps them ([source](https://github.com/mitmproxy/mitmproxy/blob/main/mitmproxy/addons/proxyserver.py)). Cap `max_scan_mb` = 25; above it `block` or `allow + audit unscanned` per tier.
- OpenAI tells admins to disable TLS inspection for the macOS app: keep a per-app bypass.

### G. File pipeline: measurements and safety

| Step | Library | Measured (p50) | Note |
|---|---|---|---|
| type, magic bytes | filetype 0.01 ms; puremagic 0.2 ms; magika 1.8-2.6 ms | 8 KB prefix | puremagic labelled an xlsx as docx; filetype correct; Magika gave `unknown` for a big xlsx prefix, correct on full file: pass full spooled file |
| docx | python-docx | 19 ms / 1500 paragraphs (47 KB) | headers/footers via `section.header`; watermark = VML in `word/header*.xml` |
| xlsx | openpyxl `read_only` | 35 ms / 10k cells | docs: **no protection against quadratic blowup / billion laughs, install defusedxml** ([docs](https://openpyxl.readthedocs.io/en/stable/index.html)) |
| pptx | python-pptx | 4.6 ms / 40 slides | pulls Pillow, XlsxWriter, lxml |
| pdf | pypdf | 2.6 ms / 30 blank pages (not representative) | pdfminer.six as fallback, not timed |
| label | zip + defusedxml | 0.04 ms | section below |

Safety (cheap rules, proposal):
- Spool to a temp file with the cap, delete after the verdict; never serve it back.
- Zip formats: read `ZipInfo` first; reject if uncompressed > 200 MB, > 2000 members, ratio > 100:1 (measured: 200 MB of zeros = 194 KB, ratio 1028:1); nested archive depth 1.
- Extract in a worker **process**: 5 s wall clock, RSS cap, 200 PDF pages, 2 MB text (scan first 1 MB fully, sample rest).
- Macros (`vbaProject.bin`, `.docm/.xlsm/.pptm`) are never executed (these libraries do not run them); flag as `macro_enabled`.
- Encrypted/RMS Office (OLE with `\x06DataSpaces`) and password PDFs: `unscannable_encrypted`; policy decides (block on unsanctioned, allow+audit on sanctioned). `msoffcrypto-tool` needs the password, not RMS.
- No OCR (scanned PDFs, images): type + size + label only.

**Purview sensitivity labels**

| Location | When | Reading |
|---|---|---|
| `docProps/custom.xml`: `MSIP_Label_<GUID>_Enabled / _SiteId (tenant) / _Method (Standard=auto, Privileged=manual) / _Name / _SetDate / _ContentBits (0x1 header, 0x2 footer, 0x4 watermark, 0x8 encrypt) / _ActionId` | legacy, co-authoring off ([MIP SDK](https://learn.microsoft.com/en-us/information-protection/develop/concept-mip-metadata)) | zip + defusedxml; parsed all 5 properties of a synthetic docx |
| `docMetadata/LabelInfo.xml`: `labelList/label {id, siteId, method, enabled, contentBits, removed}`, ns `.../office/2020/mipLabelMetadata` | co-authoring on ([blog](https://informasjonsbeskyttelse.no/en/label-metadata-in-office-documents), [MS-OFFCRYPTO 2.6.4](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/b75503d0-ada1-4eca-adc1-adeb643ab813)) | same zip read; `id` GUID mapped to our label list |
| `\x06DataSpaces\TransformInfo\LabelInfo` stream in the encrypted OLE package ([2.6.2](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/0c4ec12d-aba0-4dd4-8fd1-710da6735219)) | label with encryption | `olefile` reads it; content stays encrypted |
| PDF | key-value pairs persisted in file; PDF is a "labeling only" type ([types](https://learn.microsoft.com/en-us/information-protection/develop/concept-supported-filetypes)); Acrobat embeds header/footer/watermark in the PDF | pypdf `reader.metadata` returned custom `/MSIP_Label_<GUID>_Name` keys in a synthetic PDF; real Acrobat output not tested |

Label GUIDs are tenant-specific (config maps `guid -> Confidential`); another tenant's label = "unlabeled" for us; no label is NOT proof of "public". Visible markings are plain text: scan body, `word/header*.xml`, `footer*.xml`, pptx shapes, PDF page text for per-tenant terms (`CONFIDENTIAL`, `INTERNAL`, `POUFNE`, `TAJNE`...) with Aho-Corasick.

### H. DLP quality for human prompts

| ID | Detector | Method | FP control | Licence | Evidence |
|---|---|---|---|---|---|
| DLP-01 | Secrets + AI keys | gitleaks rules to RE2: OpenAI `sk-(proj\|svcacct\|admin)-...T3BlbkFJ...`, Anthropic `sk-ant-api03-...AA`, `sk-ant-admin01-`, plus HF `hf_`, Google `AIza`, Groq `gsk_`, xAI `xai-` | embedded markers (`T3BlbkFJ`, `AA`); entropy only as second signal | MIT ([rules](https://github.com/gitleaks/gitleaks/tree/master/cmd/generate/config/rules), push 2026-09-30) | rules read |
| DLP-02 | PII with checksums | candidate regex, then Luhn, IBAN mod-97, PESEL, NIP, REGON-9, `phonenumbers` (Apache-2.0 9.0.40), e-mail | context words ("PESEL"), own-domain allowlist | own code | all pass on public examples (PESEL 44051401359, NIP 1234563218, REGON 123456785, IBAN PL61...2874); regex 0.12 ms / 10 KB |
| DLP-05 | Source code | Magika language label + structure rule (fence, >= 5 lines, symbol density) | min 150-400 B, label confidence, skip one-line shell | Apache-2.0 | 150 random chunks per corpus from site-packages: 400 B -> Python 94 %, JS 90 % flagged, 11 % of README/LICENSE chunks flagged (contain code blocks, not hand-audited); 150 B 83/70/6 %; 1.5 KB 96/97/4 %; 2-3 ms. Pygments `guess_lexer` rejected (prose = "Tera Term macro", missed Java/SQL/JSON) |
| DLP-06 | Dictionaries | `pyahocorasick` (BSD-3, in stack): codenames, customers, hostnames; word boundary, case-fold | min length 4, stop-list, per-term weight, count threshold | BSD-3 | design |
| DLP-07 | Exact data match | HMAC-SHA256 (gateway secret) truncated to 96 bit in a Python `set`; regex candidates (11 digits, e-mail, names); require primary + supporting element within 200 chars ([Purview EDM](https://learn.microsoft.com/en-us/purview/sit-learn-about-exact-data-match-based-sits)) | corroboration kills collisions | stdlib | 1M records: 0.73 s build, ~53 MB, <0.01 ms per lookup |
| DLP-08 | Fingerprint | own 64-bit simhash (blake2b, 3-word shingles) for near-duplicate documents; 8-word shingle-hash containment for pasted excerpts `[INFERENCE]` | min shingles, drop boilerplate shingles | stdlib; datasketch MIT works but pulls scipy | synthetic 1000 words: simhash 3.1 ms, Hamming 10 (40 words changed) vs 27 (unrelated); MinHash 3.5 ms, Jaccard 0.8 vs 0.0; thresholds need real documents |
| DLP-09 | Label + marking | section G | `Confidential` and app not sanctioned -> block | own | synthetic |

False-positive control, cheapest first:
1. Per-detector rollout `monitor -> redact -> block` by department, with hit/override counters on the dashboard.
2. Checksums and context before any score; entropy alone never blocks.
3. Tier-aware action: same finding = `redact` on sanctioned, `coach` (justify + log) on in-between, `block` on unsanctioned.
4. "False positive" button writes an expiring allowlist to `local.d`; every override is audited.
5. Calibrate on open corpora: [gretelai/synthetic_pii_finance_multilingual](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) and [gretel-pii-masking-en-v1](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1) (Apache-2.0), [nvidia/Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) (CC-BY-4.0); **avoid** ai4privacy pii-masking (licence `other`) and piiranha (CC-BY-NC-ND). Benign prompts from 03.
6. No small permissive code classifier beyond Magika was evaluated; HF `FrameByFrame/programming-language-identification-100plus` (Apache-2.0) and `philomath-1209/...` (WTFPL) are untested options.

### I. Human usage and budget

Account unit: `user + department + device` (identity from the sibling onboarding file); event fields `app_id, tier, channel, bytes, est_tokens, files, usd_est`.

| Metric | How |
|---|---|
| Prompts / day | count message POSTs of `precise` adapters (web apps have no billing; the count is the only exact quantity) |
| Est. tokens | [tiktoken](https://github.com/openai/tiktoken) 0.14.0 (MIT), `o200k_base`: load 4.2 s, 10 KB in 0.6 ms, 200 KB in 4.1 ms, ~3.8 bytes/token. **Offline**: set `TIKTOKEN_CACHE_DIR`; file name = `sha1(vocab URL)` (our run: `9b5ad7...` o200k, `fb374d...` cl100k); vocab is fetched from `openaipublic.blob.core.windows.net`, its licence is not stated: seed once, keep in `var/`, not git. Claude/Gemini tokenizers are not public offline (Anthropic has online [count_tokens](https://platform.claude.com/docs/en/api/messages/count_tokens)): label o200k results `est` |
| API cost | response `usage` x LiteLLM price subset (MIT, 05); web apps = tokens x list price of the nearest model, labelled "equivalent cost" |
| Quotas | scopes `user` and `department` on the 05 ledger: prompts, est tokens, upload MB, USD-equivalent per day/month; soft = coach banner, hard = provider-shaped refusal or 429 |

API-key governance:

| Signal | Mechanism |
|---|---|
| Key class | prefix: OpenAI `sk-proj-/sk-svcacct-/sk-admin-`, Anthropic `sk-ant-api03-/sk-ant-admin01-`, Google `AIza`, HF `hf_` |
| Registered keys | store `HMAC(key)` only. Match vendor-provided hints: OpenAI Admin API `redacted_value` like `sk-abc...def` ([spec](https://github.com/openai/openai-openapi)); Anthropic Admin API `partial_key_hint`, `scope`, `principal` ([type](https://github.com/anthropics/anthropic-sdk-python/blob/main/src/anthropic/types/organization/api_key.py)). Unknown key to a sanctioned vendor = `unregistered_key` event |
| Org/project | OpenAI SDK sends `OpenAI-Organization`, `OpenAI-Project` when set ([client](https://github.com/openai/openai-python/blob/main/src/openai/_client.py)); Anthropic replies carry `anthropic-organization-id` (redacted-header list in SDK tests); may be absent |
| Vendor-side | `anthropic-allowed-org-ids` also rejects personal API keys (section D) |
| Key sharing | distinct users/devices/IPs per `HMAC(key)` in 24 h; alert > 3 (proposal) |
| Entitlement | model from request body x price per Mtok; expensive model (> $10 / Mtok in, proposal) by a non-entitled group = `model_not_entitled` |

Anomaly signals (thresholds are proposals, tune on demo traffic):

| Signal | Rule |
|---|---|
| Huge paste | prompt > 20 KB or > 5000 est tokens or > 3x user's 28-day p95 |
| Bulk/automation | > 30 prompts/min for 5 min, low inter-arrival jitter, non-browser user agent on a web host |
| Off-hours | hour outside user baseline and volume > 3 sigma on EWMA |
| Upload burst | > 10 files or > 100 MB in 10 min to non-sanctioned apps |
| App sprawl | > 5 new unreviewed AI domains per user per day |
| Key anomaly | table above |

### J. Library licence table (PyPI/GitHub, 2026-10-03)

| Item | Version, last release | Licence | Role | Deps / caveat |
|---|---|---|---|---|
| v2fly domain-list-community | push 2026-10-02 | MIT | catalog seed | data |
| magika | 1.0.3, 2026-05 | Apache-2.0 | type + code language | onnxruntime (already), click |
| filetype | 1.2.0, 2022-11 | MIT | magic bytes | none, stale but stable |
| puremagic | 2.2.0, 2026-04 | MIT | magic bytes | none; OOXML ambiguity |
| pypdf | 6.19.0, 2026-09 | BSD-3 | PDF text + metadata | none |
| pdfminer.six | 20260107 | MIT | PDF fallback | charset-normalizer, cryptography |
| python-docx | 1.2.0, 2025-06 | MIT | docx | lxml |
| openpyxl | 3.1.5, 2024-06 | MIT | xlsx | et-xmlfile; needs defusedxml |
| python-pptx | 1.0.2, 2024-08 | MIT | pptx | Pillow, XlsxWriter, lxml |
| defusedxml | 0.7.1, 2021-03 | PSF | safe XML | unmaintained, stable |
| olefile | 0.47, 2023-12 | BSD | OLE label stream | none |
| python-calamine | 0.8.2, 2026-07 | MIT | optional fast xlsx | Rust wheel |
| tiktoken | 0.14.0, 2026-08 | MIT (vocab licence unstated) | token estimates | requests |
| datasketch | 2.0.0, 2026-07 | MIT | optional MinHash | numpy, scipy |
| phonenumbers | 9.0.40, 2026-09 | Apache-2.0 | phone check | none |
| gitleaks rules | push 2026-09-30 | MIT | secrets | data |
| python-stdnum | 2.2 | LGPL | **avoid** (our checksums are 5 lines) | - |
| PyMuPDF | 1.28.2 | AGPL / commercial | **excluded** | - |
| python-magic | 0.4.27 | MIT, needs libmagic C library | **excluded** | no libmagic wanted |
| Gretel PII sets / Nemotron-PII | 2025-12 | Apache-2.0 / CC-BY-4.0 | calibration data | attribution for CC-BY |

## Inconsistent

| Topic | A | B | Choice |
|---|---|---|---|
| Claude upload size | chat 500 MB per file | project files 30 MB (same help article) | per-surface `max_upload_mb`; our cap is lower |
| puremagic vs filetype on xlsx | puremagic: docx | filetype: xlsx | filetype first for OOXML |
| Magika on prefixes | docx/pdf fine on 8 KB | big xlsx `unknown` on 8 KB | feed the full spooled file |
| OpenAI TLS guidance | allowlist these domains | macOS app: disable SSL inspection for all OpenAI domains | decrypt web/API, bypass desktop app by default |


## Could not establish

- Real Acrobat/MIP PDF label location (Info dict vs XMP); only pypdf Info reads were proven, on a synthetic file. Same for real co-authoring `docMetadata/LabelInfo.xml`. One real labelled docx/pdf would close both.
- Shape names of MIP content markings in pptx/docx (no primary source); markings are matched as text.
- `openai-organization` / `openai-project` response headers (request headers verified).
- Claude, Copilot, Gemini web upload paths are community-observed and may have changed; re-capture with mitmproxy before the demo. Copilot (work) upload path and limits unknown.
- Per-vendor SOC 2 / ISO 27001, CCI/MDCA scores of individual AI apps (login-gated).
- tiktoken error vs Claude/Gemini tokenizers; vocab file licence.
- Real text-PDF speed and pdfminer.six timing; DLP precision/recall on real prompts (only synthetic and stdlib-style corpora measured).

## Further

**Recommendation for our build**
1. **Catalog**: v2fly `category-ai-!cn` + `category-ai-cn` through a ~40-line converter, plus 10 hand-curated apps (ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek, Hugging Face, GitHub Copilot, Cursor, OpenAI/Anthropic APIs) with tiers, risk reasons, evidence; schema section E in the signed bundle; tenant overrides in `local.d`; decrypt only `decrypt: true` hosts. 1-2 h.
2. **Upload pipeline** (stage `artifact`, `role: upload`): `requestheaders` (size/type/name) -> spool -> filetype + Magika (2 ms) -> zip guard -> label read (0.04 ms) -> worker-process extraction (5-35 ms for Office, 5 s / 25 MB / 2 MB caps) -> same detector cascade as prompts -> verdict cached per `file_id`/sha256 -> block PUT/multipart or pass. Target added p95 for 1-5 MB Office: < 150 ms `[INFERENCE]`.
3. **Human detectors**: DLP-01/02 (with PL checksums), 05 (Magika), 06, 07 (demo with 1k fake customers), 08 (simhash + shingle containment), 09 (labels/markings). Defaults: redact secrets/PII, block code and labelled files on unsanctioned apps, `coach` in between, `monitor` first.
4. **Usage**: ledger scopes `user` / `department`; o200k estimates (cache seeded once); LiteLLM price subset; soft/hard quotas; HMAC key registry; Anthropic header as vendor-side key control.
5. **Dashboard**. Management: shadow-AI share = (unsanctioned + unreviewed) / all AI requests, active AI users, top apps and departments, sanctioned adoption trend, data-protection events prevented by type, equivalent cost, onboarded-user coverage. Security: user x app x event drill-down, upload/label events, unregistered-key and key-sharing alerts, anomaly list with reasons, override log, policy/feed version per decision.

**Questions for the team**
- Decrypt the ChatGPT/Claude desktop apps, or web and CLI/SDK only?
- What does `coach` do: allow with justification, or allow with redaction only?
- Is SSO identity and department known at the proxy (sibling file), and which departments does the demo show?
- Unscannable files (encrypted, > 25 MB): block or allow + audit?
- Can a teammate supply one real Purview-labelled docx and pdf?
- Is "equivalent cost" for web apps acceptable on the management page?

**Risks**

| Risk | Mitigation |
|---|---|
| Community-observed upload endpoints change; pinning, QUIC, WebSocket | `adapter: generic` fallback by content type; re-capture before demo |
| Blob PUT above `stream_large_bodies` is unmodifiable | threshold = scan cap; decide on headers; `unscanned` verdict |
| Detector `unknown` -> silent allow | `unknown` binary = `unscannable` per tier |
| Parser attacks (zip/XML bombs, malformed PDFs) | ZipInfo pre-check, defusedxml, worker process caps, no macros |
| False positives on code and PII | staged rollout, two-signal rules, feedback allowlist, FP report per detector |
| EDM secret and customer lists are sensitive | truncated HMAC only, secret outside git, rotation note |
| Copyleft lists or libs slip in | v2fly + own data only; section J review |
| Token estimates differ from vendors | label `est`, relative quotas only |
| Seed drifts (vendors add hosts) | feed refresh, `unreviewed` bucket, weekly v2fly sync |

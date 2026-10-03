# 06 - Data leakage prevention: how do we decide that a prompt, file, tool call or response would leak confidential company data, and how does the decision depend on the destination?

Verified 2026-10-03 against primary sources (links inline; HF API, PyPI JSON, GitHub API read the same day).
Legend: `[EST]` established technique, `[EXP]` experimental / research-grade, `[REC]` our architectural recommendation, `[INFERENCE]` reasoning not read anywhere, `[MEASURED]` run locally today (throwaway Python 3.13 venv in /tmp, macOS arm64; stdlib parts on Python 3.14.8; versions stated).

Scope: the regex catalogue (secrets, PII checksums, Polish identifiers) belongs to another slice and to [10 section H](../../ai_layer_control/research/10-catalog-uploads-dlp.md); here it is a signal source. This file covers what the catalogue cannot see: markings, labels, dictionaries, EDM, NER, semantic sensitivity, fingerprints of protected documents, and how the verdict depends on the destination.

## 1. Leak destinations and what changes per destination

Core point `[REC]`: `verdict = f(content class, destination trust tier, requester clearance)`. Microsoft ships the same split: DLP can block prompts containing sensitive info types, block web-search grounding for such prompts, and block Copilot from processing labelled files, as separate rule actions ([Purview DLP for Copilot](https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-learn-about)).

| Destination | Threat examples | What changes in the decision |
|---|---|---|
| External commercial LLM | Samsung engineers pasted source code and meeting notes into ChatGPT; company-wide ban ([AIID 768](https://incidentdatabase.ai/cite/768/), [Bloomberg](https://www.bloomberg.com/news/articles/2023-05-02/samsung-bans-chatgpt-and-other-generative-ai-use-by-staff-after-leak)). Consumer tiers train on inputs by default, business/API do not; DeepSeek stores data in the PRC ([10 section C](../../ai_layer_control/research/10-catalog-uploads-dlp.md)) | trust follows the *account tier*: `approved_external_llm` (DPA, no training) vs `unknown_external`; redact/pseudonymize spans, restore on reply |
| Local LLM (Ollama) | Ollama says locally run prompts are not collected ([privacy](https://ollama.com/privacy)), **but** `-cloud` model tags are forwarded to Ollama's hosted service ([blog](https://ollama.com/blog/cloud-models), [FAQ](https://docs.ollama.com/faq)): localhost is not proof of local execution. The Ollama here is shared with another team (logs, KV cache) `[INFERENCE]` | trust by *model tag* in a registry, not by host; `-cloud` -> external. Highest trust, but log hashes not raw text for CONFIDENTIAL+ |
| MCP server | postmark-mcp 1.0.16 BCC'd every email to an attacker ([Dark Reading](https://www.darkreading.com/application-security/malicious-mcp-server-exfiltrates-secrets-bcc), [THN](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html)); tool poisoning and WhatsApp-history exfil ([Invariant](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [WhatsApp](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)). MCP spec 2026-07-28: clients MUST treat tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) as untrusted unless the server is trusted ([tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)) | per-server trust tier from our registry (configured id + pinned URL/command hash, never self-declared); unknown server: block INTERNAL+ in arguments; annotations are hints, never an allow |
| Another agent (A2A, sub-agent) | agent-card spoofing, capability cloaking ([A2ASecBench poster](https://www.ieee-security.org/TC/SP2026/downloads/posters/sp2026posters-final51.pdf), [Red Hat](https://next.redhat.com/2026/05/13/securing-agent-to-agent-communication)); transitive leak via a receiver with an external tool `[INFERENCE]` | destination = (agent id from gateway-issued token, clearance); content above clearance blocked or summarised; labels travel with messages (section 8) |
| External API / webhook / URL | EchoLeak CVE-2025-32711: auto-fetched reference-style Markdown images carry data in the URL ([paper](https://arxiv.org/abs/2509.10540), [NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-32711)); ForcedLeak: expired allowlisted domain ([Noma](https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce)); [MSRC](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks) blocks these deterministically | default `unknown_external`: anything above PUBLIC blocked; host allowlist with expiry; scan URL and body |

Closest open gateway DLP documentation, Cloudflare AI Gateway: request, response or both; only `Flag` or `Block`; per gateway, no per-request profile; buffers the whole stream before scanning; no base64 decoding; cache hits skip DLP ([docs](https://developers.cloudflare.com/ai-gateway/features/dlp/)). No redaction, no destination awareness: our gap.

## 2. Static DLP beyond basic secrets/PII

Each detector emits `Finding{type, class, span, confidence, source}`; message class = max over findings (section 7).

| Signal | How | Cost | FP control |
|---|---|---|---|
| Visible markings (`CONFIDENTIAL`, `INTERNAL ONLY`, `POUFNE`, `TAJNE`) | Aho-Corasick over NFKC + casefold + zero-width-stripped text, plus docx/pptx headers, footers, watermarks, PDF page text ([10 section G](../../ai_layer_control/research/10-catalog-uploads-dlp.md)) | <0.1 ms | whole word; higher confidence in header/footer or first/last 200 chars; a policy text that *describes* markings is the classic FP |
| Embedded sensitivity labels | `docProps/custom.xml` `MSIP_Label_<GUID>_Name/_Enabled/_SiteId/_Method/_ContentBits`; `docMetadata/LabelInfo.xml` (co-authoring); PDF Info dict; encrypted OLE `\x06DataSpaces` ([MIP SDK](https://learn.microsoft.com/en-us/information-protection/develop/concept-mip-metadata), [MS-OFFCRYPTO 2.6.4](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/b75503d0-ada1-4eca-adc1-adeb643ab813)); zip + `defusedxml` 0.04 ms (measured in 10) | 0.04 ms | GUIDs are tenant-specific: map `guid -> class`; foreign GUID = unlabeled; no label is not PUBLIC |
| Dictionaries (codenames, customers, hostnames) | `pyahocorasick` 2.3.1 (BSD-3, py>=3.10, arm64 wheel, 2026-04) or `ahocorasick-rs` 1.0.3 (Apache-2.0); word boundary, casefold, diacritic fold, per-term class and weight | sub-ms for 10k terms `[INFERENCE]` | min length 4, stop-list, weak terms need a second cue |
| Exact Data Match | Purview model: hashed record values; **primary element** (regex/checksum) first, then **supporting elements** nearby raise confidence; up to 100M rows ([Purview EDM](https://learn.microsoft.com/en-us/purview/sit-learn-about-exact-data-match-based-sits)). Ours: HMAC-SHA256 with a gateway secret truncated to 96 bit in a `set`; 1M records 0.73 s build, ~53 MB, <0.01 ms lookup (measured in [10 DLP-07](../../ai_layer_control/research/10-catalog-uploads-dlp.md)) | <0.01 ms | require primary + >=1 supporting within 200 chars; same normalisation at index and query; secret outside git |
| Document fingerprints | section 6 | 0.3 ms | df filter, boilerplate list |
| Structured IDs (`ACME-FIN-2026-00417`) | config regex | <0.1 ms | anchored prefix, check digit |

Marking regex `[REC]` (over normalised text; confidence 0.6 alone, 0.9 in header/footer `[INFERENCE]`):

```
(?i)(?<![\w-])(strictly\s+confidential|confidential|internal\s+use\s+only|internal\s+only|do\s+not\s+(forward|distribute|share)|company\s+secret|poufne|ściśle\s+poufne|tajne|do\s+użytku\s+wewnętrznego|nie\s+rozpowszechniać)(?![\w-])
```

Caution `[EST]`: classifiers trained on text that still contains markings learn the marking. On 16,000 diplomatic cables, TF-IDF + logistic regression scored 99.0% on raw (marker-leaky) text and 86.26% after marker removal; best clean model BERT 89.14% accuracy ([arXiv 2608.16928](https://arxiv.org/abs/2608.16928); 2-class, US cables, not enterprise data). So: markings are their own deterministic signal; strip them from classifier exemplars; do not expect better than ~85-90% semantic accuracy.

## 3. NER for PERSON, EMAIL, PHONE, ORG, LOCATION, FINANCIAL, CREDENTIALS

Split `[REC]`: EMAIL, PHONE, FINANCIAL (Luhn, IBAN mod-97, PESEL/NIP/REGON) and CREDENTIALS are pattern + checksum problems for the regex slice (Presidio has EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, IBAN_CODE, IP_ADDRESS, URL and `PL_PESEL` as its only Polish recognizer, [entities](https://github.com/microsoft/presidio/blob/main/docs/supported_entities.md)). NER is needed for PERSON, ORG, LOCATION and zero-shot custom labels.

**Presidio** 2.2.364 (MIT, 2026-07-22, py `<3.15,>=3.10`, push 2026-09-29; [PyPI](https://pypi.org/project/presidio-analyzer/), [repo](https://github.com/microsoft/presidio)); built-in `GLiNERRecognizer` (`presidio-analyzer[gliner]`, 250-char chunks, 50 overlap, [doc](https://github.com/microsoft/presidio/blob/main/docs/samples/python/gliner.md)); other languages need own NLP config and recognizers ([languages](https://github.com/microsoft/presidio/blob/main/docs/analyzer/languages.md)).

`[MEASURED]` Presidio 2.2.364 + spaCy 3.8.16 + `en_core_web_sm` 3.8.0, one core, synthetic text with e-mail/phone/card/IBAN/IP/name/org/city:

| Config | 0.4 KB p50 | 10 KB p50 | Types found |
|---|---|---|---|
| `en_core_web_sm` NER on | 7.2 ms (p95 8.2) | 158 ms | CREDIT_CARD, DATE_TIME, EMAIL, IBAN, IP, LOCATION, ORGANIZATION, PERSON, PHONE, URL |
| blank spaCy, patterns only | 1.8 ms | 48 ms | CREDIT_CARD, EMAIL, IBAN, IP, PHONE, URL |

Chunk inputs >10 KB `[INFERENCE]`.

| Model | Date | Licence | Size | Polish | Notes | Verdict |
|---|---|---|---|---|---|---|
| spaCy `en_core_web_sm` | 3.8.0 | MIT (not re-read) | 12 MB | no | Presidio default | use for EN |
| spaCy `pl_core_news_*` | HF 2023-10 | **GPL-3.0** ([meta](https://raw.githubusercontent.com/explosion/spacy-models/master/meta/pl_core_news_sm-3.8.0.json), [HF](https://huggingface.co/spacy/pl_core_news_lg)); sm `ents_f` 0.804 | 12-500 MB | yes | copyleft | **do not ship** |
| [urchade/gliner_multi_pii-v1](https://huggingface.co/urchade/gliner_multi_pii-v1) | 2024-04 | Apache-2.0 | ~290M | **no** (en fr de es pt it) | Presidio's example model | EN/DE/FR |
| [knowledgator/gliner-pii-{edge,small,base,large}-v1.0](https://huggingface.co/knowledgator/gliner-pii-large-v1.0) | 2025-09..2026-05 | Apache-2.0 | edge ONNX 181 MB (46 MB quint8) | English card | F1 81.0 base / 83.3 large, vendor synthetic set ([03](../../ai_layer_control/research/03-semantic-models.md)) | **EN custom labels** |
| [knowledgator/gliner-x-{small,base,large}](https://huggingface.co/knowledgator/gliner-x-base) | 2026-04 | Apache-2.0 (MT5 encoder) | ~0.3 / 0.49 / 0.86 B (small: 1.2 GB fp32, ONNX int8 173 MB) | **listed, Polish example in card**; benchmark table has no Polish row | LLM-annotated FineWeb-2 | **best Polish zero-shot candidate, unvalidated** |
| [nvidia/gliner-PII](https://huggingface.co/nvidia/gliner-PII) | 2025-12 | **NVIDIA Open Model License** | - | en | not OSI | avoid |
| [openai/privacy-filter](https://huggingface.co/openai/privacy-filter) | 2026-04 | Apache-2.0 | 1.5B total, ~50M active, 128k ctx | "primarily English" | 8 fixed labels (account_number, private_address, private_email, private_person, private_phone, private_url, private_date, secret); **labels not configurable at runtime**; card admits missed uncommon names and project-specific tokens | strong EN tier, heavier than GLiNER-edge |
| [tabularisai/eu-pii-safeguard](https://huggingface.co/tabularisai/eu-pii-safeguard) | 2026-09-02 | Apache-2.0 | 559M | **F1 96.63% (vendor)** | 42 types, latency unpublished | optional PL tier |
| [pczarnik/herbert-base-ner](https://huggingface.co/pczarnik/herbert-base-ner) | 2025-01 | CC-BY-4.0 | ~124M | yes | WikiANN PER/ORG/LOC; attribution | PL fallback |
| [piiranha](https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information), [Isotonic ai4privacy deberta](https://huggingface.co/Isotonic/deberta-v3-base_finetuned_ai4privacy_v2), [wikineural](https://huggingface.co/Babelscape/wikineural-multilingual-ner) | 2023-25 | **CC-BY-NC-ND / CC-BY-NC / CC-BY-NC-SA** | 180-280M | - | non-commercial | **reject** (ai4privacy datasets: licence `other`, [10](../../ai_layer_control/research/10-catalog-uploads-dlp.md)) |

`gliner` 0.2.29 (Apache-2.0, 2026-09-08, [PyPI](https://pypi.org/project/gliner/)) needs torch; Presidio + gliner + sentence-transformers + torch 2.14.1 = 1.1 GB venv, installs on Python 3.13 / macOS arm64.

`[MEASURED]` `knowledgator/gliner-pii-edge-v1.0`, fp32 PyTorch, 10 zero-shot labels, threshold 0.4: **CPU p50 20 ms (0.4 KB), 106 ms (3 KB); MPS 29 ms / 145 ms** (MPS slower at these sizes; load 19 s cold, 2.4 s warm). English: e-mail, phone, card, ORG `Northwind Logistics`, LOC `Warsaw`, PERSON `John Smith` (0.49) and `Project Falcon` as `project codename` (0.71) found; IBAN prefix `GB82` mislabelled `project codename`. Polish (English-only model): `Jana Kowalskiego` PERSON 0.44, `Gdańsku` LOC 0.60, `Projekt Sokół` **missed**, `Zielona Energia` labelled `location`, PESEL labelled `bank account number`, internal host labelled `project codename`. Lesson: zero-shot GLiNER is a second opinion with scores 0.4-0.7; dictionaries and checksums stay authoritative.

`[REC]`: Presidio patterns + `en_core_web_sm` (~7 ms) as tier 1; one GLiNER model as tier 2 only when no tier-1 CRITICAL finding exists and the destination is below `local_model`; `gliner-x-base` if Polish matters, else `gliner-pii-edge`. `[NOT RECOMMENDED FOR HACKATHON MVP: fine-tuning a Polish PII model -> Presidio patterns + PL checksums + dictionaries + gliner-x zero-shot.]`

## 4. Custom enterprise entities

| Entity | Implementation | FP control |
|---|---|---|
| `INTERNAL_PROJECT` | policy dictionary -> Aho-Corasick with boundary; GLiNER `project codename` as second opinion | min length 4, stop-list, project cue (`projekt`, `project`) for weak words |
| `CUSTOMER_NAME` | CRM export dictionary (or HMAC set for EDM); GLiNER `customer name` / `organization` for unknown names | capitalised form or >=2 tokens |
| `SOURCE_CODE` | Magika 1.0.3 (Apache-2.0, py>=3.8, arm64 wheel, [PyPI](https://pypi.org/project/magika/)) language label + structure rule (fence, >=5 lines, symbol density); [10 DLP-05](../../ai_layer_control/research/10-catalog-uploads-dlp.md): 400 B chunks flagged 94% Python / 90% JS, 11% of README chunks false positive, 2-3 ms | min 150-400 B, label confidence; internal markers (license headers, repo hosts, `import acme_*`) via dictionary |
| `INTERNAL_HOST` | DNS-suffix list (`*.corp.example.local`, `*.internal`, `*.svc.cluster.local`) + RFC 1918 CIDRs over hostnames/URLs/IPs; no DNS resolution | closed deterministic list |
| `CONFIDENTIAL_DOCUMENT_ID` | config regex `\b(ACME|AC)-(DOC|FIN|LEG)-\d{4}-\d{4,6}\b` + optional check digit; registry of issued ids | anchored prefix; registry hit raises confidence |

Polish inflection `[MEASURED]` (pyahocorasick 2.3.1, simplemma 2.0.0, rapidfuzz 3.14.6): 4 terms (`Projekt Sokół`, `Zielona Energia`, `Północ Logistyka`, `Kowalski Logistics`), 14 positive sentences (cases such as `w projekcie Sokół`, `Sokoła`, `Zieloną Energią`, `Północy Logistyki`, upper case, missing diacritics) and 7 near-miss negatives (`sokół wędrowny to ptak`, `Zielona energia słoneczna jest tania`):

| Matcher | Recall /14 | FP /7 | Per sentence |
|---|---|---|---|
| AC exact + boundary + casefold | 7 | 1 | 1 us |
| AC on simplemma lemmas + diacritic fold | 13 (`Sokoła` lemma unchanged) | 1 | 3 us |
| diacritic-folded 5-char token prefixes + boundary | **14** | 1 | 4 us |
| `rapidfuzz.partial_ratio` >= 85 / >= 92 | 13 / 12 | 1 / 1 | 7 us |

The one FP (`Zielona energia słoneczna`) is common to all matchers: a dictionary ambiguity, fixed by a capitalisation or cue rule, not by a better matcher. Libraries: `rapidfuzz` 3.14.6 (MIT, 2026-08-30, py>=3.11), `simplemma` 2.0.0 (MIT, 2026-08-12; README lists `pl` with lemma score 0.96 on UD PL-LFG); `morfeusz2` and `pystempel` licences not read, skipped.

`[REC]`: AC over diacritic-folded 5-char token prefixes (one pass, 4 us); exact AC for case-sensitive terms; `rapidfuzz` only for typo tolerance on multi-token names.

## 5. Semantic sensitivity classification PUBLIC / INTERNAL / CONFIDENTIAL / SECRET

| Approach | Setup, licence | Cost | Evidence | Live-editable | Verdict |
|---|---|---|---|---|---|
| Zero-shot NLI | [deberta-v3-large-zeroshot-v2.0](https://huggingface.co/MoritzLaurer/deberta-v3-large-zeroshot-v2.0) MIT 435M; [bge-m3-zeroshot-v2.0](https://huggingface.co/MoritzLaurer/bge-m3-zeroshot-v2.0) MIT 568M multilingual; bart-large-mnli MIT | one pass per label, 100-300 ms `[INFERENCE]` | none found for sensitivity | label text | weak: "confidential" is org-specific; skip |
| Embeddings + exemplars (centroid / kNN) | 20-50 exemplars per class; `bge-m3` MIT 1.2 GB or `paraphrase-multilingual-MiniLM-L12-v2` Apache-2.0 | 8 ms per 60-word chunk (measured) | geoscience study: generative VLM zero-shot 82% vs embedding model 63% ([arXiv 2604.04997](https://arxiv.org/abs/2604.04997), other domain) | **yes** | **build** |
| SetFit | 8 examples/class ([paper](https://arxiv.org/abs/2209.11055)); `setfit` 1.2.0 Apache-2.0 | needs a training step | sentiment results only | no | NOT RECOMMENDED FOR HACKATHON MVP -> kNN over exemplars |
| LLM judge with rubric | rubric in `instructions`, untrusted text in `state` (`clef-flash`, `qwen3.5:4b`; [03](../../ai_layer_control/research/03-semantic-models.md)) | 0.3-1.2 s `[INFERENCE from 03]` | Zscaler, Netskope productise LLM classification ([Zscaler](https://www.zscaler.com/resources/data-sheets/zscaler-data-protection-benefits.pdf), [Netskope](https://docs.netskope.com/en/ai-ml-usage-and-governance-in-netskope-products)); no open accuracy | **yes** | ambiguous band only |
| TF-IDF + LR | needs labelled corpus | <1 ms | 86.26% clean 2-class (2608.16928) | no | we have no corpus |

`[REC]` cascade: (a) deterministic findings set a floor class; (b) embedding kNN over ~4 x 25 marking-stripped exemplars gives class probabilities (thresholds `[INFERENCE]`, calibrate on demo data; see the 0.60 near-miss in section 6); (c) judge only if the matrix would change the verdict; (d) class = max(floor, semantic). A preprint "PolicyGuard" on prompt-configurable semantic DLP was **withdrawn** by its authors ([arXiv 2608.02687](https://arxiv.org/abs/2608.02687)): do not cite its numbers. Do not claim semantic accuracy in the demo; show the mechanism (live exemplar edit) and the self-test results.

## 6. Protected-document fingerprinting

### Algorithm comparison

| Method | Partial paste | Light edits | Short fragments | Licence | `[MEASURED]` below |
|---|---|---|---|---|---|
| Exact hash of normalised sentences | whole sentences only | **no** | needs full sentence | stdlib | not run (brittle by construction) |
| Rabin-Karp all k-grams | yes | partial | yes | stdlib | 2.5x winnowing storage at w=4 |
| **Winnowing** (Schleimer, Wilkerson, Aiken, SIGMOD 2003) | **yes**, any shared substring >= t = w+k-1 tokens guaranteed | yes | needs >= t tokens | stdlib | best |
| MinHash + LSH (`datasketch` 2.0.0, MIT, 2026-07-05; numpy, scipy) | only if chunk size ~ paste size; containment variant: [LSH Ensemble](https://ekzhu.com/datasketch/lshensemble.html) | partial | weak | MIT | 15.4 MB, recall drops fast |
| SimHash (Charikar 2002) | **no** (whole-doc) | near-duplicate docs | no | stdlib | indistinguishable from unrelated |
| ssdeep / ppdeep | no | big files only | **fails** | ssdeep GPL-2.0 ([repo](https://github.com/ssdeep-project/ssdeep)), PyPI `ssdeep` LGPLv3+; `ppdeep` Apache-2.0 | 0 at 10% edit |
| TLSH (`py-tlsh` 5.0.0; [Apache OR BSD](https://github.com/trendmicro/tlsh)) | no | multi-KB files | **min 50 B** (256 in conservative mode) ([README](https://github.com/trendmicro/tlsh/blob/master/README.md)) | dual | `TNULL` < 50 B |
| Embeddings per chunk | yes | yes + paraphrase | 60-word chunks | MIT/Apache models | 8 ms per chunk |

Why ssdeep/TLSH fail: ssdeep builds a 64-char digest with a 7-byte rolling window, compares only signatures with compatible block sizes and requires a common 7-char substring ([fuzzy.c](https://github.com/ssdeep-project/ssdeep/blob/master/fuzzy.c)); block size scales with input length, so a 700 B paste inside a prompt and an 8 KB document land on different block sizes (measured 96 vs 48 -> score 0). TLSH is a whole-file digest. Both compare files, they do not find substrings.

### Recommended algorithm `[REC]`

Word-level robust winnowing, inverted index `fingerprint -> {doc ids}`, document-frequency filter, hit-count threshold; embeddings optional.

1. Normalise: NFKC, casefold, strip Unicode `Cf` (zero-width, tags), tokens `[\w']+`; fold diacritics for matching only.
2. 5-word k-grams, 64-bit blake2b; winnow with **k = 5, w = 4**: guarantee t = w+k-1 = **8 consecutive words**, density 2/(w+1) = 0.40 ([paper](https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf)).
3. Drop fingerprints present in more than **5 documents** (or in a boilerplate/public corpus).
4. Leak if distinct hit fingerprints for one document >= **4**; report coverage and matched span.
5. Pastes shorter than 8 words are undetectable by construction; say so.

`[MEASURED]` (stdlib, Python 3.14.8): 1,000 synthetic documents x 800 words plus a 158-word "M&A memo" inside doc #123. Text = bigram Markov chain trained on 76,661 words of English technical prose (harsh for common n-grams). Query = the memo's 98-word paragraph with random word deletion/substitution at the given rate, inside ~400 words of unrelated text; 50 trials per cell; df cut 5.

| k | w | t | threshold | distinct fps | 0% edit | 10% | 20% | 30% | 40% | 30-word paste, 10% | benign FP /300 | footer-prompt FP /100 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 5 | 4 | 8 | hits>=4 | 292k | 50/50 | 50/50 | 47/50 | 34/50 | 12/50 | 36/50 | 0 | 0 |
| 5 | 3 | 7 | hits>=4 | 365k | 50/50 | 50/50 | 50/50 | 44/50 | 25/50 | 43/50 | 0 | 0 |
| 6 | 4 | 9 | hits>=3 | 306k | 50/50 | 50/50 | 50/50 | 31/50 | 12/50 | 44/50 | 1 | 1 |


Without the df filter (k=5, w=4, hits>=3): 10/200 benign prompts reach >=3 hits (max 7), prompts containing the shared footer reach 18 hits; the filter dropped 1,075 fingerprints and cut footer hits to <=2 while 20%-edit detection stayed 30/30. Larger k kills FPs but also recall (k=8, w=8: 0 FP, 11/30 at 20% edit). Measured density 322,599 fps / ~800k k-grams = 0.40, matching 2/(w+1).

Cost: build 0.64-0.94 s for the 1,000 documents (pure Python, one core); query 0.3 ms for a 400-word prompt; 292k distinct fingerprints = **2.3 MB at 8 B** raw. A Python `dict[int,set]` is far larger `[INFERENCE]`: use sorted `numpy.uint64` + `np.searchsorted`.

Other algorithms, same data (datasketch 2.0.0, ppdeep 20260221, py-tlsh 5.0.0):

| Test | Result |
|---|---|
| Whole memo (158 words, ~1.1 KB) vs itself with 10/20/30% word edits | MinHash(5-gram, 128 perm) J = 0.38 / 0.19 / 0.10; SimHash Hamming 14 / 20 / 23 (unrelated: 28); ppdeep 0 / 0 / 0; TLSH diff 58 / 122 / 152 |
| 98-word paragraph (0/10/20% edit) inside ~400-word prompt vs 1,260-word document | doc-level J = 0.094 / 0.047 / 0.031; SimHash 28 / 30 / 29 (= unrelated); ppdeep 0; TLSH 144 / 137 / 148 |
| TLSH on 30 / 49 / 50 / 80 / 200 / 500 B | `TNULL` / `TNULL` / hash / hash / hash / hash |
| Chunk MinHash LSH (100-word chunks, stride 50, 128 perms, thr 0.2; 15k chunks, 6.2 s build, 15.4 MB) | detection at 0/10/20/30%: 20/20, 20/20, 13/20, 7/20; benign FP **24/100** unverified; with estimated-Jaccard verification >= 0.2: FP 0/100, detection 20, 18, 5, 0 of 20 |

Winnowing found the paste with 6.7x less memory than chunked MinHash, higher recall at 20-30% edits and no verification step; SimHash/ssdeep/TLSH cannot find a paste. MinHash fits "is this uploaded file a near-duplicate of a registered file" only.

### Embedding tier for paraphrase

Chunk docs into ~60-word windows, stride 30, `float16` matrix (1,000 docs x 27 chunks x 384 dims = 21 MB). `[MEASURED]` `paraphrase-multilingual-MiniLM-L12-v2` (sentence-transformers 6.1.0, CPU): 4 English paraphrases of 4 memo sentences: max cosine **0.66, 0.71, 0.71, 0.84**; 2 Polish paraphrases of the English memo 0.79, 0.82; 5 unrelated sentences 0.14-0.33 but a topical near-miss ("a company announced a merger with a rival") **0.60**. Paraphrases and topical neighbours overlap at n=9 with one model: no clean threshold. Encode 8 ms per chunk, 274 ms for 64. `[REC]`: emits `semantic_match` (log + judge confirmation, floor INTERNAL), never blocks alone; winnowing is the blocking evidence.

### Code sketch `[REC]`

```python
import re, unicodedata, hashlib
from collections import defaultdict, Counter
K, W, MIN_HITS, MAX_DF = 5, 4, 4, 5
def tokens(t):
    t = unicodedata.normalize("NFKC", t).casefold()
    return re.findall(r"[\w']+", "".join(c for c in t if unicodedata.category(c) != "Cf"))
def h64(s): return int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "big")
def winnow(tok):
    hs = [h64(" ".join(tok[i:i+K])) for i in range(len(tok) - K + 1)]
    if len(hs) <= W: return set(hs)
    out, last = set(), None                      # robust winnowing (paper, Def. 3)
    for i in range(len(hs) - W + 1):
        win = hs[i:i+W]; m = min(win)
        if last and last[1] == m and i <= last[0] < i + W: continue
        last = (i + max(x for x, v in enumerate(win) if v == m), m); out.add(m)
    return out
class FpIndex:
    def __init__(self): self.inv, self.label = defaultdict(set), {}
    def add(self, doc, text, label, boilerplate=frozenset()):
        self.label[doc] = label
        for f in winnow(tokens(text)) - boilerplate: self.inv[f].add(doc)
    def seal(self):
        for f in [f for f, s in self.inv.items() if len(s) > MAX_DF]: del self.inv[f]
    def scan(self, prompt):
        q = winnow(tokens(prompt)); hits = Counter(d for f in q for d in self.inv.get(f, ()))
        return [{"doc": d, "label": self.label[d], "hits": c} for d, c in hits.most_common(3) if c >= MIN_HITS]
```
For the redaction span keep `fingerprint -> token offset` in the query pass and merge matched offsets within 12 tokens.

### Impressive vs realistic `[REC]`

Realistic in 3-4 h: winnowing index, df filter, "register document" endpoint, span highlight. Impressive: the judge edits ~10-20% of the pasted words and it still fires, then flips the matrix. Not realistic: tuned paraphrase detection, OCR. Purview's document fingerprinting is template-based (blank form -> SIT; [docs](https://learn.microsoft.com/en-us/purview/sit-document-fingerprinting)); ours is excerpt-based.

## 7. Destination-aware DLP

Precedent (vendor pages are marketing; the structure is the point): Microsoft Purview Copilot DLP (one action per rule; SIT and label conditions cannot share a rule) and Endpoint DLP warn/block for third-party genAI sites in a browser ([Copilot DLP](https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-learn-about), [AI overview](https://learn.microsoft.com/en-us/purview/ai-microsoft-purview)); Cloudflare AI Gateway Flag/Block per gateway ([docs](https://developers.cloudflare.com/ai-gateway/features/dlp/)) and Cloudflare One DLP profiles per AI app and user action ([changelog](https://community.cloudflare.com/t/data-loss-prevention-new-dlp-topic-based-detection-entries-for-ai-prompt-protection/836191)); Netskope LLM-based prompt/response inspection ([docs](https://docs.netskope.com/en/ai-ml-usage-and-governance-in-netskope-products)); Zscaler prompt classification, block or redact ([sheet](https://www.zscaler.com/resources/data-sheets/zscaler-data-protection-benefits.pdf)); Nightfall text-scan API with redaction ([blog](https://www.nightfall.ai/blog/chatgpt-dlp-filtering-how-to-use-chatgpt-without-exposing-customer-data)). Our delta: trust tiers that include MCP servers and agents, redaction of only offending spans, reversible pseudonyms.

### Identifying the destination `[REC]`

| Destination | Identity source (never what the request claims) | Registry |
|---|---|---|
| LLM | the gateway's own resolved upstream host + model tag; `-cloud` tag on localhost -> external | `providers[]: {host, model_glob, tier}` |
| MCP server | configured id; remote: origin + pinned tool-list hash; stdio: command+args hash; 2026-07-28 `server/discover` identity is self-declared: log, do not trust ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)) | `mcp_servers: {id: tier}` |
| Agent | id from gateway-issued token, not the A2A card | `agents: {id: clearance}` |
| External API | host after redirects, eTLD+1 | allowlist with `expires` |

### Matrix `[REC]` (live-editable)

Classes `PUBLIC < INTERNAL < CONFIDENTIAL < SECRET`.

| Class \ destination | local_model | approved_external_llm | unknown_external | mcp_approved | mcp_unknown |
|---|---|---|---|---|---|
| PUBLIC | allow | allow | allow | allow | allow |
| INTERNAL | allow | allow | redact | allow | **block** |
| CONFIDENTIAL | allow | **redact + pseudonymize** | **block** | redact | **block** |
| SECRET | allow + audit | **block** | block | block | block |

Credentials are a `SECRET` floor for every destination except the service they belong to.

### Decision algorithm `[REC]`

```
def decide(msg, dest, who, session):
    findings = detectors.run(msg)                          # markings, labels, dict, EDM, fp, NER, semantic
    cls = max([f.cls for f in findings] + [session.taint], default=PUBLIC)   # max over findings
    action = matrix[dest.tier][cls]                        # allow | redact | block | hold
    if cls > who.clearance_for(dest): action = stricter(action, "block")
    if action == "redact":
        spans = [f.span for f in findings if f.cls > dest.ceiling]           # offending spans only
        msg = pseudonymize(msg, spans, session.map) if dest.external else mask(msg, spans)
        if redacted_fraction(msg) > 0.4: action = "block"                    # heuristic [INFERENCE]
    audit(who, dest, summary_without_raw_text, cls, action, policy_version)
    return action, msg
# response path: restore pseudonyms from session.map; run the same detectors on the reply
# against the REQUESTER's clearance (section 8). SECRET and credentials are never pseudonymized.
```
Pseudonyms are per session and consistent (`Jan Kowalski` -> `<PERSON_1>` everywhere) so the model can reason; the map stays in memory, never logged.

### YAML policy `[REC]`

```yaml
version: 7
mode: enforce                      # enforce | monitor
detectors:
  markings: {CONFIDENTIAL: [confidential, poufne], SECRET: [strictly confidential, tajne], INTERNAL: [internal use only]}
  labels: {"6f1c-guid": CONFIDENTIAL}
  dictionaries:
    INTERNAL_PROJECT: {class: CONFIDENTIAL, terms: [Falcon, Sokół], match: stem5}
    CUSTOMER_NAME:    {class: CONFIDENTIAL, file: customers.txt, match: stem5}
    INTERNAL_HOST:    {class: INTERNAL, suffixes: [.corp.example.local, .internal], cidrs: [10.0.0.0/8]}
  patterns:
    CONFIDENTIAL_DOCUMENT_ID: {class: CONFIDENTIAL, regex: '\bACME-(DOC|FIN|LEG)-\d{4}-\d{4,6}\b'}
  fingerprints: {k: 5, w: 4, min_hits: 4, max_df: 5, floor_class: from_doc}
  edm: {min_supporting: 1, window_chars: 200}
  ner: {model: gliner-pii-edge, labels: [person, organization, customer name], min_score: 0.5, class: INTERNAL}
  semantic: {knn_k: 5, judge_band: [0.4, 0.6]}
destinations:
  providers:
    - {host: "localhost:11434", model: "!*cloud", tier: local_model}
    - {host: "localhost:11434", model: "*cloud",  tier: unknown_external}
    - {host: api.openai.com, tier: approved_external_llm}
    - {host: "*", tier: unknown_external}
  mcp_servers: {github-internal: mcp_approved, "*": mcp_unknown}
  agents: {billing-agent: CONFIDENTIAL, "*": INTERNAL}
matrix:
  PUBLIC:       {local_model: allow, approved_external_llm: allow,  unknown_external: allow,  mcp_approved: allow,  mcp_unknown: allow}
  INTERNAL:     {local_model: allow, approved_external_llm: allow,  unknown_external: redact, mcp_approved: allow,  mcp_unknown: block}
  CONFIDENTIAL: {local_model: allow, approved_external_llm: redact, unknown_external: block,  mcp_approved: redact, mcp_unknown: block}
  SECRET:       {local_model: audit, approved_external_llm: block,  unknown_external: block,  mcp_approved: block,  mcp_unknown: block}
redaction: {mode: pseudonymize, restore_on_response: true, escalate_if_redacted_over: 0.4}
```
Hot reload: matrix, dictionaries and registry are read from the policy snapshot per request; fingerprint index and exemplars reload on file change, so flipping `CONFIDENTIAL.approved_external_llm` to `block` takes effect on the next request.

## 8. Output-side DLP and label propagation

Responses (LLM, tool, MCP) run through the same detectors, but the question is "may *this requester* see it?".

| Check | Rule |
|---|---|
| Response vs clearance | finding class > requester clearance -> redact span or block; RAG chunks and tool results carry the source label |
| System-prompt echo, canaries | DLP-03/04 in [01](../../ai_layer_control/research/01-threats-controls.md) |
| Egress shapes in output | strip Markdown images and reference-style links to unknown hosts (EchoLeak) |
| Restore | pseudonyms mapped back only within the same session and only if clearance allows |
| Streaming | Cloudflare buffers the whole response ([docs](https://developers.cloudflare.com/ai-gateway/features/dlp/)); we use a ~2-sentence sliding buffer with pattern lookahead `[INFERENCE]`, buffer-all for CONFIDENTIAL+ sessions |

Session taint `[REC]`: `taint = max(class of every item that entered the context)` plus a provenance set; never decreases within a session. If `taint >= CONFIDENTIAL` and the next tool targets `unknown_external`, `mcp_unknown` or has `openWorldHint`, the call is `hold` for human approval. This is the EXF-04 rule in [01](../../ai_layer_control/research/01-threats-controls.md) and the "lethal trifecta" ([Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)).

Research `[EXP]`:
- **FIDES** (Microsoft, [arXiv 2505.23643](https://arxiv.org/abs/2505.23643), v2 2025-09-03; [microsoft/fides](https://github.com/microsoft/fides) MIT, last push 2025-05): planner with confidentiality and integrity labels on a lattice; deterministic per-tool policies **P-T** (consequential action only if triggered by trusted inputs) and **P-F** (egress only if all recipients may read the data); hides data from the planner behind variables and a quarantined LLM with constrained decoding. Paper claims: with policy checks it stops all AgentDojo prompt-injection attacks and completes ~16% more tasks than a basic planner with reasoning models.
- **CaMeL** (Google DeepMind/ETH, [arXiv 2503.18813](https://arxiv.org/abs/2503.18813); [code](https://github.com/google-research/camel-prompt-injection) Apache-2.0, last push 2025-06): control/data flow extracted from the trusted query, values carry provenance and allowed readers, policies checked at tool calls; 77% of AgentDojo tasks with provable security vs 84% undefended.
- Both need control of the agent planner; a gateway only sees messages.

Hackathon version `[REC]`: labels = the 4 classes; `source -> label` at ingress (MCP server tier, file class, RAG collection class); session label = join; one **P-F** check at each egress tool call using the section 7 matrix on the session label; **P-T**-lite: tool calls proposed right after content from an `mcp_unknown` source are `hold`. `[NOT RECOMMENDED FOR HACKATHON MVP: FIDES/CaMeL planners, per-value taint -> session taint + egress matrix check.]`

## 9. Demo-worthy design: confidential M&A memo

1. Admin registers `memo-project-falcon.docx` (marked CONFIDENTIAL, label GUID in `docProps/custom.xml`) via `POST /v1/protect/documents`; UI shows label read, 158 words -> fingerprints (k=5, w=4), class CONFIDENTIAL, boilerplate filtered.
2. User asks an external approved model to "rewrite this paragraph in a friendlier tone", pasting the memo paragraph with ~15% of words changed -> `fingerprint` finding (hits >= 4), class CONFIDENTIAL, `approved_external_llm` -> **redact + pseudonymize** the matched span; dashboard shows highlighted span, outgoing diff, per-stage latency.
3. Same prompt to local `qwen3.5:4b`: allowed. Same prompt to `gpt-oss:120b-cloud` on localhost Ollama: blocked as `unknown_external`.
4. Judge changes `matrix.CONFIDENTIAL.approved_external_llm` to `block`; next request blocked, reason code and policy version in the audit log.
5. Judge pastes the paragraph with 40% of words changed: honest miss by winnowing (12/50 in the sweep), embedding tier logs `semantic_match`.
6. Agent reads the memo through an internal MCP server, then calls `send_email` on `mcp_unknown`: session taint CONFIDENTIAL -> `hold`.

Self-test rows: marking only; label only; Polish-inflected term; EDM with/without supporting field; fingerprint at 0/10/20% edit (block) vs unrelated and footer prompts (pass); one case per matrix row; `-cloud` tag; unknown MCP server with INTERNAL argument; taint hold; pseudonym restore.

## Inconsistent

| Topic | Side A | Side B | Choice |
|---|---|---|---|
| Does Purview Copilot DLP inspect uploaded files? | Learn page lists prompt-text SIT blocking, label-based file/email blocking, web-search blocking ([Learn](https://learn.microsoft.com/en-us/purview/dlp-microsoft365-copilot-location-learn-about)) | Q&A answers say only typed prompt text, not uploads ([Q&A](https://learn.microsoft.com/en-us/answers/questions/5895139/copilot-sensitive-info-type-dlp-safeguarding-not-b)); secondary | assume typed text only; we scan uploads in the upload stage (10) |
| Sensitivity classification accuracy | 99.0% with marker-leaky data | 86.26% after leakage removal ([2608.16928](https://arxiv.org/abs/2608.16928)) | quote the clean figure |
| PII NER quality | knowledgator F1 81.0-83.3; eu-pii-safeguard Polish 96.63 | no independent replication; our run: English-only GLiNER mislabels Polish | label vendor-reported |

## Could not establish

- `gliner-x-*` latency and Polish quality on our labels (fp32 download exceeds the 1 GB cap; ONNX int8 path not tried); no published CPU latency found.
- Accuracy of embedding kNN / NLI for 4-class *enterprise* sensitivity (only a 2-class WikiLeaks benchmark and a geoscience study found); a usable paraphrase cosine threshold (9 hand-made sentences only).
- Charikar 2002 / Manku 2007 SimHash cut-offs: papers not opened; Hamming values above are measured only.
- LiteLLM Presidio `output_parse_pii` (mask then unmask) precedent: GitHub fetch failed (connection reset), not cited. Presidio anonymizer's reversible `encrypt`/`decrypt` operators not verified; we propose our own placeholder map.
- Purview Endpoint DLP details beyond one sentence on the AI overview page; Netskope and Zscaler internals (marketing pages only); `en_core_web_sm` licence not re-fetched.

## Recommendation for the MVP

`[REC]` build order (hours):
1. Destination registry + matrix + decision function + YAML hot reload (3 h): the one thing judges edit live.
2. Deterministic detectors: markings, dictionaries with stem5 matching (`pyahocorasick`), doc-id regex, internal hosts, label read (reuse 10), EDM with truncated HMAC (4 h).
3. Winnowing index k=5, w=4, hits>=4, df<=5, span highlight, register-document endpoint (3-4 h): measured 50/50 at 10% edit, 0 FP on 300 benign prompts.
4. Presidio patterns + `en_core_web_sm` (1 h, ~7 ms); one GLiNER model behind a flag (2 h).
5. Redact + pseudonymize + restore (2 h); response-side scan with clearance (2 h).
6. Session taint + egress hold (2 h).
7. Embedding kNN sensitivity classifier with live exemplars (3 h); judge only for the ambiguous band (reuse 03).
8. Self-test cases from section 9 (2 h).

Cut first: embedding paraphrase tier of the fingerprinter, GLiNER, SetFit/NLI, MinHash upload near-duplicate, `eu-pii-safeguard`, fuzzy Polish matching, FIDES/CaMeL planners.

Licence guardrails: ship MIT/Apache/BSD only (Presidio, spaCy, gliner, rapidfuzz, simplemma, pyahocorasick, Magika, datasketch if used). Never ship `pl_core_news_*` (GPL-3.0), piiranha / Isotonic / wikineural (non-commercial), ssdeep (GPL-2.0/LGPL), PyMuPDF (AGPL); NVIDIA gliner-PII has its own licence; CC-BY `pczarnik/herbert-base-ner` needs attribution.

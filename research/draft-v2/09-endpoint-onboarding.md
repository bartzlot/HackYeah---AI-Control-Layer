# 09 - Endpoint onboarding: how employee laptops reach the AI egress proxy, who they are, which tenant they use, what EU/Polish law requires

Verified 2026-10-03: docs read today, mitmproxy 12.2.3 source at tag v12.2.3, spikes on the demo Mac (macOS 27.0, Chrome 154, system curl 8.7.1). `[SPIKE]` = observed by me in /tmp (repo untouched), `[INFERENCE]` = reasoning. App protocols and the AI-host catalog are sibling files; "AI host list" = `intercept.hosts` of [07](07-architecture.md) (D1, D6, D20, D29).

## Established

### A. Routing: how AI traffic reaches the proxy

| Option | Mechanism | User identity | QUIC / H3 | Verdict |
|---|---|---|---|---|
| **PAC via MDM (recommended)** | `FindProxyForURL` returns `PROXY host:18080` for AI hosts, else `DIRECT`. macOS Global HTTP Proxy payload: `ProxyType: Auto`, `ProxyPACURL` (http/https only; macOS device channel, no supervision, manual install allowed, **max one per device**) [apple-proxy]; `networksetup -setautoproxyurl <service> <url>` (local man). Chrome/Edge `ProxySettings` {`ProxyMode: pac_script`, `ProxyPacUrl`, `ProxyPacMandatory`} [chrome-proxy], [edge-proxy]; Firefox `Proxy` {`Mode: autoConfig`, `AutoConfigURL`, `Locked`} [ff-proxy]; Safari follows the OS setting | via proxy auth (C) | none: browsers tunnel with CONNECT over TCP | Non-AI traffic never touches the proxy (D1). Covers apps honouring the OS proxy (Chromium, Electron, CFNetwork). A fixed proxy for everything is rejected: only `allow_hosts` would separate tunnel from decrypt |
| WPAD / DHCP option 252 | Chrome `auto_detect` probes DHCP/DNS [chromium-proxy] | none | none | **Avoid**: rogue DHCP reply or NBNS/LLMNR spoof of "wpad" redirects traffic [ms16-077], [cisa-wpad], [acm-wpad]. Use an explicit PAC URL |
| Env vars (CLI, SDK, agents) | `HTTPS_PROXY`, `NO_PROXY`; Claude Code: Basic creds in URL, no SOCKS, no NTLM/Kerberos [cc-net]; httpx reads `HTTP(S)_PROXY`, `SSL_CERT_FILE` [httpx-env] | Basic in URL | none | Needed for dev/agent tools (they ignore the OS proxy); push via shell profile or managed settings |
| Transparent redirect (gateway) | `iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080`; macOS pf `rdr pass on en0 inet proto tcp to any port {80, 443} -> 127.0.0.1 port 8080`; no NAT before the proxy [mitm-transparent] | IP only | **TCP only** [mitm-modes] | Office design, not the demo. Host choice by IP/Host/SNI (`allow_hosts` [next-layer]); ECH would blind it |
| WireGuard mode | `--mode wireguard[:keys.conf][@port]`, userspace, standard client, narrowable `AllowedIPs` [mitm-modes] | **one peer per mode instance**: code passes `[self.pubkey]`, one `client_key`, `Address = 10.0.0.1/32`, `DNS = 10.0.0.53` [mode-servers] -> one `--mode wireguard:wg-N.conf@port` per device; identity = `sockname` port | H3 yes; DNS via mitmproxy, `strip_ech` (default true) strips ECH [strip-ech] | Unmanaged / proxy-ignoring devices; does not scale per device |
| Local capture | `--mode local[:procs]`, `local:!curl`, `local:Claude,Chrome`; **runs on the endpoint itself** [mitm-modes]. macOS: copies `Mitmproxy Redirector.app` to `/Applications`, installs a Network System Extension (App Proxy Provider, TCP+UDP), user approves in System Settings; one redirector only [mac-readme], [mac-blog] | process name | yes | Stretch for proxy-ignoring apps. Open bugs [#7236](https://github.com/mitmproxy/mitmproxy/issues/7236), [#7419](https://github.com/mitmproxy/mitmproxy/issues/7419), [#8412](https://github.com/mitmproxy/mitmproxy/issues/8412). Not run (installs a system extension) |

PAC facts [chromium-proxy]: path/query are stripped from https `url` since Chrome 52 (host-only decisions); localhost implicitly bypasses; a list gives fallback (`PROXY a:18080; PROXY b:18080`); `ProxyPacMandatory` forbids direct fallback when the PAC is unreachable (all browsing breaks if the PAC host is down). [SPIKE] Chrome 154 headless `--proxy-pac-url`: `example.com` -> CONNECT on the proxy, `api.github.com` -> DIRECT.

QUIC, DoH, ECH:
- `QuicAllowed=false`: Chrome 43+ [chrome-quic], Edge 77+ [edge-quic]. Chrome honours local roots only for **removing** trust on QUIC, so a company CA is **not trusted over QUIC** [crs-faq]: intercepting Chrome QUIC cannot work. Force TCP: PAC proxy (CONNECT) plus firewall drop of UDP/443 to AI hosts. Chrome also refuses QUIC through non-QUIC proxies (code comment in [issue 40372699](https://issues.chromium.org/40372699), 2014; today `[INFERENCE]`).
- DoH: Chrome `DnsOverHttpsMode` (unset on managed devices = off) [chrome-doh]; Firefox `DNSOverHTTPS` {`Enabled`, `Locked`} [ff-doh]. ECH: Chrome `EncryptedClientHelloEnabled` [chrome-ech]; Firefox `DisableEncryptedClientHello` [ff-ech]. With an explicit PAC proxy the host is in the plaintext CONNECT, so DoH/ECH matter only for transparent, WireGuard, local modes.
- [SPIKE] HTTPS RR (type 65) via 1.1.1.1 for 20 AI hosts (OpenAI, Anthropic, Google, Microsoft, Perplexity, DeepSeek, xAI, Mistral): 12 have one, **none carries an `ech` param**; claude.ai advertises `h3,h2`. ECH blocks nothing today.
- iCloud Private Relay can hide traffic: DNS-block `mask.icloud.com`, `mask-h2.icloud.com` [apple-relay].

Bypass prevention (D29): observed A records are shared (api.anthropic.com = claude.ai = 160.79.104.10; chatgpt.com, api.openai.com, perplexity.ai in 104.18/172.64/162.159/172.66) so IP rules cannot isolate a service `[INFERENCE]`. Use FQDN/SNI-aware groups: client VLAN -> AI FQDNs deny, proxy IP -> any allow, UDP/443 -> AI FQDNs deny, DNS sinkhole for DoH resolvers and Private Relay. A laptop skipping the PAC then fails closed.

### B. Trust: company CA on endpoints and in apps

| Platform / app | Trust source | Deployment | Catch |
|---|---|---|---|
| macOS (Safari, CFNetwork, Chrome, Electron) | System keychain, SSL "Always Trust" | `sudo security add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain ca.pem` (local man; [mitm-certs]); MDM `com.apple.security.root` [apple-root] | Automatic full trust only for MDM, Configurator or enrollment-profile installs [apple-certs]; a **manually installed profile** on macOS 13+ leaves SSL at "no value specified" [apple-forum]. Demo = `add-trusted-cert`, production = MDM |
| Windows | Local Machine Trusted Root | `certutil -addstore -f Root ca.cer` [certutil]; GPO Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies [ms-gpo]; Intune trusted certificate profile (`.cer`, Computer-Root) [ms-intune] | Not run (no Windows host) |
| Chrome / Edge | reads macOS Default+System keychains (SSL Always Trust), Windows Root/Enterprise/GPO stores | nothing after OS install | TCP only [crs-faq] |
| Firefox | own NSS store | `Certificates.ImportEnterpriseRoots: true` (= `security.enterprise_roots.enabled`; Windows+macOS only) or `Certificates.Install` [ff-certs] | - |
| Node, Python | Mozilla bundle, certifi | `NODE_EXTRA_CA_CERTS=file` (read at start, ignored if code sets `ca`), `--use-system-ca` / `NODE_USE_SYSTEM_CA=1` (v23.8+) [node-cli]; `SSL_CERT_FILE` / `SSL_CERT_DIR` for httpx [httpx-env]; `REQUESTS_CA_BUNDLE` `[INFERENCE from 07 §11]` | - |
| Claude Code | bundled + OS store (`CLAUDE_CODE_CERT_STORE`, default `bundled,system`; native installer or Node >= 22.15) | OS store or `NODE_EXTRA_CA_CERTS` [cc-net] | no pinning |
| Electron apps (Claude Desktop), VS Code | Chromium verifier = OS store | OS install | `app.on('login')`: "default behavior is to cancel all authentications" unless handled [electron-app] -> Basic proxy auth can silently fail (VS Code shows a popup: Basic, Digest, NTLM, Negotiate [vscode-net]). Claude.app 2.19675.0 here is Electron (observed). Desktop ignoring `NODE_EXTRA_CA_CERTS` is user-reported [#70394](https://github.com/anthropics/claude-code/issues/70394). Untested |
| ChatGPT desktop / mobile | **pinned** | OpenAI: add your CA to the app pin list via MDM, or block `desktop.chatgpt.com`, `android.chat.openai.com`, `ios.chat.openai.com` (blocks all accounts) [openai-net] | Default for us: tunnel, no decrypt (`ignore_hosts` [mitm-certs]) |

**Name-constrained CA (D6)**: `nameConstraints = critical, permitted;DNS:<hosts>`.
- Chrome, Edge, Firefox, Safari rejected violating certs in Netflix's tests; Java, Node, Python had CN/SAN edge-case bypasses (2017); 2021 rerun notes false rejects when an IP sits in the CN [netflix], [bettertls]. A permitted `example.com` covers sub-labels (RFC 5280 §4.2.1.10).
- [SPIKE] mitmproxy 12.2.3 loads a constrained `mitmproxy-ca.pem` (key+cert) from `confdir`. System curl: permitted host OK, other host `permitted subtree violation`. macOS SecTrust (`security verify-cert -r ca.crt -p ssl -s host`): permitted OK, violating host `CSSMERR_TP_INVALID_CERTIFICATE`. Chrome, Node, Windows not tested.
- **[SPIKE] gotcha for spike S1:** default `upstream_cert=true` copies the upstream cert's SANs into the leaf. gemini.google.com's upstream cert lists `*.google.com`, `*.bdn.dev`, `*.google.ca` ...; against a CA permitting only `gemini.google.com`, curl failed with `permitted subtree violation`. With `--set upstream_cert=false` the leaf SAN is only `gemini.google.com` and the request returned 200. **A constrained CA requires `upstream_cert=false`.** (Upstream SANs of chatgpt.com, claude.ai, perplexity.ai, api.openai.com stay under their own domain.)

### C. Identity

| Option | How the proxy learns the user | Verified facts | Fit |
|---|---|---|---|
| Basic via `proxyauth` | `proxyauth` = `user:pass` / `any` / `@htpasswd` (bcrypt or SHA1) / `ldap[s]:url:port:dn_auth:password:dn_subtree` [proxyauth-src], [htpasswd-src]. Addon reads `flow.metadata["proxyauth"]` = `(user, password)` | **Basic only**. Unauthenticated CONNECT -> 407. `Proxy-Authorization` is removed before the `request` hook. `http_connect` hook already has the user, **also for tunnelled hosts**. No auth in transparent / WireGuard / local modes [SPIKE all] | Demo + CLI. Chrome prompts (Basic, Digest, NTLM, Negotiate; best score wins) [chromium-auth]; Firefox `Proxy.AutoLogin` skips the prompt if a password is saved [ff-proxy]. Token crosses a plain-HTTP LAN hop `[INFERENCE]`: per-device random token, rotate |
| Kerberos / NTLM front proxy | Chrome does integrated auth automatically when a **proxy** challenges [chromium-auth]; Squid authenticates and forwards with `cache_peer ... login=*:password` ("send the username to the upstream cache, but with a fixed password") [squid-cfg] -> our Basic validator takes `user` | chain not run `[INFERENCE]` | Production, AD shops |
| Port per user | per-device PAC returns `PROXY host:<port_user>`; `--mode regular@port` each; `client_conn.sockname[1]` | [SPIKE] two `regular@` ports in one process, sockname distinguishes | No prompts, works for Electron; identification, not authentication |
| IP -> user map | `client_conn.peername[0]`. NGFW analogue: Palo Alto User-ID maps IP to user via AD/Exchange log monitoring, syslog, GlobalProtect, captive portal, XML API, client probing, terminal-server agent [pan-userid] | wrong behind NAT/VDI/shared IP `[INFERENCE]` | Demo fallback (static leases); production: DHCP leases + AD 4624 logons |
| WireGuard peer | one mode instance per device (A) | every peer is 10.0.0.1 | unmanaged devices |

Resolver (D20): validated `proxyauth` user -> else `ip_map` -> else `anonymous` with the strictest profile.

### D. Tenant restrictions: headers the proxy injects (vendor docs only; unverified items dropped)

Proxy must decrypt the "inject on" hosts, **overwrite** client-sent headers (`flow.request.headers[name] = value`; duplicates give 400 at Anthropic and GitHub), never log bodies of sign-in hosts.

| Vendor | Header | Value | Inject on | Limits |
|---|---|---|---|---|
| Entra TRv2 [tr-v2] (2026-03-20) | `sec-Restrict-Tenant-Access-Policy` | `<TenantId>:<policyGuid>` (id from `/crosstenantaccesspolicy/default`) | login.live.com, login.microsoft.com, login.microsoftonline.com, login.windows.net | auth plane only; Entra P1/P2; MS accepts decrypting these hosts for header insertion; exclude device-registration hosts; stop sending v1 `restrict-msa` |
| Entra TRv1 [tr-v1] (2024-11-29) | `Restrict-Access-To-Tenants` + `Restrict-Access-Context`; `sec-Restrict-Tenant-Access-Policy: restrict-msa` | tenant CSV (no spaces); own directory id; literal | login.microsoftonline.com, login.microsoft.com, login.windows.net; MSA on login.live.com | not `*.login...`; exclude `device.login.microsoftonline.com`, `enterpriseregistration.windows.net` |
| Microsoft Copilot [ms-copilot] | none beyond TRv2 | - | - | "To manage whether users can sign in with personal accounts, see Tenant Restrictions v2"; `copilot.cloud.microsoft` accepts work or personal sign-in; MS "doesn't recommend and can't support" domain/IP blocking for Copilot Chat |
| Google Workspace [goog-tr] (2026-10-01) | `X-GoogApps-Allowed-Domains` | domain CSV; tokens `consumer_accounts`, `visitor_accounts`, `gserviceaccounts.com` | every `*.google.com` request | sign-in only, anonymous use not blocked. **Gemini app, AI Studio, NotebookLM not named** (likely applies, unverified) |
| ChatGPT Enterprise [openai-net] | `ChatGPT-Allowed-Workspace-Id` | workspace UUIDs, comma, no spaces | `https://chatgpt.com/*` | others incl. personal workspace filtered; 403 if none left, 400 if malformed; also block `https://chatgpt.com/backend-anon/`; Team/Edu not stated |
| Anthropic [anthropic-tr] (2026-08-03) | `anthropic-allowed-org-ids` | org UUIDs, comma; long lists `;n=K` + `anthropic-allowed-org-ids1..K-1`; max 500 | claude.ai, api.anthropic.com, claude.com, anthropic.com (+ `platform.claude.com` `[INFERENCE]` from [cc-net]) | Enterprise + Console orgs (Team not listed); Web, Desktop, API key, OAuth; block = 403 `tenant_restriction_violation` |
| GitHub EMU + Copilot [gh-proxy] | `sec-GitHub-allowed-enterprise` | enterprise id | github.com, api.github.com, `*.githubcopilot.com` | `X-GitHub-Enterprise-*` does not exist; SSH, `github.dev`, githubusercontent uncovered; Copilot plan by hostname: allow `*.business.` / `*.enterprise.githubcopilot.com`, block `*.individual.` [gh-copilot] |

Also documented: `X-GeminiCodeAssist-Allowed-Domains` (domain CSV, no `@`, on `https://cloudcode-pa.googleapis.com`, no wildcards) [gca]; `OpenAI-Allowed-Organization-Ids` (`org-...` CSV, on `https://api.openai.com/*`; API-key behaviour not stated) [openai-org].

**No documented network mechanism** (fallback: domain block + enforced SSO + classify consumer vs enterprise login in the proxy `[INFERENCE]`): Perplexity Enterprise (SSO blocks personal sign-ups) [pplx], Mistral [mistral], xAI Grok [xai], DeepSeek (nothing found). Dropbox header only in Cato's doc, Atlassian none. SSO alone does not stop personal use: one OpenAI account can hold personal and work workspaces [openai-ws].

Consequence: Google and Microsoft headers force decryption of **sign-in hosts**, wider than the AI host list. Mark them `inject_only` (decrypt, set header, `flow.request.stream = True`, log nothing) and widen the CA constraint for exactly those names. macOS Platform SSO breaks if the proxy CA is outside Apple roots [tr-v2].

### E. EU / Polish legal checklist and design defaults

GDPR text: gdpr-info.eu. Kodeks pracy via lexlege.pl (secondary, **confirm on ISAP**). WP249 = [WP29 Opinion 2/2017](https://ec.europa.eu/newsroom/document.cfm?doc_id=45631). Not legal advice.

| Requirement | Source | Design default |
|---|---|---|
| Minimisation, purpose, storage limit | [GDPR 5](https://gdpr-info.eu/art-5-gdpr/) | Log metadata (user, host, time, size, verdict); prompt text only on a policy hit; fixed retention; log who reads logs |
| Legal basis | [6(1)(f)](https://gdpr-info.eu/art-6-gdpr/); WP249 §6.2 "Employees are almost never in a position to freely give, refuse or revoke consent" | Legitimate interest + written balancing test, never consent |
| Transparency, DPIA | [13](https://gdpr-info.eu/art-13-gdpr/), [35](https://gdpr-info.eu/art-35-gdpr/); UODO DPIA list (M.P. 2019 poz. 666) names monitoring of email, software, internet flows (read via [secondary](https://www.odoserwis.pl/a/1333/komunikat-puodo-z-dnia-17-czerwca-2019-r-w-sprawie-wykazu-rodzajow-operacji-przetwarzania-danych-osobowych-wymagajacych-oceny-skutkow-przetwarzania-dla-ich-ochrony)) | Ship a DPIA template and the employee notice (below) |
| Employment context | [88](https://gdpr-info.eu/art-88-gdpr/) -> KP 22^2, 22^3 | KP rules are a mandatory layer |
| Purpose | KP 22^3 §1-2: control of work email only if necessary for work organisation and proper use of tools, no breach of correspondence secrecy; §4: other forms of monitoring "odpowiednio" [kp-22-3] | Purpose = work-time organisation + proper tool use; DLP wording needs a lawyer; prompts are not named in the statute |
| Announcement | KP 22^2 §6 purposes/scope/method in agreement, work rules or notice; §7 inform **>= 2 weeks before** start; §8 new hires before work; §9 marking >= 1 day before (written for video, applied "odpowiednio") [kp-22-2] | Enforce mode gated until notice date + 14 days; visible notice page (`aicl.test`) `[INFERENCE]` |
| Unions / council | KP 104^2 work rules agreed with the union (>= 50 employees need rules) [kp-104]; works-council duty unverified | Plan union agreement if rules carry the monitoring |
| Proportionality, interception | WP249 §5.3: "monitoring every online activity ... is a disproportionate response"; prefer blocking; no interception of private webmail, banking, health; log on incident; review yearly. [CISA TA17-075A](https://www.cisa.gov/news-events/alerts/2017/03/16/https-interception-weakens-tls-security): validate upstream certs. [NCSC-NL](https://www.enisa.europa.eu/news/member-states/ncsc-published-factsheet-on-tls-interception): protect the proxy | Decrypt **only** AI hosts, rest tunnelled; incident-only content; no `ssl_insecure`; CA key 0600; annual review |
| Content reveal | [Barbulescu v Romania GC 2017](https://hudoc.echr.coe.int/eng?i=001-177082) para 121: notice, flow vs content, reasons, less intrusive means, consequences, safeguards | Metadata by default; content via logged reveal with reason + second approver, stated in the notice |
| Retention | only video has a number: 3 months (KP 22^2 §3) [kp-22-2]; WP249 §6.4 minimum necessary | `[INFERENCE]` metadata 90 days, prompt excerpts 30 days, longer only under legal hold |
| AI Act | [5(1)(f)](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-5) emotion inference at work banned; [Annex III 4(b)](https://ai-act-service-desk.ec.europa.eu/en/ai-act/annex-3) employee monitoring/evaluation high-risk | No sentiment inference, no per-employee scoring |

Notice contents: controller + DPO; purpose; legal basis + interest; AI hosts decrypted (named) and categories never decrypted; company CA on the device; logged fields; who sees what and the logged reveal; retention; processors/transfers; automated blocking + review route; rights incl. complaint to UODO; private-use rule; effective date >= 14 days. UODO: do not monitor the period before the employee was told [uodo]. Lawyer points: is AI traffic "inne formy monitoringu" with a DLP purpose; secrecy of correspondence vs prompts on a work device; third-party and special-category data in prompts (art. 9, 14); BYOD; art. 36 consultation if residual risk stays high.

## Inconsistent

- Apple: MDM-installed roots get automatic full trust [apple-certs]; macOS 13+ forum reports profile roots lose SSL trust, one MDM user too [apple-forum]. Test per MDM.
- GitHub allows `ID1 ... ID20` in `sec-GitHub-allowed-enterprise`, its troubleshooting table says one enterprise (400) [gh-proxy]. Cato's M365 mapping disagrees with Microsoft's pages (Microsoft used). Anthropic's host list omits `platform.claude.com`, [cc-net] lists it.
- Claude Desktop: Anthropic treats it as header-injectable, users report it ignores `NODE_EXTRA_CA_CERTS`.
- KP 22^2 §8 now "papierowej lub elektronicznej", UODO 2018 slides "na piśmie"; the brief's "21 Feb 2018" is unconfirmed, UODO cites the act of 10 May 2018 (Dz.U. 2018 poz. 1000).

## Could not establish

- ChatGPT desktop, Claude Desktop, Copilot apps on macOS: PAC/OS-store behaviour (not safe to launch against our proxy); OpenAI pin-list procedure (docsend page).
- Safari proxy-auth prompt; Chrome, Node, Python, Windows against a constrained CA (only curl and SecTrust tested).
- Install of the generated `.mobileconfig` (state-changing). The demo Mac is **MDM-enrolled** (`profiles status -type enrollment`: DEP yes, User Approved, Mosyle; `MosyleSecurity.app`, `Self-Service.app` present): a second Global HTTP Proxy payload cannot coexist, MDM may restrict manual profiles.
- Gemini app / AI Studio / NotebookLM under `X-GoogApps-Allowed-Domains`; Team/Edu header coverage; ISAP text of KP 22^2/22^3; works-council threshold; Squid -> mitmproxy parent chain; local capture on this Mac.

## Further

### Recommendation for our build

**Demo (1-2 macOS endpoints, ~5 min each, admin password).** Artifacts served by the console `:18000`:

| Artifact | Content |
|---|---|
| `/proxy.pac` | generated from `intercept.hosts` (same list feeds CA constraint and `allow_hosts`): `host === h \|\| dnsDomainIs(host, "." + h)` -> `PROXY <LAN_IP>:18080`, else `DIRECT`; includes `aicl.test` (pattern tested in Chrome 154) |
| `/aicl-ca.cer` | CA cert only, name-constrained to `intercept.hosts` + `aicl.test` (+ `inject_only` hosts); key stays 0600 |
| `/aicl.mobileconfig` | `plistlib`, `plutil -lint` OK [SPIKE]: `com.apple.security.root`, `com.apple.proxy.http.global` (`Auto` + `ProxyPACURL`), optional `com.google.Chrome` {`ProxySettings`, `QuicAllowed: false`} [chrome-mac]. Optional on the MDM-enrolled demo Mac |
| `/onboard` | static page: 3 links, the commands below, per-user token, link to `http://aicl.test/` |
| whoami addon | 5 lines: `pretty_host == "aicl.test"` -> `proxied as <user> from <ip>`; [SPIKE] works over HTTP and HTTPS with `connection_strategy=lazy` + `upstream_cert=false` |

Proxy: `mitmdump --listen-host 0.0.0.0 --mode regular@18080 --set confdir=var/ca --set upstream_cert=false --set connection_strategy=lazy --set allow_hosts=<regex of intercept.hosts> --set proxyauth=@var/htpasswd -s identity.py`. `block_global` (default on) kills public source IPs [block-src]; allow incoming connections for Python in the macOS firewall; Wi-Fi client isolation breaks it [mitm-modes]. Port 18081 was already taken by another process during my spikes: re-check ports.

Endpoint steps:
1. Open `http://<LAN_IP>:18000/onboard` (not proxied).
2. Trust: `sudo security add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain aicl-ca.cer`.
3. Route: `sudo networksetup -setautoproxyurl Wi-Fi http://<LAN_IP>:18000/proxy.pac` (or the profile). Revert: System Settings > Network > Details > Proxies; delete the CA in Keychain Access.
4. Identity: browser prompts once -> user `alice` + token. CLI/agents: `export HTTPS_PROXY=http://alice:<token>@<LAN_IP>:18080` + `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`. Apps that cannot prompt: `ip_map` entry (static lease).
5. Verify: `https://aicl.test/` says `proxied as alice`, no cert warning; `chatgpt.com` padlock shows the AICL CA; `example.net` shows its real issuer; audit shows `alice` for decrypted and tunnelled CONNECTs.
6. Stretch on the proxy Mac only: `--mode local:Claude` (rehearse the system-extension approval first).

**Production.** (1) Legal gate: DPIA, balancing test, notice, union agreement, 14-day lead. (2) Pilot team in monitor mode. (3) MDM: macOS profile (root + PAC + Chrome/Firefox policies), Windows GPO/Intune (root, browser `ProxySettings`, Firefox `ImportEnterpriseRoots`), env for dev tools via managed settings. (4) PAC lists two proxies, `ProxyPacMandatory` off. (5) FQDN firewall deny for AI hosts from client networks, UDP/443 deny, DNS sinkhole for DoH and Private Relay. (6) AD: Squid/Kerberos front with `login=*:password`, or IP map from DHCP + AD events. (7) Tenant headers per vendor after testing, sign-in hosts `inject_only`. (8) Pinned apps: tunnel and restrict by host, or pin-list our CA by MDM.

### Risks

- A constrained CA protects only clients that enforce it; apps with their own stores ignore CA and constraint. Mitigate: key 0600, short CA lifetime, CA per environment.
- Header injection puts login traffic (credentials) inside the proxy: accidental body logging is a GDPR breach. Enforce `inject_only` in code, test it.
- Basic auth over plain HTTP exposes the token; Electron apps cannot prompt; IP identity fails behind NAT.
- Demo Mac is MDM-managed: profile install may be blocked or conflict; keep `add-trusted-cert` as plan B, rehearse on the actual laptop.
- ECH or HTTPS-record changes can remove SNI visibility in transparent modes; PAC mode is immune.
- AI Act high-risk if monitoring turns into performance evaluation; prompts carry third-party and special-category data.

### Questions for the team

1. Demo identity: Basic prompt with per-user token (real, desktop apps fail) or IP map (silent, weaker)? Proposal: both, token first.
2. Tenant restriction live (needs a real ChatGPT Enterprise / Claude org / Entra tenant, none in the repo) or simulated?
3. Widen the CA constraint to Google/Microsoft sign-in hosts with `inject_only`, or keep tenant restriction as documentation?
4. Pinned desktop apps: tunnel and allow/deny by host, or MDM pin-list?
5. Constrained CA by default (needs `upstream_cert=false`; amends S1) or unconstrained fallback?
6. Retention defaults (90 d / 30 d) and purpose wording: lawyer sign-off.

[apple-proxy]: https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.proxy.http.global.yaml
[apple-root]: https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.security.root.yaml
[apple-certs]: https://support.apple.com/guide/deployment/certificates-payload-settings-dep91d2eb26/web
[apple-forum]: https://developer.apple.com/forums/thread/724327
[apple-relay]: https://developer.apple.com/icloud/prepare-your-network-for-icloud-private-relay/
[chrome-proxy]: https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/policy/resources/templates/policy_definitions/Miscellaneous/ProxySettings.yaml
[edge-proxy]: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/proxysettings
[chrome-quic]: https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/policy/resources/templates/policy_definitions/Miscellaneous/QuicAllowed.yaml
[edge-quic]: https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/quicallowed
[chrome-doh]: https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/policy/resources/templates/policy_definitions/Miscellaneous/DnsOverHttpsMode.yaml
[chrome-ech]: https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/policy/resources/templates/policy_definitions/Miscellaneous/EncryptedClientHelloEnabled.yaml
[chrome-mac]: https://support.google.com/chrome/a/answer/9020077
[crs-faq]: https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/data/ssl/chrome_root_store/faq.md
[chromium-proxy]: https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md
[chromium-auth]: https://www.chromium.org/developers/design-documents/http-authentication/
[ff-proxy]: https://github.com/mozilla/enterprise-admin-reference/blob/main/src/content/docs/reference/policies/Proxy.mdx
[ff-certs]: https://github.com/mozilla/enterprise-admin-reference/blob/main/src/content/docs/reference/policies/Certificates.mdx
[ff-doh]: https://github.com/mozilla/enterprise-admin-reference/blob/main/src/content/docs/reference/policies/DNSOverHTTPS.mdx
[ff-ech]: https://github.com/mozilla/enterprise-admin-reference/blob/main/src/content/docs/reference/policies/DisableEncryptedClientHello.mdx
[mitm-modes]: https://docs.mitmproxy.org/stable/concepts/modes/
[mitm-transparent]: https://docs.mitmproxy.org/stable/howto/transparent/
[mitm-certs]: https://docs.mitmproxy.org/stable/concepts/certificates/
[next-layer]: https://github.com/mitmproxy/mitmproxy/blob/v12.2.3/mitmproxy/addons/next_layer.py
[mode-servers]: https://github.com/mitmproxy/mitmproxy/blob/v12.2.3/mitmproxy/proxy/mode_servers.py
[strip-ech]: https://github.com/mitmproxy/mitmproxy/blob/v12.2.3/mitmproxy/addons/strip_dns_https_records.py
[proxyauth-src]: https://github.com/mitmproxy/mitmproxy/blob/v12.2.3/mitmproxy/addons/proxyauth.py
[htpasswd-src]: https://github.com/mitmproxy/mitmproxy/blob/v12.2.3/mitmproxy/utils/htpasswd.py
[block-src]: https://github.com/mitmproxy/mitmproxy/blob/v12.2.3/mitmproxy/addons/block.py
[mac-readme]: https://github.com/mitmproxy/mitmproxy_rs/blob/main/mitmproxy-macos/redirector/README.md
[mac-blog]: https://www.mitmproxy.org/posts/local-capture/macos/
[ms16-077]: https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-077
[cisa-wpad]: https://www.cisa.gov/news-events/alerts/2016/05/23/wpad-name-collision-vulnerability
[acm-wpad]: https://dl.acm.org/doi/10.1145/3565361
[cc-net]: https://code.claude.com/docs/en/network-config.md
[httpx-env]: https://raw.githubusercontent.com/encode/httpx/master/docs/environment_variables.md
[node-cli]: https://github.com/nodejs/node/blob/main/doc/api/cli.md
[vscode-net]: https://code.visualstudio.com/docs/setup/network
[electron-app]: https://github.com/electron/electron/blob/main/docs/api/app.md
[certutil]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
[ms-gpo]: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/distribute-certificates-group-policy
[ms-intune]: https://learn.microsoft.com/en-us/intune/intune-service/protect/certificates-trusted-root
[netflix]: https://netflixtechblog.com/bettertls-c9915cd255c0
[bettertls]: https://bettertls.com/
[squid-cfg]: https://github.com/squid-cache/squid/blob/master/src/cf.data.pre
[pan-userid]: https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/user-id/map-ip-addresses-to-users
[tr-v2]: https://learn.microsoft.com/en-us/entra/external-id/tenant-restrictions-v2
[tr-v1]: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tenant-restrictions
[ms-copilot]: https://learn.microsoft.com/en-us/copilot/manage
[goog-tr]: https://knowledge.workspace.google.com/admin/security/block-access-to-consumer-accounts
[gca]: https://docs.cloud.google.com/gemini/docs/codeassist/network-access
[openai-net]: https://help.openai.com/en/articles/20001323-corporate-network-controls-in-chatgpt-enterprise
[openai-org]: https://developers.openai.com/api/docs/guides/organization-blocking.md
[openai-ws]: https://help.openai.com/en/articles/9047883
[anthropic-tr]: https://support.claude.com/en/articles/13198485-enforce-network-level-access-control-with-tenant-restrictions
[gh-proxy]: https://docs.github.com/en/enterprise-cloud@latest/admin/configuring-settings/hardening-security-for-your-enterprise/restricting-access-to-githubcom-using-a-corporate-proxy
[gh-copilot]: https://docs.github.com/en/enterprise-cloud@latest/copilot/how-tos/administer-copilot/manage-for-organization/manage-access/manage-network-access
[pplx]: https://www.perplexity.ai/help-center/en/articles/12067853-introduction-to-organization-admins
[mistral]: https://docs.mistral.ai/admin/set-up-organization/verify-domain
[xai]: https://docs.x.ai/grok/organization.md
[kp-22-2]: https://lexlege.pl/kp/art-22-2
[kp-22-3]: https://lexlege.pl/kp/art-22-3
[kp-104]: https://lexlege.pl/kp/rozdzial-iv-regulamin-pracy/260
[uodo]: https://uodo.gov.pl/pl/138/545

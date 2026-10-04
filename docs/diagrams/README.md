# AICL diagrams

Mermaid sources (`*.mmd`) and rendered SVG in a light and a dark variant (`<name>.light.svg`, `<name>.dark.svg`).
Facts come from `research/14-transparent-interception.md`, `policy/policy.yaml`, `w1-gateway` and `w2-core`; change the code or research first, then the diagram.

| Source | Shows |
|---|---|
| `01-topology.mmd` | deployment: corporate network, DHCP option 6, AICL DNS, gateway :443, egress firewall, providers, Ollama judge |
| `02-sequence.mmd` | one request: DNS, TLS with the AICL CA leaf, decide() on the request, upstream with the client's own credential, decide() on the response, native answer or block |
| `03-decide.mmd` | the decide() pipeline and the ALLOW < LOG < WARN < REDACT < BLOCK lattice |
| `04-bypass.mmd` | bypass attempts, what stops them, and what NET-01 shows |

## Regenerate

```
make diagrams                      # or: bash docs/diagrams/render.sh
```

Needs Node (`npx` downloads `@mermaid-js/mermaid-cli`, pinned in `render.sh`) and a Chromium-based browser.
The script uses `PUPPETEER_EXECUTABLE_PATH` when set, else the first Chrome / Edge / Chromium it finds, else puppeteer's own download.
Themes: `mermaid.light.json` (neutral, white background) and `mermaid.dark.json` (dark, `#0d1117` background).
`htmlLabels` is off so the SVG carries plain text and renders in every viewer, not only browsers.
Mermaid escapes `<` and `->` inside labels in this mode: write words, not those characters.

Commit the SVG next to the `.mmd`. `tests/test_diagrams.py` fails when a source has no rendered pair.

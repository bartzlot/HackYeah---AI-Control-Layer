#!/usr/bin/env bash
# Render every docs/diagrams/*.mmd to <name>.light.svg and <name>.dark.svg with mermaid-cli (mmdc).
# Needs Node (npx). Chrome: puppeteer's own download, or PUPPETEER_EXECUTABLE_PATH / Edge / Chrome found below.
set -euo pipefail
cd "$(dirname "$0")"
MMDC_VERSION="${MMDC_VERSION:-11.12.0}"

if [ -z "${PUPPETEER_EXECUTABLE_PATH:-}" ]; then
  for c in "/c/Program Files/Google/Chrome/Application/chrome.exe" \
           "/c/Program Files (x86)/Google/Chrome/Application/chrome.exe" \
           "/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" \
           "/c/Program Files/Microsoft/Edge/Application/msedge.exe" \
           /usr/bin/google-chrome /usr/bin/chromium /usr/bin/chromium-browser \
           "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    if [ -x "$c" ]; then PUPPETEER_EXECUTABLE_PATH="$c"; break; fi
  done
fi
if [ -n "${PUPPETEER_EXECUTABLE_PATH:-}" ]; then
  export PUPPETEER_EXECUTABLE_PATH PUPPETEER_SKIP_DOWNLOAD=1
  case "$PUPPETEER_EXECUTABLE_PATH" in /c/*) PUPPETEER_EXECUTABLE_PATH="C:${PUPPETEER_EXECUTABLE_PATH#/c}";; esac
  export PUPPETEER_EXECUTABLE_PATH
fi

# --no-sandbox: needed in containers / CI, harmless for local rendering of our own sources
echo '{"args":["--no-sandbox","--disable-setuid-sandbox"]}' > .puppeteer.json
trap 'rm -f .puppeteer.json' EXIT

n=0
for src in *.mmd; do
  name="${src%.mmd}"
  for mode in light dark; do
    bg=white; [ "$mode" = dark ] && bg='#0d1117'
    npx -y "@mermaid-js/mermaid-cli@${MMDC_VERSION}" -q -i "$src" -o "$name.$mode.svg" \
      -c "mermaid.$mode.json" -p .puppeteer.json -b "$bg"
    n=$((n+1))
  done
done
echo "diagrams: rendered $n SVG files"

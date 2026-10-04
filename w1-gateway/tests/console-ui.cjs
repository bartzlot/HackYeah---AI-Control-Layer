// T-131: offline browser regression. Node 22+ and Chrome/Edge; no npm packages or backend.
// Run: node w1-gateway/tests/console-ui.cjs (AICL_CHROME can select a browser executable).
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const http = require("node:http");
const { spawn } = require("node:child_process");
const assets = path.resolve(__dirname, "../aicl_gateway/console");
const events = fs.readFileSync(path.join(assets, "fixtures.jsonl"), "utf8").trim().split(/\r?\n/).map(JSON.parse);
const event = events.find(e => e.decision === 4) || events[0];
const finding = { control_id: "INJ-04", rule_id: "injection.fixture", action: "BLOCK", category: "injection", judge: { model: "fixture", verdict: "BLOCK", eval_ms: 127 }, spans: [] };
const policy = { version: "fixture-policy", profile: "balanced", rules: 2, files: ["policy/policy.yaml"],
  yaml: "version: 1\nclients:\n  - match: {cidr: 10.77.0.0/24}\n    principal: demo-dev\n",
  clients: ["10.77.0.0/24", "127.0.0.0/8"].map(cidr => ({ match: { cidr }, principal: "demo-dev", profile: "balanced" })),
  interception: { mode: "proxy", hosts: ["api.anthropic.com"], block_style: { anthropic_messages: { hard: "400", soft: "200", budget: "402" } } } };
const fixtures = {
  "/catalog": { controls: { "INJ-04": { id: "INJ-04", name: "Injection", description: "Checks prompts", layer: "ai" } }, rules: {} },
  "/summary": { requests: 12, events_total: 12, blocked: 2, redacted: 1, clients: 2, cost_usd: 0.02, tokens: 1000, budget_used_pct: 2, budget_usd: 1, posture_pct: 100, controls_enforced: 2, controls_total: 2, overhead_ms: { p50: 22, p95: 33 }, timeline: [{ t: "2026-10-04T10:00:00Z", allow: 9, redact: 1, block: 2 }], categories: { injection: 2 }, protocols: { managed: 12 }, top_rules: [], agent_budgets: [] },
  "/judge": { status: "warm", model: "fixture", p50_ms: 127, cache_hits: 3, cache_misses: 1 },
  "/events": { events },
  "/policy": policy,
  "/status": { mode: "proxy", policy_mode: "proxy", listeners: { http: { on: true, port: 18080 } }, warnings: [], notes: [] },
  "/budgets": { agents: { "demo-dev": { tokens: 10000, usd: 1, period: "day" } }, usage: [] },
  "/whoami": { can_edit: true },
  "/clients": { clients: [{ principal: "demo-dev", client_ip: "127.0.0.1", tools: ["Codex"], protocols: ["openai_responses"], models: ["fixture-model"], requests: 12, blocked: 2, redacted: 1, tokens: 1000, usd: 0.02 }] },
  "/network": { intercepted_by_host: { "api.anthropic.com": 12 }, bypass_alerts: [], passthrough: { total: 1, paths: {} } },
  "/interception": { providers: [{ name: "Anthropic", hosts: ["api.anthropic.com"], protocol: "anthropic_messages", upstream: "https://api.anthropic.com", inspect: ["/v1/messages"], raw_paths: [] }] },
  "/controls": { controls: [{ id: "INJ-04", mode: "enforce", hits: 2 }] },
  "/demo/presets": { presets: [{ title: "Fixture prompt" }] },
  "/demo/batch": { summary: { passed: 1, prompts: 1, requests: 1, decide_ms: { p50: 24, p95: 30 }, throughput_rps: 4, wall_s: 0.25, by_layer: { deterministic: 0, ai: 1 }, judge_ms: { count: 1, p50: 127 } }, rows: [{ id: "fixture", title: "Fixture prompt", outcome: "blocked", decision: "BLOCK", ok: true, control: "INJ-04", rule: "injection.fixture", layer: "ai", request_id: event.request_id, decide_ms: 24, judge_ms: 127, judge: finding.judge }] },
  "/playground": { models: { local: ["fixture"], external: [] } },
};
const explanation = { identity: { principal: "demo-dev" }, model: { model: "fixture", destination: "local" },
  stages: [{ id: "semantic", label: "Injection", ran: ["INJ-04"], controls: ["INJ-04"], findings: [finding], latency_ms: 127, action: "BLOCK" }],
  final: { action: "BLOCK", lattice: ["ALLOW", "BLOCK"] }, records: 1, latency_ms: { decide_total: 127 }, server_timing: "decide;dur=127" };
const requests = [];
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1"), name = url.pathname;
  requests.push(name);
  if (name.startsWith("/console/api/")) {
    const key = name.slice("/console/api".length);
    const value = key.startsWith("/explain/") ? explanation : fixtures[key];
    res.writeHead(value ? 200 : 404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify(value || { error: "Missing fixture: " + key }));
  }
  if (name === "/v1/chat/completions") {
    res.writeHead(200, { "Content-Type": "application/json", "X-AICL-Decision": "BLOCK", "X-AICL-Request-Id": event.request_id, "Server-Timing": "decide;dur=127" });
    return res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content: "Blocked fixture prompt" } }] }));
  }
  const file = name === "/console" ? "index.html" : name.startsWith("/console/static/") ? name.slice(16) : "";
  if (!file || path.basename(file) !== file || !fs.existsSync(path.join(assets, file))) { res.writeHead(404); return res.end(); }
  const types = { ".html": "text/html", ".css": "text/css", ".js": "application/javascript", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".png": "image/png" };
  res.writeHead(200, { "Content-Type": types[path.extname(file)] || "application/octet-stream" });
  res.end(fs.readFileSync(path.join(assets, file)));
});
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(fn, label) { for (let i = 0; i < 100; i++) { if (await fn()) return; await delay(100); } throw Error("Timed out: " + label); }
function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url), pending = new Map(), errors = []; let id = 0;
    ws.onerror = reject;
    ws.onmessage = ({ data }) => { const msg = JSON.parse(data); if (msg.method === "Runtime.exceptionThrown") errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text); if (msg.method === "Runtime.consoleAPICalled" && ["warning", "error"].includes(msg.params.type)) errors.push(JSON.stringify(msg.params.args)); if (msg.id) { const p = pending.get(msg.id); pending.delete(msg.id); if (p) msg.error ? p.reject(Error(JSON.stringify(msg.error))) : p.resolve(msg.result); } };
    ws.onopen = () => resolve({ errors, close: () => ws.close(), send: (method, params = {}) => new Promise((resolve, reject) => { const key = ++id; const timer = setTimeout(() => { pending.delete(key); reject(Error("CDP timeout: " + method)); }, 10000); pending.set(key, { resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } }); ws.send(JSON.stringify({ id: key, method, params })); }) });
  });
}
async function main() {
  const executable = [process.env.AICL_CHROME, "C:/Program Files/Google/Chrome/Application/chrome.exe", "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe", "/usr/bin/chromium", "/usr/bin/google-chrome"].find(x => x && fs.existsSync(x));
  assert(executable, "Install Chrome/Edge or set AICL_CHROME");
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "aicl-console-ui-"));
  let browser, cdp;
  try {
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    browser = spawn(executable, ["--headless=new", "--disable-gpu", "--no-first-run", "--no-sandbox", "--disable-background-networking", "--remote-debugging-port=0", "--user-data-dir=" + profile, "about:blank"], { windowsHide: true, stdio: "ignore" });
    browser.on("error", e => { throw e; });
    const portFile = path.join(profile, "DevToolsActivePort");
    await until(() => fs.existsSync(portFile), "browser startup");
    const port = fs.readFileSync(portFile, "utf8").split(/\r?\n/)[0];
    const targets = await (await fetch("http://127.0.0.1:" + port + "/json/list")).json();
    cdp = await connect(targets.find(t => t.type === "page").webSocketDebuggerUrl);
    await cdp.send("Runtime.enable");
    await cdp.send("Network.enable");
    await cdp.send("Network.setBlockedURLs", { urls: ["https://*", "http://*.com/*"] });
    const evaluate = async expression => { const r = await cdp.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }); if (r.exceptionDetails) throw Error(r.exceptionDetails.text + ": " + r.result.description); return r.result.value; };
    const click = selector => evaluate("document.querySelector(" + JSON.stringify(selector) + ").click()");
    const noTiming = async selector => { const text = await evaluate("document.querySelector(" + JSON.stringify(selector) + ").innerText"); assert(!/\blatency\b|\bthroughput\b|server-timing|stage timing|\bp(?:50|95)\b|\b\d+(?:\.\d+)?\s*ms\b/i.test(text), "Timing displayed in " + selector + ": " + text); };
    const layout = async label => {
      const result = await evaluate(`(() => {
        const visible = e => e.getClientRects().length > 0;
        const rounded = [...document.querySelectorAll('.card,.tile,button,input,select,textarea,.badge,.chip,.tag')].filter(visible).filter(e => parseFloat(getComputedStyle(e).borderTopLeftRadius) > 0).map(e => e.className || e.tagName);
        const colors = [...document.querySelectorAll('body,.side,.top,.card,.tile,button,.badge,.chip,.tag')].filter(visible).flatMap(e => {const s=getComputedStyle(e); return [s.color,s.backgroundColor,s.borderTopColor];});
        const colorful = colors.filter(c => {const n=c.match(/[\\d.]+/g)?.map(Number); return n && (n.length<4 || n[3]>0) && Math.max(...n.slice(0,3))-Math.min(...n.slice(0,3))>2;});
        return {width:innerWidth,scroll:document.documentElement.scrollWidth,rounded,colorful:[...new Set(colorful)]};
      })()`);
      assert(result.scroll <= result.width + 1, label + " body overflows: " + JSON.stringify(result));
      assert.deepEqual(result.rounded, [], label + " rounded corners");
      assert.deepEqual(result.colorful, [], label + " non-monochrome colors");
      await noTiming(".page.active");
    };
    const pages = ["overview", "clients", "playground", "security", "network", "controls", "policy"];
    for (const width of [1440, 390]) {
      await cdp.send("Emulation.setDeviceMetricsOverride", { width, height: 1000, deviceScaleFactor: 1, mobile: false });
      await cdp.send("Page.navigate", { url: "http://127.0.0.1:" + server.address().port + "/console?nolive=1" });
      await until(() => evaluate("!!document.querySelector('#tiles .tile') && !!document.querySelector('#events tbody tr[data-id]')"), "initial render");
      assert.equal(await evaluate("document.querySelectorAll('[data-page=performance],#page-performance').length"), 0, "Performance page removed");
      for (const p of pages) {
        await click('#nav [data-page="' + p + '"]');
        await delay(200);
        assert.equal(await evaluate("document.querySelector('.page.active').id"), "page-" + p);
        await layout(width + " " + p);
        if (process.env.AICL_UI_SHOTS && ["overview", "policy"].includes(p)) {
          fs.mkdirSync(process.env.AICL_UI_SHOTS, { recursive: true });
          const screenshot = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
          fs.writeFileSync(path.join(process.env.AICL_UI_SHOTS, p + "-" + width + ".png"), Buffer.from(screenshot.data, "base64"));
        }
        if (p === "policy") {
          const contained = await evaluate(`Array.from(document.querySelectorAll('#pol-cards table')).every(t=> {const box=t.closest('.tablewrap') || t; const card=t.closest('.card'); return box.getBoundingClientRect().right <= card.getBoundingClientRect().right + 1;})`);
          assert(contained, "Policy tables overlap cards");
          assert(await evaluate("document.querySelector('#pol-cards').innerText.includes('10.77.0.0/24')"), "Identity fixture rendered");
        }
      }
      await click('#nav [data-page="security"]'); await delay(150);
      await click('#events tbody tr[data-id="' + event.event_id + '"]');
      await until(() => evaluate("!!document.querySelector('#tl .tl-step')"), "event explanation");
      await layout(width + " activity details");
      await click('#nav [data-page="playground"]');
      await click("#batch-run");
      await until(() => evaluate("!!document.querySelector('#batch-table tbody tr')"), "batch results");
      await layout(width + " batch");
      await click("#pg-run");
      await until(() => evaluate("document.querySelector('#pg-out').innerText.includes('HTTP 200')"), "playground result");
      await layout(width + " playground result");
      await click("#theme"); await delay(200);
      await layout(width + " alternate theme");
      console.log("PASS " + width + "px: 7 pages, identity table, activity detail, batch, playground, theme");
    }
    assert.deepEqual(cdp.errors, [], "Browser errors or warnings");
    assert(!requests.includes("/console/api/performance"), "Performance endpoint requested");
    console.log("PASS no browser errors; no performance requests; all API calls use offline fixtures");
  } finally {
    if (cdp) { await Promise.race([cdp.send("Browser.close").catch(() => {}), delay(1000)]); cdp.close(); }
    if (browser && browser.exitCode === null) await Promise.race([new Promise(resolve => browser.once("exit", resolve)), delay(1500)]);
    if (browser && browser.exitCode === null) browser.kill();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    // The only recursive removal is our unique temporary browser profile.
    if (path.dirname(profile) === path.resolve(os.tmpdir()) && path.basename(profile).startsWith("aicl-console-ui-")) {
      try { fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); }
      catch (e) { console.warn("Temporary browser profile remains at " + profile + " (" + e.code + ")"); }
    }
  }
}
main().catch(e => { console.error(e.stack); process.exitCode = 1; });

// UI end-to-end for the console policy + budget editor (T-107): real Chrome, real clicks and typing.
const puppeteer = require("puppeteer-core");
const BASE = process.argv[2] || "http://127.0.0.1:18096";
const OUT = process.argv[3] || ".";
(async () => {
  const browser = await puppeteer.launch({ executablePath: process.env.AICL_CHROME || "C:/Program Files/Google/Chrome/Application/chrome.exe", headless: "new",
    args: ["--window-size=1440,1000"] });
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 1000 });
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error" && !/status of (422|401|403)/.test(m.text())) errors.push(m.text()); });
  const step = (n, ok, info) => console.log((ok ? "PASS " : "FAIL ") + n + (info ? " :: " + info : ""));

  await page.goto(BASE + "/console#policy", { waitUntil: "networkidle2" }).catch(() => {});
  await page.waitForSelector("#pol-yaml span.k", { timeout: 20000 });
  step("policy page renders highlighted yaml", true);
  await page.waitForSelector("#bud-edit tbody tr[data-id='demo-dev']", { timeout: 20000 });
  step("budget editor lists principals", true);

  // 1. invalid policy edit: rejected, live policy unchanged
  const v0 = await page.$eval("#chip-policy", (e) => e.textContent);
  await page.click("#pol-edit");
  await page.$eval("#pol-text", (t) => { t.value = t.value.replace("  mode: enforce              #", "  mode: maybe                #"); });
  await page.click("#pol-save");
  await page.waitForFunction(() => /Rejected|Applied|Not saved/.test(document.querySelector("#pol-msg").textContent), { timeout: 20000 });
  const m1 = await page.$eval("#pol-msg", (e) => e.textContent);
  step("invalid edit rejected with the loader's reason", /Rejected \(HTTP 422\)[\s\S]*defaults\.mode/.test(m1), m1.slice(0, 140));
  await page.screenshot({ path: OUT + "/editor-rejected.png" });

  // 2. valid edit: profile strict, applied at once
  await page.$eval("#pol-text", (t) => { t.value = t.value.replace("  mode: maybe                #", "  mode: enforce              #").replace("  profile: balanced          #", "  profile: strict            #"); });
  await page.click("#pol-save");
  await page.waitForFunction(() => /Applied/.test(document.querySelector("#pol-msg").textContent), { timeout: 20000 });
  await new Promise((r) => setTimeout(r, 800));
  const v1 = await page.$eval("#chip-policy", (e) => e.textContent);
  const banner = await page.$eval("#pol-banner", (e) => e.textContent);
  step("valid edit applied, new policy version live", v1 !== v0 && /profile strict/.test(banner), v0 + " -> " + v1);
  await page.screenshot({ path: OUT + "/editor-applied.png" });

  // 3. budget edit via the inputs
  const tok = await page.$("#bud-edit tbody tr[data-id='demo-dev'] input[data-k='usd']");
  await tok.evaluate((i) => { i.value = ""; });
  await tok.type("0.42");
  await page.click("#bud-save");
  await page.waitForFunction(() => /Saved|Rejected|Not saved/.test(document.querySelector("#bud-msg").textContent), { timeout: 20000 });
  const m3 = await page.$eval("#bud-msg", (e) => e.textContent);
  const api = await page.evaluate(async () => (await (await fetch("/console/api/budgets")).json()).agents["demo-dev"]);
  step("budget saved through the UI", /Saved/.test(m3) && api.usd === 0.42, m3 + " :: " + JSON.stringify(api));

  // 3b. control toggle (T-114): DLP-01 off from the Controls page, KILL-01 has no "off"
  await page.click("#nav button[data-page='controls']");
  await page.waitForSelector("#ctl select.modesel[data-id='DLP-01']", { timeout: 20000 });
  await page.select("#ctl select.modesel[data-id='DLP-01']", "off");
  await page.waitForFunction(() => /live|Rejected|Not saved/.test(document.querySelector("#ctl-msg").textContent), { timeout: 20000 });
  const m4 = await page.$eval("#ctl-msg", (e) => e.textContent);
  const dlp = await page.evaluate(async () => (await (await fetch("/console/api/controls")).json()).controls.find((c) => c.id === "DLP-01").mode);
  const killOpts = await page.$$eval("#ctl select.modesel[data-id='KILL-01'] option", (os) => os.map((o) => o.value));
  step("control switched off from the UI and live", /live/.test(m4) && dlp === "off" && killOpts.join() === "enforce", m4 + " :: KILL-01 " + killOpts.join("/"));
  await page.screenshot({ path: OUT + "/controls-toggled.png" });

  // 3c. intercepted AI domains (T-115): add a host from the Network page, wildcard rejected
  await page.click("#nav button[data-page='network']");
  await page.waitForSelector("#icpt tbody tr", { timeout: 20000 });
  await page.type("#icpt-host", "api.claude-proxy.example");
  await page.click("#icpt-add");
  await page.waitForFunction(() => /intercepted now|Rejected|Not saved/.test(document.querySelector("#icpt-msg").textContent), { timeout: 20000 });
  const m5 = await page.$eval("#icpt-msg", (e) => e.textContent);
  await page.$eval("#icpt-host", (i) => { i.value = ""; });
  await page.type("#icpt-host", "*.anthropic.com");
  await page.click("#icpt-add");
  await page.waitForFunction(() => /Rejected/.test(document.querySelector("#icpt-msg").textContent), { timeout: 20000 });
  const m6 = await page.$eval("#icpt-msg", (e) => e.textContent);
  step("intercepted host added from the UI, wildcard rejected", /api\.claude-proxy\.example/.test(m5) && /wildcard/.test(m6), m5.slice(0, 90) + " | " + m6.slice(0, 60));
  await page.screenshot({ path: OUT + "/network-domains.png" });

  // 4. every page renders without JS errors
  for (const p of ["overview", "clients", "security", "network", "controls", "performance", "playground", "audit", "policy"]) {
    await page.click(`#nav button[data-page='${p}']`);
    await new Promise((r) => setTimeout(r, 400));
    const visible = await page.$eval(`#page-${p}`, (e) => e.classList.contains("active"));
    if (!visible) step("page " + p, false);
  }
  step("all 9 pages navigate", true);
  // 5. playground sends a prompt through the gateway
  await page.click("#nav button[data-page='playground']");
  await page.select("#pg-dest", "unknown");
  await page.click("#pg-run");
  await page.waitForFunction(() => /HTTP \d+/.test(document.querySelector("#pg-out").textContent), { timeout: 15000 });
  const pg = await page.$eval("#pg-out", (e) => e.textContent);
  step("playground shows the decision", /decision (BLOCK|ALLOW|REDACT)/.test(pg), pg.split("\n")[0]);
  step("no JS errors", errors.length === 0, errors.join(" | ").slice(0, 200));
  await browser.close();
})().catch((e) => { console.log("FAIL exception :: " + e.message); process.exit(1); });

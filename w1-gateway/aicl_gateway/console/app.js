"use strict";
(function () {
  const $ = (s, r) => (r || document).querySelector(s);
  const API = "/console/api";
  const DN = ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"];
  const dn = (v) => (typeof v === "number" ? DN[v] || "ALLOW" : String(v || "ALLOW").toUpperCase());
  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const usd = (v) => "$" + Number(v || 0).toFixed(Number(v || 0) >= 1 ? 2 : 4);
  const num = (v) => Number(v || 0).toLocaleString("en-US");
  const PAGES = {
    overview: ["Management overview", "Security posture, blocked threats and spend across every AI client"],
    clients: ["Clients & spend", "Who uses which AI tool and model, at what cost, and how often AICL stepped in"],
    security: ["Live events", "Every decision with its explain trace: controls, rules, spans, latency"],
    network: ["Network & bypass", "Interception path, intercepted lookups and bypass attempts"],
    controls: ["Controls", "The control catalog from policy.yaml: mode, default action and hits"],
    policy: ["Policy", "The single config source that is live right now"],
    performance: ["Performance", "Decision latency per control, p50 / p95 / max"],
    playground: ["Playground", "Send an ad-hoc prompt through the gateway and see the decision"],
    audit: ["Audit export", "Exportable records for security teams"],
  };
  let events = [];
  const charts = {};
  let page = "overview";
  let selected = null;
  let pendingRule = null;     // T-119: rule / control to mark on the Policy page

  // theme
  try { const t = localStorage.getItem("aicl-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
  $("#theme").onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const nx = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = nx;
    try { localStorage.setItem("aicl-theme", nx); } catch (e) {}
    Object.values(charts).forEach((c) => c.destroy && c.destroy());
    Object.keys(charts).forEach((k) => delete charts[k]);
    refresh(true);
  };
  // navigation
  function go(p) {
    page = p;
    if (p !== "policy") pendingRule = null;
    document.querySelectorAll("#nav button").forEach((x) => x.classList.toggle("active", x.dataset.page === p));
    document.querySelectorAll(".page").forEach((s) => s.classList.toggle("active", s.id === "page-" + p));
    $("#title").textContent = PAGES[p][0];
    $("#subtitle").textContent = PAGES[p][1];
    try { history.replaceState(null, "", "#" + p); } catch (e) {}
    refresh(true);
  }
  document.querySelectorAll("#nav button").forEach((b) => (b.onclick = () => go(b.dataset.page)));

  async function getJSON(u) { const r = await fetch(u); if (!r.ok) throw new Error(u + " " + r.status); return r.json(); }
  const css = () => getComputedStyle(document.documentElement);
  const col = (n, d) => css().getPropertyValue(n).trim() || d;

  function tile(label, value, cls, sub, barPct, highIsGood) {
    const bc = highIsGood ? (barPct >= 80 ? "var(--ok)" : "var(--warn)") : (barPct >= 80 ? "var(--red)" : "var(--accent)");
    return '<div class="tile ' + (cls || "") + '"><div class="l">' + esc(label) + '</div><div class="v">' + esc(value) + "</div>" +
      (sub ? '<div class="s">' + sub + "</div>" : "") + (barPct != null ? '<div class="bar"><i style="width:' + Math.min(100, barPct) + "%;background:" + bc + '"></i></div>' : "") + "</div>";
  }
  function fallbackBars(el, labels, values) {
    const max = Math.max(1, ...values);
    el.innerHTML = labels.map((l, i) => '<div class="fb-row"><span>' + esc(l) + '</span><i style="width:' + (100 * values[i] / max) + '%;min-width:2px"></i><b>' + values[i] + "</b></div>").join("");
    el.parentElement.classList.add("nochart");
  }
  function drawChart(key, canvasId, fbId, cfg, labels, values) {
    if (window.Chart) {
      Chart.defaults.color = col("--muted", "#667085");
      Chart.defaults.borderColor = col("--line", "#e3e6ec");
      if (charts[key]) { charts[key].data = cfg.data; charts[key].update("none"); return; }
      charts[key] = new Chart($(canvasId), cfg);
    } else {
      fallbackBars($(fbId), labels, values);
    }
  }

  // ---- overview
  async function loadSummary() {
    const s = await getJSON(API + "/summary");
    const oh = s.overhead_ms || {};
    $("#tiles").innerHTML =
      tile("AI requests", num(s.requests), "", num(s.events_total) + " decisions") +
      tile("Blocked", num(s.blocked), "bad", "threats stopped before execution") +
      tile("Redacted", num(s.redacted), "warn", "data removed in flight") +
      tile("Clients protected", num(s.clients), "violet", plural(Object.keys(s.protocols || {}).length, "API contract")) +
      tile("API spend", usd(s.cost_usd), s.budget_used_pct >= 80 ? "bad" : "", num(s.tokens) + " tokens, " + s.budget_used_pct + "% of " + usd(s.budget_usd), s.budget_used_pct) +
      tile("Security posture", s.posture_pct + "%", s.posture_pct >= 80 ? "ok" : "warn", s.controls_enforced + "/" + s.controls_total + " controls enforced", s.posture_pct, true) +
      tile("AICL overhead", (oh.p50 || 0) + " ms", "ok", "p50, p95 " + (oh.p95 || 0) + " ms") +
      tile("Bypass attempts", num(s.bypass_alerts), s.bypass_alerts ? "bad" : "ok", s.bypass_alerts ? "see Network" : "none detected");
    setCount("#nav-blocks", s.blocked);
    setCount("#nav-bypass", s.bypass_alerts);
    renderBudgets(s.agent_budgets || []);
    const tl = s.timeline || [];
    const tlabels = tl.map((x) => x.t.slice(11));
    drawChart("time", "#ch-time", "#fb-time", {
      type: "bar",
      data: { labels: tlabels, datasets: [
        { label: "allowed", data: tl.map((x) => x.allow), backgroundColor: col("--ok", "#16a34a"), borderRadius: 4 },
        { label: "redacted", data: tl.map((x) => x.redact), backgroundColor: col("--warn", "#d97706"), borderRadius: 4 },
        { label: "blocked", data: tl.map((x) => x.block), backgroundColor: col("--red", "#dc2626"), borderRadius: 4 } ] },
      options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom" } }, scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } },
    }, tlabels, tl.map((x) => x.allow + x.redact + x.block));
    const cl = Object.keys(s.categories || {}), cv = cl.map((k) => s.categories[k]);
    drawChart("cat", "#ch-cat", "#fb-cat", {
      type: "doughnut",
      data: { labels: cl, datasets: [{ data: cv, borderWidth: 0, backgroundColor: ["#4f46e5", "#d97706", "#dc2626", "#16a34a", "#7c3aed", "#0ea5e9", "#db2777", "#65a30d"] }] },
      options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { position: "right" } } },
    }, cl, cv);
    const pl = Object.keys(s.protocols || {}), pv = pl.map((k) => s.protocols[k]);
    drawChart("proto", "#ch-proto", "#fb-proto", {
      type: "bar",
      data: { labels: pl.map(protoName), datasets: [{ data: pv, backgroundColor: col("--accent", "#4f46e5"), borderRadius: 6 }] },
      options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } } },
    }, pl.map(protoName), pv);
  }
  function plural(n, w) { return n + " " + w + (n === 1 ? "" : "s"); }
  function setCount(sel, n) { const el = $(sel); el.textContent = n; el.classList.toggle("show", n > 0); }
  function protoName(p) { return { anthropic_messages: "Anthropic Messages", openai_responses: "OpenAI Responses", openai_chat: "OpenAI Chat", managed: "Managed gateway" }[p] || p; }
  function burn(used, lim, fmt) {
    if (lim == null) return esc(fmt(used)) + ' <span class="muted">(no cap)</span>';
    const p = lim > 0 ? Math.min(100, 100 * used / lim) : (used > 0 ? 100 : 0);
    return esc(fmt(used)) + " / " + esc(fmt(lim)) + ' <span class="muted">' + p.toFixed(0) + "%</span>" +
      '<div class="bar"><i style="width:' + p + "%;background:" + (p >= 80 ? "var(--red)" : "var(--accent)") + '"></i></div>';
  }
  function renderBudgets(rows) {
    if (!rows.length) return;
    $("#budgets tbody").innerHTML = rows.map((b) => "<tr><td><b>" + esc(b.agent_id) + "</b></td><td>" + burn(b.tokens + b.reserved_tokens, b.limit_tokens, num) +
      "</td><td>" + burn(b.usd + b.reserved_usd, b.limit_usd, usd) + '</td><td class="num">' + esc(b.requests) + '</td><td class="num">' + esc(b.denied) +
      '</td><td class="num">' + esc(Math.round(b.resets_in_s / 60)) + " min</td></tr>").join("");
  }

  // ---- clients
  async function loadClients() {
    const c = (await getJSON(API + "/clients")).clients;
    $("#clients tbody").innerHTML = c.length ? c.map((x) => "<tr><td><b>" + esc(x.principal) + "</b></td><td class='mono'>" + esc(x.client_ip) + "</td><td>" +
      (x.tools.length ? x.tools.map(esc).join(", ") : '<span class="muted">-</span>') + "</td><td>" + (x.protocols.map((p) => '<span class="tag p-' + esc(p) + '">' + esc(protoName(p)) + "</span>").join("") || '<span class="tag">managed</span>') +
      "</td><td class='mono'>" + esc(x.models.slice(0, 3).join(", ")) + (x.models.length > 3 ? " +" + (x.models.length - 3) : "") + '</td><td class="num">' + num(x.requests) +
      '</td><td class="num" style="color:var(--red)">' + num(x.blocked) + '</td><td class="num" style="color:var(--warn)">' + num(x.redacted) + '</td><td class="num">' + num(x.tokens) +
      '</td><td class="num">' + usd(x.usd) + "</td><td class='muted'>" + esc((x.last || "").slice(11, 19)) + "</td></tr>").join("")
      : '<tr><td class="empty" colspan="11">No client traffic yet.</td></tr>';
  }

  // ---- live events
  function ctrls(r) { return [...new Set((r.findings || []).map((f) => f.control_id))].join(", "); }
  function client(r) {
    const tool = r.user_agent ? toolOf(r.user_agent) : "";
    return "<b>" + esc(r.agent_id) + "</b>" + (tool || r.client_ip ? '<span class="sub2">' + esc([tool, r.client_ip].filter(Boolean).join(" @ ")) + "</span>" : "");
  }
  function toolOf(ua) {
    const u = String(ua).toLowerCase();
    return u.includes("claude-cli") || u.includes("claude-code") ? "Claude Code" : u.includes("codex") ? "Codex" : u.startsWith("bun/") ? "Claude Code probe" :
      u.includes("openai") ? "OpenAI SDK" : u.includes("anthropic") ? "Anthropic SDK" : String(ua).split("/")[0].slice(0, 18);
  }
  const SHORT = { anthropic_messages: "anthropic", openai_responses: "responses", openai_chat: "chat" };
  function row(r, isNew) {
    const tr = document.createElement("tr");
    if (isNew) tr.className = "new";
    if (r.event_id === selected) tr.classList.add("sel");
    tr.dataset.id = r.event_id;
    const lat = (r.latency_us || {}).total;
    tr.innerHTML = "<td class='muted'>" + esc((r.ts || "").slice(11, 19)) + '</td><td><span class="badge b-' + dn(r.decision) + '">' + dn(r.decision) + "</span></td><td>" +
      esc(r.event_type) + (r.protocol ? '<span class="sub2"><span class="tag p-' + esc(r.protocol) + '">' + esc(SHORT[r.protocol] || r.protocol) + "</span></span>" : "") + "</td><td>" + client(r) + "</td><td class='mono'>" +
      esc(r.tool || r.model || r.upstream_host || "") + "</td><td class='mono wrap'>" + esc(ctrls(r)) + '</td><td class="num">' + (lat != null ? (lat / 1000).toFixed(1) : "") + "</td>";
    tr.onclick = () => select(r);
    return tr;
  }
  function matches(r) {
    const d = $("#f-decision").value, p = $("#f-proto").value, t = $("#f-text").value.toLowerCase();
    if (d && dn(r.decision) !== d) return false;
    if (p === "ai" && (r.stage === "dns" || r.event_type === "PASSTHROUGH")) return false;
    if (p === "dns" && r.stage !== "dns" && r.event_type !== "PASSTHROUGH") return false;
    if (p === "managed" && (r.protocol || r.stage === "dns")) return false;
    if (p && p !== "dns" && p !== "managed" && p !== "ai" && r.protocol !== p) return false;
    if (!t) return true;
    const hay = [r.agent_id, r.tool, r.model, r.event_type, r.client_ip, r.user_agent, r.upstream_host, ctrls(r),
      (r.findings || []).map((f) => f.rule_id + " " + ((f.spans || []).map((s) => s.type).join(" "))).join(" ")].join(" ").toLowerCase();
    return hay.includes(t);
  }
  function render() {
    const tb = $("#events tbody");
    tb.innerHTML = "";
    const shown = events.filter(matches);
    shown.slice(0, 400).forEach((r) => tb.appendChild(row(r)));
    if (!shown.length) tb.innerHTML = '<tr><td class="empty" colspan="7">No events match.</td></tr>';
    $("#count").textContent = shown.length + " of " + events.length + " events";
  }
  function select(r) {
    selected = r.event_id;
    document.querySelectorAll("#events tr").forEach((t) => t.classList.toggle("sel", t.dataset.id === selected));
    const fs = (r.findings || []).map((f) => "<li><code>" + esc(f.control_id) + " / " + esc(f.rule_id) + "</code> " + esc(f.category) + ' <span class="badge b-' + dn(f.action) + '">' + dn(f.action) + "</span>" +
      (f.score != null ? " <span class='muted'>score " + f.score + " vs " + f.threshold + "</span>" : "") +
      ((f.spans || []).length ? "<br><span class='muted'>spans " + f.spans.map((s) => esc(s.type) + "[" + s.start + "-" + s.end + "]" + (s.sha256_8 ? " #" + esc(s.sha256_8) : "")).join(", ") + "</span>" : "") +
      (f.reason_code ? "<br><span class='muted'>" + esc(f.reason_code) + "</span>" : "") + "</li>").join("");
    const lat = r.latency_us || {};
    const u = r.usage || {};
    $("#explain").innerHTML = "<h2>Explain</h2>" +
      '<span class="badge b-' + dn(r.decision) + '">' + dn(r.decision) + "</span> <b>" + esc(r.event_type) + "</b>" +
      '<div class="kv"><b>Client</b><span>' + esc(r.agent_id) + (r.client_ip ? " @ " + esc(r.client_ip) : "") + "</span>" +
      (r.user_agent ? "<b>Tool</b><span>" + esc(r.user_agent) + "</span>" : "") +
      (r.protocol ? "<b>API</b><span>" + esc(protoName(r.protocol)) + " -> " + esc(r.upstream_host || "") + "</span>" : "") +
      "<b>Stage</b><span>" + esc(r.stage) + " (" + esc(r.channel) + ")</span><b>Model</b><span>" + esc(r.model || "-") + " (" + esc(r.destination) + ")</span>" +
      (r.tool ? "<b>Tool call</b><span>" + esc(r.tool) + "</span>" : "") +
      (r.would_decision != null && dn(r.would_decision) !== dn(r.decision) ? "<b>Would be</b><span>" + dn(r.would_decision) + " (shadow mode)</span>" : "") +
      (u.usd != null ? "<b>Usage</b><span>" + num((u.input_tokens || 0) + (u.output_tokens || 0)) + " tokens, " + usd(u.usd) + "</span>" : "") +
      "<b>Latency</b><span>" + esc(lat.total != null ? (lat.total / 1000).toFixed(2) + " ms" : "-") + "</span><b>Policy</b><span class='mono'>" + esc((r.policy_version || "").slice(0, 16)) + "</span></div>" +
      '<h2>decide() timeline <span class="hint">whole request</span></h2><div id="tl"><p class="muted">Loading...</p></div>' +
      "<h2>Findings</h2><ul>" + (fs || "<li class='muted'>none</li>") + "</ul><h2>Trace</h2><div class='trace'>" + (r.explain || []).map(esc).join("\n") + "</div>";
    loadTimeline(r);
  }
  // ---- explain drawer: per-request decide() timeline (T-119); spans arrive as hashes / tokens only
  function spanText(s) {
    return esc(s.type) + " [" + esc(s.part) + ":" + esc(s.start) + "-" + esc(s.end) + "]" + (s.sha256_8 ? " #" + esc(s.sha256_8) : "") + (s.token ? " -> <code>" + esc(s.token) + "</code>" : "");
  }
  function tlFinding(f) {
    const j = f.judge;
    return '<div class="tl-f' + (f.shadow ? " shadow" : "") + '"><span class="badge b-' + esc(f.action) + '">' + esc(f.action) + "</span>" + (f.shadow ? ' <span class="badge b-WARN">shadow, not enforced</span>' : "") + ' <a href="#policy" class="rulelink" data-rule="' + esc(f.rule_id) + '" data-control="' + esc(f.control_id) + '" title="Show in the policy">' +
      esc(f.control_id) + " / " + esc(f.rule_id) + "</a>" + (f.record_stage ? ' <span class="muted">on ' + esc(f.record_stage) + "</span>" : "") +
      (f.score != null ? ' <span class="muted">score ' + esc(f.score) + " vs " + esc(f.threshold) + "</span>" : "") +
      (j ? '<div class="muted">judge ' + esc(j.model || "-") + ": " + esc(j.verdict) + (j.cached ? ", cached" : "") + (j.eval_ms != null ? ", " + esc(j.eval_ms) + " ms" : "") + (j.degraded ? ', <span style="color:var(--warn)">degraded</span>' : "") + "</div>" : "") +
      (f.reason_code ? '<div class="muted">' + esc(f.reason_code) + "</div>" : "") +
      ((f.spans || []).length ? '<div class="muted">spans ' + f.spans.map(spanText).join(", ") + "</div>" : "") + "</div>";
  }
  function renderTimeline(t) {
    const id = t.identity || {}, m = t.model || {}, fin = t.final || {};
    const steps = (t.stages || []).map((s) => {
      const ran = (s.ran || []).length || (s.findings || []).length || s.note;
      let body = "";
      if (s.id === "identity") body += "<div>" + esc(id.principal || "-") + (id.client_ip ? " @ " + esc(id.client_ip) : "") + (id.credential_hash ? ", key #" + esc(id.credential_hash) : "") + "</div>";
      if (s.id === "model_budget") body += "<div>" + esc(m.model || "-") + " (" + esc(m.destination || "-") + ")" + (m.protocol ? ", " + esc(protoName(m.protocol)) + " -> " + esc(m.upstream_host || "") : "") + "</div>";
      if (s.note) body += "<div>" + esc(s.note) + "</div>";
      body += ran ? (s.ran.length ? "<div>ran " + s.ran.map(esc).join(", ") + "</div>" : "") : "<div>not run for this request (" + s.controls.map(esc).join(", ") + ")</div>";
      body += (s.findings || []).map(tlFinding).join("");
      return '<li class="tl-step a-' + esc(s.action) + (ran ? "" : " skip") + '"><span class="tl-dot"></span><div class="tl-head"><b>' + esc(s.label) + '</b> <span class="badge b-' + esc(s.action) + '">' + esc(s.action) +
        '</span><span class="ms">' + (ran ? esc(Number(s.latency_ms).toFixed(2)) + " ms" : "-") + '</span></div><div class="tl-body">' + body + "</div></li>";
    });
    const lattice = (fin.lattice || []).map((a) => '<span class="lat' + (a === fin.action ? " on b-" + esc(a) : "") + '">' + esc(a) + "</span>").join(' <span class="muted">&lt;</span> ');
    steps.push('<li class="tl-step a-' + esc(fin.action) + '"><span class="tl-dot"></span><div class="tl-head"><b>Final action</b><span class="ms">' + esc(Number((t.latency_ms || {}).decide_total || 0).toFixed(2)) + ' ms</span></div><div class="tl-body"><div class="lattice">' + lattice + "</div>" +
      (fin.by ? "<div>by " + esc(fin.by.control_id) + " / " + esc(fin.by.rule_id) + "</div>" : "") + (fin.would && fin.would !== fin.action ? "<div>would be " + esc(fin.would) + " without shadow mode</div>" : "") +
      (fin.degraded ? '<div style="color:var(--warn)">degraded: a control failed or timed out, its fail mode applied</div>' : "") + "</div></li>");
    return '<ol class="tl">' + steps.join("") + "</ol>" + (t.records > 1 ? '<p class="muted">' + esc(t.records) + " decisions in this request: " + (t.record_stages || []).map(esc).join(", ") + "</p>" : "") +
      '<div class="trace" title="Server-Timing syntax; the response header itself covers the decisions made before the answer started">Stage timing, whole request: ' + esc(t.server_timing || "-") + "</div>";
  }
  async function loadTimeline(r) {
    try {
      const t = await getJSON(API + "/explain/" + encodeURIComponent(r.event_id));
      const box = $("#tl");
      if (selected !== r.event_id || !box) return;
      box.innerHTML = renderTimeline(t);
      box.querySelectorAll("a.rulelink").forEach((a) => (a.onclick = (e) => { e.preventDefault(); pendingRule = { rule: a.dataset.rule, control: a.dataset.control }; go("policy"); }));
    } catch (e) { const box = $("#tl"); if (selected === r.event_id && box) box.innerHTML = '<p class="muted">Timeline unavailable.</p>'; }
  }
  // the mark stays across live refreshes of the Policy page until the user leaves it (go) or edits
  function markPolicy() {
    if (!pendingRule) return;
    const want = pendingRule;
    const reEsc = (x) => String(x).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const lines = polText.split("\n");
    const tok = want.rule ? new RegExp("(^|[^A-Za-z0-9_.-])" + reEsc(want.rule) + "($|[^A-Za-z0-9_.-])") : null;
    let i = tok ? lines.findIndex((l) => !l.trimStart().startsWith("#") && tok.test(l)) : -1;
    const byRule = i >= 0;
    if (i < 0 && want.control) i = lines.findIndex((l) => l.trimStart().startsWith(want.control + ":"));
    $("#pol-msg").textContent = byRule || i < 0 || !want.rule ? "" : "Rule " + want.rule + " is built in or lives in policy/rules/: showing its control " + want.control + ".";
    if (i < 0) return;
    const html = $("#pol-yaml").innerHTML.split("\n");
    html[i] = '<mark class="hit" id="pol-hit">' + html[i] + "</mark>";
    $("#pol-yaml").innerHTML = html.join("\n");
    $("#pol-hit").scrollIntoView({ block: "center" });
  }

  async function loadEvents() { events = (await getJSON(API + "/events?limit=800")).events; render(); }
  ["#f-decision", "#f-proto"].forEach((s) => ($(s).onchange = render));
  $("#f-text").oninput = render;

  // ---- network
  async function loadNetwork() {
    loadInterception().catch(() => {});
    const n = await getJSON(API + "/network");
    const st = n.resolver || {};
    const hosts = n.intercepted_by_host || {};
    $("#net-tiles").innerHTML =
      tile("Intercepted lookups", num(Object.values(hosts).reduce((a, b) => a + b, 0)), "violet", plural(Object.keys(hosts).length, "provider host")) +
      tile("Resolver queries", num(st.queries || 0), "", num(st.forwarded || 0) + " forwarded upstream") +
      tile("Bypass attempts", num((n.bypass_alerts || []).length), (n.bypass_alerts || []).length ? "bad" : "ok", "DoH resolvers sinkholed") +
      tile("Proxied requests", num((n.passthrough || {}).total || 0), "", "probes, token counts, auth refresh");
    $("#bypass tbody").innerHTML = (n.bypass_alerts || []).map((b) => "<tr><td class='muted'>" + esc((b.ts || "").slice(11, 19)) + "</td><td>" + esc(b.principal) + " <span class='muted mono'>" + esc(b.client_ip || "") + "</span></td><td class='wrap'>" + esc(b.what) + "</td></tr>").join("") ||
      '<tr><td class="empty" colspan="3">No bypass attempts seen.</td></tr>';
    $("#net-hosts tbody").innerHTML = Object.entries(hosts).map(([h, c]) => "<tr><td class='mono'>" + esc(h) + '</td><td class="num">' + num(c) + "</td></tr>").join("") ||
      '<tr><td class="empty" colspan="2">No DNS traffic yet (the resolver runs in transparent mode).</td></tr>';
    const paths = (n.passthrough || {}).paths || {};
    $("#net-paths tbody").innerHTML = Object.entries(paths).map(([p, c]) => "<tr><td class='mono'>" + esc(p) + '</td><td class="num">' + num(c) + "</td></tr>").join("") ||
      '<tr><td class="empty" colspan="2">None.</td></tr>';
  }

  // ---- intercepted domains (T-115)
  async function loadInterception() {
    const ps = (await getJSON(API + "/interception")).providers || [];
    $("#icpt tbody").innerHTML = ps.map((p) => "<tr><td><b>" + esc(p.name) + "</b></td><td>" + (p.hosts || []).map((h) =>
      '<span class="tag">' + esc(h) + ' <a href="#" class="icpt-rm" data-p="' + esc(p.name) + '" data-h="' + esc(h) + '" title="stop intercepting">x</a></span>').join(" ") +
      '</td><td><span class="tag p-' + esc(p.protocol) + '">' + esc(p.protocol) + "</span></td><td class='mono'>" + esc(p.upstream || "") + "</td><td class='mono wrap'>" +
      esc((p.inspect || []).join(" ")) + "</td></tr>").join("") || '<tr><td class="empty" colspan="5">No providers.</td></tr>';
    const sel = $("#icpt-prov"), cur = sel.value;
    sel.innerHTML = ps.map((p) => "<option>" + esc(p.name) + "</option>").join("");
    if (cur) sel.value = cur;
    document.querySelectorAll(".icpt-rm").forEach((a) => (a.onclick = (e) => { e.preventDefault(); icptEdit({ remove_host: { provider: a.dataset.p, host: a.dataset.h } }); }));
  }
  async function icptEdit(body) {
    const m = $("#icpt-msg");
    try {
      const r = await fetch(API + "/interception", { method: "PUT", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      m.style.color = r.ok && j.ok ? "var(--ok)" : "var(--red)";
      m.textContent = r.ok && j.ok ? (j.what || "saved") + "; intercepted now: " + (j.hosts || []).join(", ") : "Rejected (HTTP " + r.status + "): " + (j.error || j.detail || "");
    } catch (e) { m.style.color = "var(--red)"; m.textContent = "Not saved: " + e.message; }
    loadInterception();
  }
  $("#icpt-add").onclick = () => icptEdit({ add_host: { provider: $("#icpt-prov").value, host: $("#icpt-host").value } });
  $("#icpt-addp").onclick = () => {
    const b = { name: $("#icpt-name").value, host: $("#icpt-phost").value, protocol: $("#icpt-proto").value };
    if ($("#icpt-up").value.trim()) b.upstream = $("#icpt-up").value.trim();
    icptEdit({ add_provider: b });
  };

  // ---- controls
  const MODES = ["enforce", "shadow", "off"];
  function modeSelect(id, cur, profile, locked) {
    return '<select class="modesel" data-id="' + esc(id) + '"' + (profile ? ' data-profile="' + profile + '"' : "") + ">" +
      MODES.filter((m) => !locked || m === "enforce").map((m) => "<option" + (m === cur ? " selected" : "") + ">" + m + "</option>").join("") + "</select>";
  }
  async function loadControls() {
    const c = (await getJSON(API + "/controls")).controls;
    $("#ctl tbody").innerHTML = c.map((x) => {
      const spec = x.mode_spec;
      const sel = spec && typeof spec === "object"
        ? ["strict", "balanced", "permissive"].map((p) => '<span class="muted" style="font-size:11px">' + p + "</span> " + modeSelect(x.id, spec[p] || "enforce", p, x.locked)).join(" ")
        : modeSelect(x.id, x.mode, null, x.locked);
      return "<tr><td><code>" + esc(x.id) + "</code></td><td>" + esc(x.name) + (x.locked ? ' <span class="muted" title="cannot be switched off from the console">(locked on)</span>' : "") +
        "</td><td>" + esc(x.category) + "</td><td>" + esc(x.severity) + '</td><td><span class="badge ' + (x.mode === "enforce" ? "b-ALLOW" : x.mode === "shadow" ? "b-WARN" : "b-BLOCK") + '">' +
        esc(x.mode) + "</span></td><td>" + sel + "</td><td>" + esc(x.action) + '</td><td class="num">' + num(x.hits) + "</td></tr>";
    }).join("");
    document.querySelectorAll("#ctl .modesel").forEach((s) => (s.onchange = async () => {
      const m = $("#ctl-msg");
      const body = { mode: s.value };
      if (s.dataset.profile) body.profile = s.dataset.profile;
      try {
        const r = await fetch(API + "/controls/" + encodeURIComponent(s.dataset.id), { method: "PUT", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify(body) });
        const j = await r.json().catch(() => ({}));
        m.style.color = r.ok && j.ok ? "var(--ok)" : "var(--red)";
        m.textContent = r.ok && j.ok ? s.dataset.id + ": " + JSON.stringify(j.old) + " -> " + JSON.stringify(j.new) + ", live (policy " + String(j.version).slice(0, 12) + ")"
          : "Rejected (HTTP " + r.status + "): " + (j.error || j.detail || "");
      } catch (e) { m.style.color = "var(--red)"; m.textContent = "Not saved: " + e.message; }
      loadControls(); loadSummary();
    }));
  }

  // ---- policy
  function yamlHtml(t) {
    return String(t).split("\n").map((raw) => {      // find the comment in the RAW line, then escape both halves
      const m = raw.match(/^((?:[^#"']|"[^"]*"|'[^']*')*)(#.*)?$/);
      const code = esc(m ? m[1] : raw), cmt = m && m[2] ? '<span class="c">' + esc(m[2]) + "</span>" : "";
      return code.replace(/^(\s*-?\s*)([A-Za-z0-9_."*-]+)(:)/, '$1<span class="k">$2</span>$3') + cmt;
    }).join("\n");
  }
  async function loadPolicy() {
    const [p, st] = await Promise.all([getJSON(API + "/policy"), getJSON(API + "/status").catch(() => ({}))]);
    const b = $("#pol-banner");
    if (p.error) { b.className = "banner err"; b.textContent = "Last edit rejected, the previous policy stays live: " + p.error; }
    else { b.className = "banner ok"; b.innerHTML = "Live policy <code>" + esc((p.version || "").slice(0, 16)) + "</code>, profile <b>" + esc(p.profile || "-") + "</b>, " + num(p.rules) + " signature rules with inline tests, files: " + (p.files || []).map((f) => "<code>" + esc(f) + "</code>").join(" "); }
    const ic = p.interception || {};
    const styles = Object.entries(ic.block_style || {}).map(([k, v]) => "<tr><td>" + esc(protoName(k)) + "</td><td class='mono'>" + esc(v.hard) + "</td><td class='mono'>" + esc(v.soft) + "</td><td class='mono'>" + esc(v.budget) + "</td></tr>").join("");
    $("#pol-cards").innerHTML =
      '<div class="card"><h2>Interception</h2><div class="kv"><b>Runtime mode</b><span>' + esc(MODE_NAME[st.mode] || st.mode || "-") + "</span><b>Listeners</b><span class=\"prose\">" + esc(listenerText(st)) +
        "</span>" + (st.warnings || []).map((x) => '<b>Warning</b><span class="prose" style="color:var(--warn)">' + esc(x) + "</span>").join("") +
        (st.notes || []).map((x) => '<b>Note</b><span class="prose">' + esc(x) + "</span>").join("") + "<b>Policy mode</b><span>" + esc(ic.mode || "-") + "</span><b>Credentials</b><span>" + esc(ic.credentials || "-") + "</span><b>Hosts</b><span>" + (ic.hosts || []).map((h) => "<code>" + esc(h) + "</code>").join(" ") + "</span></div></div>" +
      '<div class="card"><h2>Native block contract</h2><div class="tablewrap"><table><thead><tr><th>API</th><th>Hard</th><th>Soft</th><th>Budget</th></tr></thead><tbody>' + styles + "</tbody></table></div></div>" +
      '<div class="card"><h2>Clients (identity)</h2><table><thead><tr><th>Match</th><th>Principal</th><th>Profile</th></tr></thead><tbody>' +
      (p.clients || []).map((c) => "<tr><td class='mono'>" + esc(JSON.stringify(c.match)) + "</td><td>" + esc(c.principal) + "</td><td>" + esc(c.profile || "-") + "</td></tr>").join("") + "</tbody></table></div>" +
      '<div class="card"><h2>Signed signature feed</h2>' + (p.feed ? '<div class="kv"><b>Source</b><span class="mono">' + esc(p.feed.url) + "</span><b>Version</b><span>" + esc(p.feed.version) +
        (p.feed.rules != null ? " (" + esc(p.feed.rules) + " rules)" : "") + "</span><b>Last check</b><span>" + esc(p.feed.last_check || "-") + "</span><b>Status</b><span" +
        (p.feed.last_error ? ' style="color:var(--red)">rejected: ' + esc(p.feed.last_error) : ' style="color:var(--ok)">verified (Ed25519), no rollback, inline tests passed') + "</span></div>"
        : '<p class="muted">Not configured. Set AICL_FEED_URL and AICL_FEED_PUBKEY: bundles are Ed25519-signed, rollback is refused, and every rule must pass its inline tests before it goes live.</p>') + "</div>";
    if (!editing) { $("#pol-yaml").innerHTML = yamlHtml(p.yaml || ""); polText = p.yaml || ""; markPolicy(); }
    $("#foot-policy").textContent = "policy " + (p.version || "").slice(0, 12);
    await loadBudgetEditor();
  }

  // ---- policy + budget editor (T-107)
  let editing = false, polText = "";
  try { $("#admin-token").value = sessionStorage.getItem("aicl-admin") || ""; } catch (e) {}
  $("#admin-token").oninput = () => { try { sessionStorage.setItem("aicl-admin", $("#admin-token").value); } catch (e) {} };
  function authHeaders(extra) {
    const t = $("#admin-token").value.trim();
    return Object.assign(t ? { Authorization: "Bearer " + t } : {}, extra || {});
  }
  function setEditing(on) {
    editing = on;
    $("#pol-text").style.display = on ? "block" : "none";
    $("#pol-yaml").style.display = on ? "none" : "block";
    $("#pol-save").style.display = on ? "inline-flex" : "none";
    $("#pol-cancel").style.display = on ? "inline-flex" : "none";
    $("#pol-edit").style.display = on ? "none" : "inline-flex";
    if (on) $("#pol-text").value = polText;
  }
  $("#pol-edit").onclick = () => { setEditing(true); $("#pol-msg").textContent = ""; };
  $("#pol-cancel").onclick = () => { setEditing(false); $("#pol-msg").textContent = ""; };
  $("#pol-save").onclick = async () => {
    const m = $("#pol-msg");
    m.textContent = "Validating...";
    try {
      const r = await fetch(API + "/policy", { method: "PUT", headers: authHeaders({ "Content-Type": "text/plain" }), body: $("#pol-text").value });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.ok) { m.style.color = "var(--ok)"; m.textContent = "Applied, policy " + String(j.version).slice(0, 12); setEditing(false); refresh(true); }
      else { m.style.color = "var(--red)"; m.textContent = "Rejected (HTTP " + r.status + "), live policy unchanged: " + (j.error || j.detail || ""); }
    } catch (e) { m.style.color = "var(--red)"; m.textContent = "Not saved: " + e.message; }
  };
  async function loadBudgetEditor() {
    const b = await getJSON(API + "/budgets");
    const used = {};
    (b.usage || []).forEach((u) => (used[u.agent_id] = u));
    const rows = Object.entries(b.agents || {});
    $("#bud-edit tbody").innerHTML = rows.map(([id, v]) => {
      const u = used[id] || {};
      const per = ["minute", "hour", "day", "month"].map((p) => "<option" + (p === v.period ? " selected" : "") + ">" + p + "</option>").join("");
      return '<tr data-id="' + esc(id) + '"><td><b>' + esc(id) + '</b></td><td><input data-k="tokens" type="number" min="0" step="1000" data-orig="' + esc(v.tokens ?? "") + '" value="' + esc(v.tokens ?? "") +
        '" style="width:140px"></td><td><input data-k="usd" type="number" min="0" step="0.01" data-orig="' + esc(v.usd ?? "") + '" value="' + esc(v.usd ?? "") + '" style="width:110px"></td><td><select data-k="period" data-orig="' + esc(v.period ?? "") + '">' + per +
        "</select></td><td class='muted'>" + num((u.tokens || 0) + (u.reserved_tokens || 0)) + " tok, " + usd((u.usd || 0) + (u.reserved_usd || 0)) + "</td></tr>";
    }).join("") || '<tr><td class="empty" colspan="5">No budgets in the policy.</td></tr>';
  }
  $("#bud-save").onclick = async () => {
    const agents = {};
    document.querySelectorAll("#bud-edit tbody tr[data-id]").forEach((tr) => {
      const e = {};
      tr.querySelectorAll("[data-k]").forEach((i) => {
        if (i.value !== "" && i.value !== i.dataset.orig) e[i.dataset.k] = i.dataset.k === "period" ? i.value : Number(i.value);
      });
      if (Object.keys(e).length) agents[tr.dataset.id] = e;   // only what the admin changed
    });
    const m = $("#bud-msg");
    if (!Object.keys(agents).length) { m.style.color = ""; m.textContent = "Nothing changed."; return; }
    try {
      const r = await fetch(API + "/budgets", { method: "PUT", headers: authHeaders({ "Content-Type": "application/json" }), body: JSON.stringify({ agents }) });
      const j = await r.json().catch(() => ({}));
      m.style.color = r.ok && j.ok ? "var(--ok)" : "var(--red)";
      m.textContent = r.ok && j.ok ? "Saved and applied, policy " + String(j.version).slice(0, 12) : "Rejected (HTTP " + r.status + "): " + (j.error || j.detail || "");
      if (r.ok) refresh(true);
    } catch (e) { m.style.color = "var(--red)"; m.textContent = "Not saved: " + e.message; }
  };

  // ---- performance
  async function loadPerformance() {
    const rows = (await getJSON(API + "/performance")).controls;
    const tot = rows.find((r) => r.control === "total") || { p50: 0, p95: 0, max: 0, count: 0 };
    const det = rows.filter((r) => r.control !== "total" && r.control !== "INJ-04");
    const detP95 = det.reduce((a, r) => a + r.p95, 0);
    const judge = rows.find((r) => r.control === "INJ-04");
    $("#perf-tiles").innerHTML =
      tile("Decision p50", tot.p50 + " ms", "ok", num(tot.count) + " decisions") +
      tile("Decision p95", tot.p95 + " ms", tot.p95 > 500 ? "warn" : "ok", "max " + tot.max + " ms") +
      tile("Deterministic controls", detP95.toFixed(1) + " ms", "ok", "sum of p95 over " + det.length + " controls") +
      tile("Local AI judge", judge ? judge.p50 + " ms" : "-", "violet", judge ? "p50, cached verdicts are free" : "not invoked yet");
    $("#perf tbody").innerHTML = rows.map((r) => "<tr><td><code>" + esc(r.control) + '</code></td><td class="num">' + num(r.count) + '</td><td class="num">' + r.p50 + '</td><td class="num">' + r.p95 + '</td><td class="num">' + r.max + "</td></tr>").join("") ||
      '<tr><td class="empty" colspan="5">No decisions yet.</td></tr>';
    const pr = rows.filter((r) => r.control !== "total");
    drawChart("perf", "#ch-perf", "#fb-perf", {
      type: "bar",
      data: { labels: pr.map((r) => r.control), datasets: [{ label: "p95 ms", data: pr.map((r) => r.p95), backgroundColor: pr.map((r) => r.control === "INJ-04" ? col("--violet", "#7c3aed") : col("--accent", "#4f46e5")), borderRadius: 6 }] },
      options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { type: "logarithmic" }, y: { grid: { display: false } } } },
    }, pr.map((r) => r.control), pr.map((r) => r.p95));
  }

  // ---- header chips
  const MODE_NAME = { transparent: "transparent", base_url: "base-URL", proxy: "proxy", off: "off" };
  // T-116: the chip shows the listeners this process really runs, not the policy's interception.mode
  function listenerText(s) {
    const l = s.listeners || {}, on = (x) => x && x.on;
    return ["HTTP " + (on(l.http) ? ":" + l.http.port : "off"), "TLS " + (on(l.tls) ? ":" + l.tls.port : "off"),
      "DNS " + (on(l.dns) ? ":" + l.dns.port : "off"), "CA " + (s.ca && s.ca.present ? "present" : "missing")].join(", ");
  }
  async function loadMode() {
    const s = await getJSON(API + "/status");
    const w = s.warnings || [], n = s.notes || [];
    const c = $("#chip-mode");
    c.textContent = "mode: " + (MODE_NAME[s.mode] || s.mode || "-") + (w.length ? " (" + w.length + " warning" + (w.length > 1 ? "s" : "") + ")" : "");
    c.className = "chip mode" + (w.length ? " warn" : "");
    c.title = ["Runtime: " + listenerText(s), "Policy interception.mode: " + (s.policy_mode || "-")].concat(w.map((x) => "Warning: " + x), n.map((x) => "Note: " + x)).join("\n");
    return s;
  }
  async function loadHeader() {
    try {
      const [, p] = await Promise.all([loadMode().catch(() => {}), getJSON(API + "/policy")]);
      const c = $("#chip-policy");
      c.textContent = (p.error ? "policy error, last good " : "policy ") + (p.version || "").slice(0, 10);
      c.className = "chip" + (p.error ? " err" : "");
      $("#foot-policy").textContent = "policy " + (p.version || "").slice(0, 12);
    } catch (e) {}
  }

  const LOADERS = { overview: loadSummary, clients: loadClients, security: loadEvents, network: loadNetwork, controls: loadControls,
    policy: loadPolicy, performance: loadPerformance, playground: async () => {}, audit: async () => {} };
  let pending = null;
  function refresh(now) {
    if (pending && !now) return;
    clearTimeout(pending);
    pending = setTimeout(() => {
      pending = null;
      Promise.all([LOADERS[page](), page !== "overview" ? loadSummary() : null, loadHeader()]).catch((e) => console.warn(e));
    }, now ? 0 : 800);
  }

  // live stream
  function live() {
    if (!window.EventSource || /[?&]nolive=1/.test(location.search)) return;   // nolive: static snapshots
    const es = new EventSource(API + "/stream");
    es.onopen = () => { const p = $("#live"); p.innerHTML = '<span class="dot"></span>live'; p.className = "chip on"; };
    es.onerror = () => { const p = $("#live"); p.innerHTML = '<span class="dot"></span>reconnecting'; p.className = "chip"; };
    es.addEventListener("audit", (e) => {
      const r = JSON.parse(e.data);
      events.unshift(r);
      if (events.length > 800) events.pop();
      if (page === "security") {
        if (matches(r)) { const tb = $("#events tbody"); if (tb.querySelector(".empty")) tb.innerHTML = ""; tb.prepend(row(r, true)); }
        $("#count").textContent = events.filter(matches).length + " of " + events.length + " events";
      }
      refresh(false);
    });
  }

  // playground
  $("#pg-run").onclick = async () => {
    const out = $("#pg-out");
    out.className = "result"; out.textContent = "Sending...";
    const t0 = performance.now();
    try {
      const dest = $("#pg-dest").value;
      let pc = { api_key: null, models: { local: [], external: [] } };
      try { pc = await getJSON("/console/api/playground"); } catch (e) {}
      const model = dest === "unknown" ? "unknown-model" : (pc.models[dest] || [])[0] || (dest === "local" ? "qwen3.5:2b-q4_K_M" : "gpt-4o-mini");
      const headers = { "Content-Type": "application/json", "X-AICL-Destination": dest };
      let sameOrigin = false;
      try { sameOrigin = new URL($("#pg-url").value, location.href).origin === location.origin; } catch (e) {}
      if (pc.api_key && sameOrigin) headers["Authorization"] = "Bearer " + pc.api_key;
      const r = await fetch($("#pg-url").value, { method: "POST", headers, body: JSON.stringify({ model, messages: [{ role: "user", content: $("#pg-text").value }] }) });
      const txt = await r.text();
      let body = txt; try { body = JSON.stringify(JSON.parse(txt), null, 2); } catch (e) {}
      const dec = ["x-aicl-decision", "server-timing", "x-aicl-request-id"].map((h) => r.headers.get(h) ? h + ": " + r.headers.get(h) : "").filter(Boolean).join("\n");
      let trace = "";
      const rid = r.headers.get("x-aicl-request-id");
      if (rid) {
        try {
          const evs = (await getJSON(API + "/events?limit=20&request_id=" + encodeURIComponent(rid))).events.slice().reverse();
          trace = "\n\nPolicy decisions:\n" + evs.map((e) => "- " + e.stage + ": " + dn(e.decision) + " (" + e.event_type + ")" +
            (e.findings || []).map((f) => "\n    " + f.control_id + " / " + f.rule_id + " [" + f.category + "]").join("") +
            (e.explain || []).map((x) => "\n    > " + x).join("")).join("\n");
        } catch (e) {}
      }
      const verdict = r.headers.get("x-aicl-decision") || (r.status >= 400 ? "error" : "no decision");
      out.textContent = "HTTP " + r.status + " - decision " + verdict + " in " + Math.round(performance.now() - t0) + " ms\n" + dec + trace + "\n\nResponse:\n" + body;
    } catch (e) {
      out.textContent = "Gateway not reachable at " + $("#pg-url").value + ": " + e.message;
    }
  };

  const start = (location.hash || "").slice(1);
  Promise.all([loadSummary(), loadEvents(), loadHeader()]).catch((e) => { $("#tiles").innerHTML = '<div class="card muted">Console API unavailable: ' + esc(e.message) + "</div>"; })
    .then(() => { if (PAGES[start] && start !== "overview") go(start); live(); });
})();

"use strict";
(function () {
  const $ = (s, r) => (r || document).querySelector(s);
  const API = "/console/api";
  const DN = ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"];
  const dn = (v) => (typeof v === "number" ? DN[v] || "ALLOW" : String(v || "ALLOW").toUpperCase());
  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  let events = [];
  let charts = {};
  let selected = null;

  // theme + nav
  try { const t = localStorage.getItem("aicl-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
  $("#theme").onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const nx = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = nx;
    try { localStorage.setItem("aicl-theme", nx); } catch (e) {}
  };
  document.querySelectorAll("#nav button").forEach((b) => (b.onclick = () => {
    document.querySelectorAll("#nav button").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(".page").forEach((p) => p.classList.toggle("active", p.id === "page-" + b.dataset.page));
  }));

  async function getJSON(u) { const r = await fetch(u); if (!r.ok) throw new Error(u + " " + r.status); return r.json(); }

  // overview
  function tile(label, value, cls, extra) {
    return '<div class="tile ' + (cls || "") + '"><div class="v">' + esc(value) + '</div><div class="l">' + esc(label) + "</div>" + (extra || "") + "</div>";
  }
  function bar(p) { return '<div class="bar"><i style="width:' + Math.min(100, p) + '%"></i></div>'; }
  function fallbackBars(el, labels, values) {
    const max = Math.max(1, ...values);
    el.innerHTML = labels.map((l, i) => '<div class="fb-row"><span>' + esc(l) + '</span><i style="width:' + (100 * values[i] / max) + '%;min-width:2px"></i><b>' + values[i] + "</b></div>").join("");
    el.parentElement.classList.add("nochart");
  }
  function drawChart(key, canvasId, fbId, cfg, labels, values) {
    if (window.Chart) {
      if (charts[key]) { charts[key].data = cfg.data; charts[key].update(); return; }
      charts[key] = new Chart($(canvasId), cfg);
    } else {
      fallbackBars($(fbId), labels, values);
    }
  }
  async function loadSummary() {
    const s = await getJSON(API + "/summary");
    $("#tiles").innerHTML =
      tile("AI requests", s.requests) +
      tile("Blocked", s.blocked, "bad") +
      tile("Redacted", s.redacted, "warn") +
      tile("Allowed", s.allowed, "ok") +
      tile("API cost (simulated, USD)", "$" + s.cost_usd.toFixed(4), "", '<div class="l">' + esc(s.tokens || 0) + " tokens</div>") +
      tile("Budget used", s.budget_used_pct + "%", s.budget_used_pct >= 80 ? "bad" : "", '<div class="l">of $' + esc(s.budget_usd) + " USD budget</div>" + bar(s.budget_used_pct)) +
      tile("Security posture", s.posture_pct + "%", s.posture_pct >= 80 ? "ok" : "warn", '<div class="l">' + s.controls_enforced + "/" + s.controls_total + " controls enforced</div>" + bar(s.posture_pct));
    const tl = s.timeline;
    const tlabels = tl.map((x) => x.t.slice(11));
    const css = getComputedStyle(document.documentElement);
    const col = (n, d) => css.getPropertyValue(n).trim() || d;
    drawChart("time", "#ch-time", "#fb-time", {
      type: "bar",
      data: { labels: tlabels, datasets: [
        { label: "allow", data: tl.map((x) => x.allow), backgroundColor: col("--ok", "#2f9e44") },
        { label: "redact", data: tl.map((x) => x.redact), backgroundColor: col("--warn", "#e8890c") },
        { label: "block", data: tl.map((x) => x.block), backgroundColor: col("--red", "#e03131") } ] },
      options: { maintainAspectRatio: false, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true } } },
    }, tlabels, tl.map((x) => x.allow + x.redact + x.block));
    const cl = Object.keys(s.categories), cv = cl.map((k) => s.categories[k]);
    drawChart("cat", "#ch-cat", "#fb-cat", {
      type: "doughnut",
      data: { labels: cl, datasets: [{ data: cv, backgroundColor: ["#3b5bdb", "#e8890c", "#e03131", "#2f9e44", "#9c36b5", "#1098ad"] }] },
      options: { maintainAspectRatio: false },
    }, cl, cv);
  }

  // security
  function ctrls(r) { return [...new Set((r.findings || []).map((f) => f.control_id))].join(", "); }
  function row(r, isNew) {
    const tr = document.createElement("tr");
    if (isNew) tr.className = "new";
    tr.dataset.id = r.event_id;
    tr.innerHTML = "<td>" + esc((r.ts || "").slice(11, 19)) + '</td><td><span class="badge b-' + dn(r.decision) + '">' + dn(r.decision) + "</span></td><td>" + esc(r.severity) + "</td><td>" + esc(r.event_type) + (r.tool ? " <code>" + esc(r.tool) + "</code>" : "") + "</td><td>" + esc(r.agent_id) + "</td><td>" + esc(r.destination) + "</td><td>" + esc(ctrls(r)) + "</td>";
    tr.onclick = () => select(r);
    return tr;
  }
  function matches(r) {
    const d = $("#f-decision").value, t = $("#f-text").value.toLowerCase();
    if (d && dn(r.decision) !== d) return false;
    if (!t) return true;
    const hay = [r.agent_id, r.tool, r.event_type, ctrls(r), (r.findings || []).map((f) => f.rule_id + " " + ((f.spans || []).map((s) => s.type).join(" "))).join(" ")].join(" ").toLowerCase();
    return hay.includes(t);
  }
  function render() {
    const tb = $("#events tbody");
    tb.innerHTML = "";
    const shown = events.filter(matches);
    shown.forEach((r) => tb.appendChild(row(r)));
    $("#count").textContent = shown.length + " of " + events.length + " events";
  }
  function select(r) {
    selected = r.event_id;
    document.querySelectorAll("#events tr").forEach((t) => t.classList.toggle("sel", t.dataset.id === selected));
    const fs = (r.findings || []).map((f) => "<li><code>" + esc(f.control_id) + " / " + esc(f.rule_id) + "</code> " + esc(f.category) + " -> <b>" + esc(typeof f.action === "number" ? ["ALLOW", "LOG", "WARN", "REDACT", "BLOCK"][f.action] : f.action) + "</b>" +
      (f.score != null ? " score " + f.score + " vs threshold " + f.threshold : "") +
      ((f.spans || []).length ? " spans: " + f.spans.map((s) => esc(s.type) + "[" + s.start + "-" + s.end + "] #" + esc(s.sha256_8)).join(", ") : "") +
      " <span class='muted'>(" + esc(f.rule_source) + ")</span></li>").join("");
    const lat = r.latency_us || {};
    $("#explain").innerHTML = "<h2>Explain</h2>" +
      '<span class="badge b-' + dn(r.decision) + '">' + dn(r.decision) + "</span> " + esc(r.event_type) +
      '<div class="kv"><b>Event</b><span>' + esc(r.event_id) + "</span><b>Stage</b><span>" + esc(r.stage) + " (" + esc(r.channel) + ")</span><b>Agent</b><span>" + esc(r.agent_id) + "</span><b>Model</b><span>" + esc(r.model || "-") + " (" + esc(r.destination) + ")</span>" +
      (r.would_decision != null && dn(r.would_decision) !== dn(r.decision) ? "<b>Would be</b><span>" + dn(r.would_decision) + " (shadow)</span>" : "") +
      "<b>Policy</b><span>" + esc(r.policy_version) + "</span><b>Latency</b><span>" + esc(lat.total != null ? (lat.total / 1000).toFixed(1) + " ms" : "-") + "</span></div>" +
      "<h2>Findings</h2><ul>" + (fs || "<li class='muted'>none</li>") + "</ul><h2>Trace</h2><ul>" + (r.explain || []).map((x) => "<li>" + esc(x) + "</li>").join("") + "</ul>";
  }
  async function loadEvents() {
    events = (await getJSON(API + "/events?limit=500")).events;
    render();
  }
  $("#f-decision").onchange = render;
  $("#f-text").oninput = render;

  // controls
  async function loadControls() {
    const c = (await getJSON(API + "/controls")).controls;
    $("#ctl tbody").innerHTML = c.map((x) => "<tr><td><code>" + esc(x.id) + "</code></td><td>" + esc(x.name) + "</td><td>" + esc(x.category) + "</td><td>" + esc(x.severity) + '</td><td><span class="badge ' + (x.mode === "enforce" ? "b-ALLOW" : x.mode === "shadow" ? "b-WARN" : "") + '">' + esc(x.mode) + "</span></td><td>" + esc(x.action) + "</td><td>" + x.hits + "</td></tr>").join("");
  }

  // live stream
  function live() {
    if (!window.EventSource) return;
    const es = new EventSource(API + "/stream");
    es.onopen = () => { const p = $("#live"); p.textContent = "live"; p.className = "pill on"; };
    es.onerror = () => { const p = $("#live"); p.textContent = "offline"; p.className = "pill off"; };
    es.addEventListener("audit", (e) => {
      const r = JSON.parse(e.data);
      events.unshift(r);
      if (events.length > 500) events.pop();
      if (matches(r)) { $("#events tbody").prepend(row(r, true)); }
      $("#count").textContent = events.length + " events";
      loadSummary().catch(() => {}); loadControls().catch(() => {});
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
      const r = await fetch($("#pg-url").value, {
        method: "POST", headers,
        body: JSON.stringify({ model, messages: [{ role: "user", content: $("#pg-text").value }] }),
      });
      const txt = await r.text();
      let body = txt; try { body = JSON.stringify(JSON.parse(txt), null, 2); } catch (e) {}
      const dec = ["x-aicl-decision", "x-aicl-action", "server-timing", "x-aicl-request-id"].map((h) => r.headers.get(h) ? h + ": " + r.headers.get(h) : "").filter(Boolean).join("\n");
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

  const boot = () => Promise.all([loadSummary(), loadEvents(), loadControls()]).catch((e) => { $("#tiles").innerHTML = '<div class="card muted">Console API unavailable: ' + esc(e.message) + "</div>"; });
  boot().then(live);
})();

"use strict";

// The ARGUS console: dependency-free, no build step, no external CDN. It reads
// the admin HTTP API on the same origin and subscribes to the alert stream over
// Server-Sent Events. Screens whose backends do not exist yet (Hunt, Automation,
// AI analyst) arrive with their phases; everything here is backed by real data.

// ---- tiny DOM helpers ----------------------------------------------------
const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k === "html") node.innerHTML = v;
    else node.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
};
const pick = (obj, ...keys) => {
  for (const k of keys) if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
  return undefined;
};
async function getJSON(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return res.json();
}
const fmtTime = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
};
const sevText = (s) => (typeof s === "number" ? ["", "low", "medium", "high", "critical"][s] || s : s || "");
const sevClass = (s) => "sev sev-" + String(sevText(s)).toLowerCase();
const sevBadge = (s) => el("span", { class: sevClass(s), text: sevText(s) || "—" });

function toast(msg) {
  const t = el("div", { class: "toast", text: msg });
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 4000);
}

// ---- routing -------------------------------------------------------------
const routes = {
  overview: { title: "Overview", render: renderOverview },
  alerts: { title: "Alerts", render: renderAlerts },
  investigation: { title: "Investigation", render: renderInvestigation },
  detections: { title: "Detections", render: renderDetections },
  fleet: { title: "Fleet", render: renderFleet },
};
let currentRoute = "overview";

function navigate(route) { location.hash = "#/" + route; }

function applyRoute() {
  const route = (location.hash.replace(/^#\//, "") || "overview");
  const def = routes[route] || routes.overview;
  currentRoute = routes[route] ? route : "overview";
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === currentRoute));
  document.querySelectorAll(".screen").forEach((s) => s.classList.toggle("active", s.id === currentRoute));
  $("#page-title").textContent = def.title;
  def.render();
}

// ---- overview ------------------------------------------------------------
async function renderOverview() {
  let agents = [], incidents = [], recent = [];
  try { agents = await getJSON("/api/agents"); } catch (_) {}
  try { incidents = await getJSON("/api/alerts?incidents=true&limit=8"); } catch (_) {}
  try { recent = await getJSON("/api/alerts?limit=8"); } catch (_) {}

  const sum = (key) => agents.reduce((n, a) => n + (a[key] || 0), 0);
  $("#ov-tiles").replaceChildren(
    tile(agents.length, "agents"),
    tile(agents.filter((a) => a.online).length, "online", true),
    tile(sum("events_processed").toLocaleString(), "events"),
    tile(sum("alerts").toLocaleString(), "alerts"),
    tile(sum("incidents").toLocaleString(), "incidents"),
  );
  $("#ov-incidents").replaceChildren(...incidents.map((a) => el("tr", {},
    el("td", { text: fmtTime(pick(a, "Time", "time")) }),
    el("td", { text: pick(a, "Hostname", "hostname") || "—" }),
    el("td", { class: "mono", text: pick(a, "RuleID", "rule_id") || "—" }),
    el("td", { class: "mono", text: pick(a, "RiskScore", "risk_score") || 0 }),
  )) || []);
  $("#ov-alerts").replaceChildren(...recent.map((a) => el("tr", {},
    el("td", { text: fmtTime(pick(a, "Time", "time")) }),
    el("td", {}, sevBadge(pick(a, "Severity", "severity"))),
    el("td", { class: "mono", text: pick(a, "RuleID", "rule_id") || "—" }),
    el("td", { text: pick(a, "Hostname", "hostname") || "—" }),
  )));
}
const tile = (n, label, accent) => el("div", { class: "tile" + (accent ? " accent" : "") },
  el("div", { class: "n", text: String(n) }), el("div", { class: "l", text: label }));

// ---- alerts --------------------------------------------------------------
function alertQuery() {
  const params = new URLSearchParams();
  const host = $("#f-host").value.trim();
  const sev = $("#f-sev").value;
  const tech = $("#f-tech").value.trim();
  if (host) params.set("host", host);
  if (sev) params.set("severity", sev);
  if (tech) params.set("technique", tech);
  if ($("#f-inc").checked) params.set("incidents", "true");
  params.set("limit", "200");
  return params;
}
function alertRow(a) {
  const row = el("tr", { class: "clickable" },
    el("td", { text: fmtTime(pick(a, "Time", "time")) }),
    el("td", {}, sevBadge(pick(a, "Severity", "severity"))),
    el("td", { class: "mono", text: pick(a, "RuleID", "rule_id") || "—" }),
    el("td", { class: "tech", text: pick(a, "TechniqueID", "technique_id") || "—" }),
    el("td", { text: pick(a, "Hostname", "hostname") || "—" }),
    el("td", { class: "mono", text: pick(a, "PID", "pid") || "—" }),
    el("td", { text: pick(a, "ProcessName", "process_name") || "—" }),
    el("td", { class: "mono", text: pick(a, "DestinationIP", "destination_ip") || "—" }),
    el("td", { class: "mono", text: pick(a, "RiskScore", "risk_score") || 0 }),
  );
  row.addEventListener("click", () => openAlertDrawer(a));
  return row;
}
async function renderAlerts() {
  let rows = [];
  try { rows = await getJSON("/api/alerts?" + alertQuery().toString()); } catch (_) { return; }
  $("#alerts-count").textContent = `${rows.length} alert(s)`;
  $("#alerts-body").replaceChildren(...rows.map(alertRow));
}
function liveAlertMatchesFilter(a) {
  const host = $("#f-host").value.trim();
  const sev = $("#f-sev").value;
  const tech = $("#f-tech").value.trim();
  if (host && pick(a, "Hostname", "hostname") !== host) return false;
  if (sev && String(sevText(pick(a, "Severity", "severity"))).toLowerCase() !== sev) return false;
  if (tech && pick(a, "TechniqueID", "technique_id") !== tech) return false;
  if ($("#f-inc").checked && !pick(a, "IsIncident", "is_incident")) return false;
  return true;
}

// ---- drawer (alert detail + triage) -------------------------------------
function openAlertDrawer(a) {
  const isIncident = pick(a, "IsIncident", "is_incident");
  const rows = [
    ["Rule", `${pick(a, "RuleID", "rule_id") || ""} ${pick(a, "RuleName", "rule_name") || ""}`],
    ["Severity", sevText(pick(a, "Severity", "severity"))],
    ["Technique", `${pick(a, "TechniqueID", "technique_id") || ""} ${pick(a, "TechniqueName", "technique_name") || ""}`],
    ["Host", pick(a, "Hostname", "hostname")],
    ["Process", `${pick(a, "ProcessName", "process_name") || ""} (pid ${pick(a, "PID", "pid") || "?"})`],
    ["Executable", pick(a, "ProcessExecutable", "process_executable")],
    ["Destination", pick(a, "DestinationIP", "destination_ip")],
    ["Risk", pick(a, "RiskScore", "risk_score")],
    ["Time", fmtTime(pick(a, "Time", "time"))],
  ];
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of rows) {
    if (v === undefined || v === null || v === "") continue;
    dl.append(el("dt", { text: k }), el("dd", { class: "mono", text: String(v) }));
  }
  const kids = [
    el("button", { class: "icon-btn close", "aria-label": "Close" }, document.createTextNode("✕")),
    el("h3", { html: '<span class="' + sevClass(pick(a, "Severity", "severity")) + '">' + (sevText(pick(a, "Severity", "severity")) || "") + "</span> Alert" }),
    dl,
    el("div", { id: "drawer-triage" }),
  ];
  if (isIncident) {
    const btn = el("button", { class: "btn", text: "Run triage" });
    btn.addEventListener("click", () => renderTriageInto("#drawer-triage", pick(a, "ID", "id")));
    kids.push(btn);
  }
  $("#drawer").replaceChildren(...kids);
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawer").classList.add("show");
  $("#overlay").classList.add("show");
}
function closeDrawer() {
  $("#drawer").classList.remove("show");
  $("#overlay").classList.remove("show");
}

async function renderTriageInto(sel, id) {
  const panel = $(sel);
  panel.replaceChildren(el("div", { class: "muted", text: "Running triage…" }));
  let r;
  try { r = await getJSON("/api/alerts/" + encodeURIComponent(id) + "/triage"); }
  catch (_) { panel.replaceChildren(el("div", { class: "empty", text: "Triage unavailable." })); return; }
  const kids = [
    el("h3", {}, el("span", { text: "Triage " }), sevBadge(r.severity), el("span", { class: "muted", text: " · " + (r.source || "") })),
    el("p", { class: "summary", text: r.summary || "" }),
    el("ul", { class: "steps" }, ...(r.containment || []).map((s) => el("li", { text: s }))),
  ];
  if (r.rule_draft) kids.push(el("pre", { class: "draft", text: r.rule_draft }));
  panel.replaceChildren(...kids);
}

// ---- investigation -------------------------------------------------------
async function renderInvestigation() {
  const host = $("#i-host").value.trim();
  const tl = $("#timeline");
  if (!host) { tl.replaceChildren(el("div", { class: "empty", text: "Enter a host to reconstruct its alert chain." })); return; }
  let rows = [];
  try { rows = await getJSON("/api/alerts?limit=500&host=" + encodeURIComponent(host)); } catch (_) { return; }
  if (!rows.length) { tl.replaceChildren(el("div", { class: "empty", text: "No alerts for " + host })); return; }
  $("#triage").replaceChildren(el("div", { class: "muted", text: "Select an incident node to triage." }));
  tl.replaceChildren(...rows.map((a) => {
    const proc = pick(a, "ProcessExecutable", "process_executable", "ProcessName", "process_name") || "process";
    const tech = pick(a, "TechniqueID", "technique_id");
    const dest = pick(a, "DestinationIP", "destination_ip");
    const chain = [proc, tech && `▶ ${tech}`, dest && `▶ ${dest}`].filter(Boolean).join("  ");
    const body = el("div", {},
      sevBadge(pick(a, "Severity", "severity")),
      el("strong", { text: " " + (pick(a, "RuleID", "rule_id") || "") + " " }),
      el("span", { text: pick(a, "RuleName", "rule_name") || "" }),
      el("div", { class: "chain", text: chain }),
    );
    if (pick(a, "IsIncident", "is_incident")) {
      const btn = el("button", { class: "btn ghost", text: "Triage" });
      btn.addEventListener("click", () => renderTriageInto("#triage", pick(a, "ID", "id")));
      body.append(btn);
    }
    return el("div", { class: "node" }, el("div", { class: "ts", text: fmtTime(pick(a, "Time", "time")) }), body);
  }));
}

// ---- detections ----------------------------------------------------------
let allRules = [];
async function renderDetections() {
  let data;
  try { data = await getJSON("/api/rules"); } catch (_) { return; }
  allRules = data.rules || [];
  $("#rules-meta").textContent = `version ${data.version} · ${allRules.length} rules`;
  const tactics = {};
  for (const r of allRules) {
    const t = (r.technique && r.technique.tactic) || "uncategorized";
    tactics[t] = (tactics[t] || 0) + 1;
  }
  $("#coverage").replaceChildren(...Object.entries(tactics).sort().map(([t, n]) => tile(n, t)));
  drawRules();
}
function drawRules() {
  const q = ($("#r-filter").value || "").toLowerCase();
  const rows = allRules.filter((r) =>
    !q || (r.id + " " + r.name + " " + ((r.technique && r.technique.id) || "")).toLowerCase().includes(q));
  $("#rules-body").replaceChildren(...rows.map((r) => el("tr", {},
    el("td", { class: "mono", text: r.id }),
    el("td", { class: "wrap", text: r.name }),
    el("td", {}, sevBadge(r.severity)),
    el("td", { class: "tech", text: (r.technique && r.technique.id) || "—" }),
    el("td", { text: (r.technique && r.technique.tactic) || "—" }),
    el("td", { class: "mono", text: r.risk_score }),
    el("td", { text: r.enabled ? "✓" : "✗" }),
  )));
}

// ---- fleet ---------------------------------------------------------------
async function renderFleet() {
  let agents = [];
  try { agents = await getJSON("/api/agents"); } catch (_) { return; }
  const sum = (key) => agents.reduce((n, a) => n + (a[key] || 0), 0);
  $("#fleet-tiles").replaceChildren(
    tile(agents.length, "agents"),
    tile(agents.filter((a) => a.online).length, "online", true),
    tile(sum("events_processed").toLocaleString(), "events"),
    tile(sum("alerts").toLocaleString(), "alerts"),
  );
  $("#fleet-body").replaceChildren(...agents.map((a) => el("tr", {},
    el("td", { text: a.hostname || a.id }),
    el("td", { class: a.online ? "online" : "offline", text: a.online ? "● online" : "○ offline" }),
    el("td", { class: "mono", text: a.version || "—" }),
    el("td", { class: "mono", text: a.kernel || "—" }),
    el("td", { class: "mono", text: (a.events_processed || 0).toLocaleString() }),
    el("td", { class: "mono", text: a.alerts || 0 }),
    el("td", { class: "mono", text: a.incidents || 0 }),
    el("td", { class: "mono", text: a.rules_version || "—" }),
    el("td", { text: fmtTime(a.last_seen) }),
  )));
}

// ---- command palette -----------------------------------------------------
const commands = [
  { label: "Go to Overview", ic: "▦", run: () => navigate("overview") },
  { label: "Go to Alerts", ic: "⚑", run: () => navigate("alerts") },
  { label: "Go to Investigation", ic: "⌖", run: () => navigate("investigation") },
  { label: "Go to Detections", ic: "❡", run: () => navigate("detections") },
  { label: "Go to Fleet", ic: "▤", run: () => navigate("fleet") },
  { label: "Toggle theme", ic: "◐", run: toggleTheme },
  { label: "Refresh current view", ic: "↻", run: applyRoute },
];
let cmdkSel = 0;
function openCmdk() {
  $("#cmdk").classList.add("show");
  $("#cmdk-input").value = "";
  cmdkSel = 0;
  drawCmdk();
  $("#cmdk-input").focus();
}
function closeCmdk() { $("#cmdk").classList.remove("show"); }
function filteredCommands() {
  const q = $("#cmdk-input").value.toLowerCase();
  return commands.filter((c) => c.label.toLowerCase().includes(q));
}
function drawCmdk() {
  const items = filteredCommands();
  if (cmdkSel >= items.length) cmdkSel = Math.max(0, items.length - 1);
  $("#cmdk-list").replaceChildren(...items.map((c, i) => {
    const li = el("li", { class: i === cmdkSel ? "sel" : "" },
      el("span", { class: "ic", text: c.ic }), el("span", { text: c.label }));
    li.addEventListener("click", () => runCmdk(c));
    return li;
  }));
}
function runCmdk(c) { closeCmdk(); c.run(); }

// ---- theme ---------------------------------------------------------------
function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("argus-theme", next); } catch (_) {}
}

// ---- live stream ---------------------------------------------------------
function setConn(on) {
  const pill = $("#conn");
  pill.textContent = on ? "live" : "offline";
  pill.className = "pill " + (on ? "on" : "off");
}
function connectStream() {
  const src = new EventSource("/api/stream");
  src.addEventListener("open", () => setConn(true));
  src.addEventListener("error", () => setConn(false));
  src.addEventListener("alert", (ev) => {
    let a;
    try { a = JSON.parse(ev.data); } catch (_) { return; }
    if (currentRoute === "alerts" && liveAlertMatchesFilter(a)) {
      const row = alertRow(a);
      row.classList.add("flash");
      $("#alerts-body").prepend(row);
    }
    if (pick(a, "IsIncident", "is_incident")) {
      toast(`Incident: ${pick(a, "RuleName", "rule_name") || pick(a, "RuleID", "rule_id") || "alert"} on ${pick(a, "Hostname", "hostname") || "host"}`);
    }
  });
}

// ---- keyboard & wiring ---------------------------------------------------
function onKeydown(e) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    $("#cmdk").classList.contains("show") ? closeCmdk() : openCmdk();
    return;
  }
  if (e.key === "Escape") { closeCmdk(); closeDrawer(); return; }
  if (!$("#cmdk").classList.contains("show")) return;
  const items = filteredCommands();
  if (e.key === "ArrowDown") { e.preventDefault(); cmdkSel = (cmdkSel + 1) % items.length; drawCmdk(); }
  else if (e.key === "ArrowUp") { e.preventDefault(); cmdkSel = (cmdkSel - 1 + items.length) % items.length; drawCmdk(); }
  else if (e.key === "Enter") { e.preventDefault(); if (items[cmdkSel]) runCmdk(items[cmdkSel]); }
}

function wire() {
  document.querySelectorAll(".nav a").forEach((a) => a.addEventListener("click", () => navigate(a.dataset.route)));
  $("#f-apply").addEventListener("click", renderAlerts);
  $("#i-load").addEventListener("click", renderInvestigation);
  $("#r-filter").addEventListener("input", drawRules);
  $("#cmdk-open").addEventListener("click", openCmdk);
  $("#cmdk-input").addEventListener("input", drawCmdk);
  $("#theme-toggle").addEventListener("click", toggleTheme);
  $("#overlay").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", onKeydown);
  window.addEventListener("hashchange", applyRoute);
}

// ---- boot ----------------------------------------------------------------
async function boot() {
  try { document.documentElement.dataset.theme = localStorage.getItem("argus-theme") || "dark"; } catch (_) {}
  try { const v = await getJSON("/version"); $("#version").textContent = "v" + (v.version || "?"); } catch (_) {}
  wire();
  applyRoute();
  connectStream();
  setInterval(() => { if (currentRoute === "overview" || currentRoute === "fleet") applyRoute(); }, 10000);
}
boot();

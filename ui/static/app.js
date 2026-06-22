"use strict";

// The ARGUS console: dependency-free, no build step, no external CDN. It reads
// the admin HTTP API on the same origin and subscribes to the alert stream over
// Server-Sent Events. Screens whose backends do not exist yet (Automation, AI
// analyst) arrive with their phases; everything here is backed by real data.

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
  hunt: { title: "Hunt", render: renderHunt },
  investigation: { title: "Investigation", render: renderInvestigation },
  detections: { title: "Detections", render: renderDetections },
  automation: { title: "Automation", render: renderAutomation },
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

// ---- hunt (ARQL) ---------------------------------------------------------
async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${url}: ${res.status}`);
  return data;
}

let huntFieldsLoaded = false;
async function renderHunt() {
  if (huntFieldsLoaded) return;
  let schema;
  try { schema = await getJSON("/api/hunt/fields"); } catch (_) { return; }
  huntFieldsLoaded = true;
  const chip = (text, kind) => {
    const c = el("button", { class: "chip " + kind, text, type: "button" });
    c.addEventListener("click", () => insertAtCursor($("#q-input"), text + " "));
    return c;
  };
  $("#q-fields").replaceChildren(
    ...(schema.classes || []).map((c) => chip(c, "klass")),
    ...(schema.fields || []).map((f) => chip(f, "field")),
  );
}
function insertAtCursor(area, text) {
  const start = area.selectionStart ?? area.value.length;
  area.value = area.value.slice(0, start) + text + area.value.slice(area.selectionEnd ?? start);
  area.focus();
  area.selectionStart = area.selectionEnd = start + text.length;
}

const huntCols = [
  ["time", (r) => fmtTime(r.time)],
  ["action", (r) => r.action || "—"],
  ["host", (r) => r.host || "—"],
  ["pid", (r) => r.pid || "—"],
  ["process", (r) => r.process || "—"],
  ["parent", (r) => r.parent || "—"],
  ["destination", (r) => r.destination || r.domain || "—"],
  ["file", (r) => r.file || "—"],
];
function huntRowEl(r) {
  const row = el("tr", { class: "clickable" }, ...huntCols.map(([, get]) =>
    el("td", { class: "mono", text: String(get(r)) })));
  row.addEventListener("click", () => openHuntDrawer(r));
  return row;
}
function huntTable(rows) {
  return el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, ...huntCols.map(([h]) => el("th", { text: h })))),
    el("tbody", {}, ...rows.map(huntRowEl))));
}
async function runHunt() {
  const query = $("#q-input").value.trim();
  if (!query) return;
  const out = $("#hunt-results");
  out.replaceChildren(el("div", { class: "muted", text: "Running hunt…" }));
  let res;
  try { res = await postJSON("/api/hunt", { query }); }
  catch (e) { out.replaceChildren(el("div", { class: "empty", text: String(e.message || e) })); return; }
  $("#q-meta").textContent = `${res.count} hit(s) · ${res.elapsed_ms} ms`;
  if (res.sequences) {
    if (!res.sequences.length) { out.replaceChildren(el("div", { class: "empty", text: "No matching chains." })); return; }
    out.replaceChildren(...res.sequences.map((chain, i) =>
      el("div", { class: "chain-group" }, el("h2", { class: "section-title", text: `Chain ${i + 1}` }), huntTable(chain))));
    return;
  }
  const events = res.events || [];
  if (!events.length) { out.replaceChildren(el("div", { class: "empty", text: "No matching events." })); return; }
  out.replaceChildren(huntTable(events));
}
function openHuntDrawer(r) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of Object.entries(r)) {
    if (v === undefined || v === null || v === "" || v === 0) continue;
    dl.append(el("dt", { text: k }), el("dd", { class: "mono", text: String(v) }));
  }
  $("#drawer").replaceChildren(
    el("button", { class: "icon-btn close", "aria-label": "Close" }, document.createTextNode("✕")),
    el("h3", { text: "Event" }), dl);
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawer").classList.add("show");
  $("#overlay").classList.add("show");
}

// saveAsRule opens a small form in the drawer; on submit it asks the server to
// convert the current query into rule YAML (Phase 14 → 16) and shows it to copy.
function saveAsRule() {
  const query = $("#q-input").value.trim();
  if (!query) { toast("Write a query first."); return; }
  const field = (id, label, placeholder) => el("label", { class: "form-row" },
    el("span", { text: label }), el("input", { id, type: "text", placeholder: placeholder || "" }));
  const form = el("div", { class: "rule-form" },
    field("rf-id", "Rule ID", "R-0500"),
    field("rf-name", "Name", "Suspicious shell from web service"),
    field("rf-sev", "Severity", "high"),
    field("rf-tech", "Technique ID", "T1059"),
    field("rf-risk", "Risk score", "70"),
  );
  const gen = el("button", { class: "btn", text: "Generate rule" });
  const output = el("pre", { class: "draft", style: "display:none" });
  gen.addEventListener("click", async () => {
    try {
      const data = await postJSON("/api/hunt/to-rule", {
        query,
        id: $("#rf-id").value.trim(), name: $("#rf-name").value.trim(),
        severity: $("#rf-sev").value.trim() || "medium",
        risk_score: parseInt($("#rf-risk").value, 10) || 0,
        technique: { id: $("#rf-tech").value.trim() },
      });
      output.textContent = data.yaml;
      output.style.display = "block";
      toast("Rule generated · copy it into rules/ and reload");
    } catch (e) { toast(String(e.message || e)); }
  });
  $("#drawer").replaceChildren(
    el("button", { class: "icon-btn close", "aria-label": "Close" }, document.createTextNode("✕")),
    el("h3", { text: "Save hunt as rule" }),
    el("p", { class: "muted summary", text: query }),
    form, gen, output);
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawer").classList.add("show");
  $("#overlay").classList.add("show");
}

// ---- investigation: attack graph + timeline + cases ----------------------
async function renderInvestigation() {
  renderCases();
  const host = $("#i-host").value.trim();
  if (!host) return;
  await Promise.all([renderGraph(host), renderTimeline(host)]);
}

async function renderTimeline(host) {
  const tl = $("#timeline");
  let rows = [];
  try { rows = await getJSON("/api/alerts?limit=500&host=" + encodeURIComponent(host)); } catch (_) { return; }
  if (!rows.length) { tl.replaceChildren(el("div", { class: "empty", text: "No alerts for " + host })); return; }
  tl.replaceChildren(...rows.map((a) => {
    const tech = pick(a, "TechniqueID", "technique_id");
    const dest = pick(a, "DestinationIP", "destination_ip");
    const proc = pick(a, "ProcessName", "process_name") || "process";
    const chain = [proc, tech && `▶ ${tech}`, dest && `▶ ${dest}`].filter(Boolean).join("  ");
    const body = el("div", {},
      sevBadge(pick(a, "Severity", "severity")),
      el("strong", { text: " " + (pick(a, "RuleID", "rule_id") || "") + " " }),
      el("span", { text: pick(a, "RuleName", "rule_name") || "" }),
      el("div", { class: "chain", text: chain }),
    );
    if (pick(a, "IsIncident", "is_incident")) {
      const t = el("button", { class: "btn ghost", text: "Triage" });
      t.addEventListener("click", () => openAlertDrawer(a));
      body.append(t);
    }
    return el("div", { class: "node" }, el("div", { class: "ts", text: fmtTime(pick(a, "Time", "time")) }), body);
  }));
}

// ---- attack graph (SVG, dependency-free) ---------------------------------
const SVGNS = "http://www.w3.org/2000/svg";
const svg = (tag, attrs = {}, ...kids) => {
  const node = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
};
const graphColors = { process: "var(--accent)", file: "var(--sev-medium)", network: "var(--sev-low)" };

async function renderGraph(host) {
  const wrap = $("#graph");
  wrap.replaceChildren(el("div", { class: "muted", text: "Building graph…" }));
  let graph;
  try { graph = await getJSON("/api/investigate/graph?host=" + encodeURIComponent(host)); }
  catch (e) { wrap.replaceChildren(el("div", { class: "empty", text: String(e.message || e) })); return; }
  if (!graph.nodes || !graph.nodes.length) {
    wrap.replaceChildren(el("div", { class: "empty", text: "No events in the lake for " + host + ". Wire --event-store to the agent's lake." }));
    $("#graph-legend").replaceChildren();
    return;
  }
  drawGraph(wrap, graph);
  $("#graph-legend").replaceChildren(...Object.entries(graphColors).map(([kind, color]) =>
    el("span", { class: "legend-item" }, svgDot(color), el("span", { text: kind }))));
}
function svgDot(color) {
  const s = svg("svg", { width: 10, height: 10, class: "legend-dot" });
  s.append(svg("circle", { cx: 5, cy: 5, r: 5, fill: color }));
  return s;
}

// layerNodes assigns each node an x-layer: root processes at 0, spawned children
// one deeper than their parent, and file/network nodes one past the process that
// touched them — a left-to-right reading of how the attack unfolded.
function layerNodes(graph) {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const parent = new Map();
  for (const e of graph.edges) if (e.kind === "spawned") parent.set(e.target, e.source);
  const touch = new Map();
  for (const e of graph.edges) if (e.kind !== "spawned" && !touch.has(e.target)) touch.set(e.target, e.source);
  const layer = new Map();
  const depthOf = (id, seen) => {
    if (layer.has(id)) return layer.get(id);
    if (seen.has(id)) return 0; // cycle guard
    seen.add(id);
    const src = parent.get(id) ?? touch.get(id);
    const d = src && byId.has(src) ? depthOf(src, seen) + 1 : 0;
    layer.set(id, d);
    return d;
  };
  for (const n of graph.nodes) depthOf(n.id, new Set());
  return layer;
}

function drawGraph(wrap, graph) {
  const layer = layerNodes(graph);
  const cols = new Map();
  for (const n of graph.nodes) {
    const depth = layer.get(n.id);
    if (!cols.has(depth)) cols.set(depth, []);
    cols.get(depth).push(n);
  }
  const NW = 150, NH = 40, GX = 70, GY = 18;
  const pos = new Map();
  let maxRow = 0;
  for (const [col, nodes] of cols) {
    nodes.forEach((n, row) => {
      pos.set(n.id, { x: col * (NW + GX) + 10, y: row * (NH + GY) + 10 });
      maxRow = Math.max(maxRow, row);
    });
  }
  const width = (Math.max(...cols.keys()) + 1) * (NW + GX) + 10;
  const height = (maxRow + 1) * (NH + GY) + 10;
  const s = svg("svg", { class: "graph-svg", viewBox: `0 0 ${width} ${height}`, width, height });
  s.append(svg("defs", {}, (() => {
    const m = svg("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto-start-reverse" });
    m.append(svg("path", { d: "M0,0 L10,5 L0,10 z", fill: "var(--border)" }));
    return m;
  })()));
  for (const e of graph.edges) {
    const a = pos.get(e.source), b = pos.get(e.target);
    if (!a || !b) continue;
    const x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2;
    const mx = (x1 + x2) / 2;
    s.append(svg("path", { d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`, class: "edge", "marker-end": "url(#arrow)" }));
    s.append(svg("text", { x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 4, class: "edge-label", "text-anchor": "middle" }, document.createTextNode(e.kind)));
  }
  for (const n of graph.nodes) {
    const p = pos.get(n.id);
    const g = svg("g", { class: "gnode", transform: `translate(${p.x},${p.y})`, tabindex: "0", role: "button" });
    const sev = n.alerting ? sevText(n.severity) : "";
    const rect = svg("rect", { width: NW, height: NH, rx: 8, class: "gnode-box" + (n.alerting ? " alerting" : ""),
      style: `stroke:${n.alerting ? `var(--sev-${sev})` : graphColors[n.kind] || "var(--border)"}` });
    g.append(rect);
    g.append(svg("circle", { cx: 12, cy: NH / 2, r: 4, fill: graphColors[n.kind] || "var(--muted)" }));
    const label = svg("text", { x: 24, y: NH / 2 - 2, class: "gnode-label" }, document.createTextNode(clip(n.label, 16)));
    g.append(label);
    const sub = svg("text", { x: 24, y: NH / 2 + 12, class: "gnode-sub" },
      document.createTextNode((n.techniques || []).join(" ") || n.kind));
    g.append(sub);
    g.addEventListener("click", () => openGraphNodeDrawer(n));
    s.append(g);
  }
  wrap.replaceChildren(s);
}
const clip = (text, n) => (text && text.length > n ? text.slice(0, n - 1) + "…" : text || "");
function openGraphNodeDrawer(n) {
  const dl = el("dl", { class: "kv" });
  const rows = [["Kind", n.kind], ["Label", n.label], ["PID", n.pid], ["Detail", n.detail],
    ["Severity", n.alerting ? sevText(n.severity) : ""], ["Techniques", (n.techniques || []).join(", ")]];
  for (const [k, v] of rows) if (v) dl.append(el("dt", { text: k }), el("dd", { class: "mono", text: String(v) }));
  $("#drawer").replaceChildren(
    el("button", { class: "icon-btn close", "aria-label": "Close" }, document.createTextNode("✕")),
    el("h3", { text: n.label || "Node" }), dl);
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawer").classList.add("show");
  $("#overlay").classList.add("show");
}

// ---- cases ---------------------------------------------------------------
async function renderCases() {
  let list = [];
  try { list = await getJSON("/api/cases"); } catch (_) { return; }
  const body = $("#cases-body");
  if (!list.length) { body.replaceChildren(el("tr", {}, el("td", { colspan: "7", class: "muted", text: "No cases yet." }))); return; }
  body.replaceChildren(...list.map((c) => {
    const row = el("tr", { class: "clickable" },
      el("td", { class: "mono", text: c.id }),
      el("td", { class: "wrap", text: c.title }),
      el("td", { text: c.status }),
      el("td", { text: c.assignee || "—" }),
      el("td", {}, sevBadge(c.severity)),
      el("td", { text: c.host || "—" }),
      el("td", { text: fmtTime(c.updated) }),
    );
    row.addEventListener("click", () => openCaseDrawer(c.id));
    return row;
  }));
}

function newCaseForm() {
  const host = $("#i-host").value.trim();
  const field = (id, label, value) => el("label", { class: "form-row" },
    el("span", { text: label }), el("input", { id, type: "text", value: value || "" }));
  const form = el("div", { class: "rule-form" },
    field("nc-title", "Title", host ? "Investigation on " + host : ""),
    field("nc-sev", "Severity", "high"),
    field("nc-host", "Host", host));
  const create = el("button", { class: "btn", text: "Create case" });
  create.addEventListener("click", async () => {
    try {
      const c = await postJSON("/api/cases", {
        title: $("#nc-title").value.trim(), severity: $("#nc-sev").value.trim(), host: $("#nc-host").value.trim(),
      });
      closeDrawer(); toast("Opened " + c.id); renderCases();
    } catch (e) { toast(String(e.message || e)); }
  });
  $("#drawer").replaceChildren(
    el("button", { class: "icon-btn close", "aria-label": "Close" }, document.createTextNode("✕")),
    el("h3", { text: "New case" }), form, create);
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawer").classList.add("show");
  $("#overlay").classList.add("show");
}

async function openCaseDrawer(id) {
  let c;
  try { c = await getJSON("/api/cases/" + encodeURIComponent(id)); } catch (_) { return; }
  const act = async (path, body, ok) => {
    try { await postJSON("/api/cases/" + id + path, body); toast(ok); openCaseDrawer(id); renderCases(); }
    catch (e) { toast(String(e.message || e)); }
  };
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of [["Status", c.status], ["Assignee", c.assignee], ["Severity", c.severity], ["Host", c.host], ["Evidence", (c.evidence || []).length + " alert(s)"]])
    if (v) dl.append(el("dt", { text: k }), el("dd", { class: "mono", text: String(v) }));

  const statusSel = el("select", {}, ...["open", "triage", "closed"].map((s) =>
    el("option", s === c.status ? { value: s, selected: "selected" } : { value: s }, document.createTextNode(s))));
  statusSel.addEventListener("change", () => act("/status", { status: statusSel.value }, "Status updated"));
  const assignIn = el("input", { type: "text", placeholder: "assignee", value: c.assignee || "" });
  const assignBtn = el("button", { class: "btn ghost", text: "Assign" });
  assignBtn.addEventListener("click", () => act("/assign", { assignee: assignIn.value.trim() }, "Assigned"));
  const commentIn = el("input", { type: "text", placeholder: "add a note" });
  const commentBtn = el("button", { class: "btn ghost", text: "Comment" });
  commentBtn.addEventListener("click", () => commentIn.value.trim() && act("/comments", { author: "analyst", body: commentIn.value.trim() }, "Note added"));
  const reportBtn = el("button", { class: "btn", text: "Generate report" });
  const reportOut = el("pre", { class: "draft", style: "display:none" });
  reportBtn.addEventListener("click", async () => {
    try { const r = await getJSON("/api/cases/" + id + "/report"); reportOut.textContent = r.report; reportOut.style.display = "block"; }
    catch (e) { toast(String(e.message || e)); }
  });
  const comments = el("div", { class: "case-notes" }, ...(c.comments || []).map((cm) =>
    el("div", { class: "note" }, el("span", { class: "muted mono", text: fmtTime(cm.time) + " " + cm.author + ": " }), el("span", { text: cm.body }))));

  $("#drawer").replaceChildren(
    el("button", { class: "icon-btn close", "aria-label": "Close" }, document.createTextNode("✕")),
    el("h3", { text: c.id + " · " + c.title }), dl,
    el("div", { class: "form-row" }, el("span", { text: "Status" }), statusSel),
    el("div", { class: "toolbar" }, assignIn, assignBtn),
    el("div", { class: "toolbar" }, commentIn, commentBtn),
    comments, reportBtn, reportOut);
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawer").classList.add("show");
  $("#overlay").classList.add("show");
}

// ---- automation (SOAR) ---------------------------------------------------
let soarEnabled = false;
async function renderAutomation() {
  try {
    const status = await getJSON("/api/soar/status");
    soarEnabled = !!status.enabled;
  } catch (_) {}
  const pill = $("#soar-status");
  pill.textContent = "engine: " + (soarEnabled ? "on" : "off");
  pill.className = "pill " + (soarEnabled ? "on" : "off");
  $("#soar-toggle").textContent = soarEnabled ? "Disable engine" : "Enable engine";

  let playbooks = [];
  try { playbooks = await getJSON("/api/playbooks"); } catch (_) {}
  const body = $("#pb-body");
  if (!playbooks.length) {
    body.replaceChildren(el("tr", {}, el("td", { colspan: "6", class: "muted", text: "No playbooks yet." })));
  } else {
    body.replaceChildren(...playbooks.map(playbookRow));
  }
  renderRuns();
}
function triggerText(t) {
  const parts = [];
  if (t.severities && t.severities.length) parts.push(t.severities.join("/"));
  if (t.techniques && t.techniques.length) parts.push(t.techniques.join(","));
  if (t.rule_ids && t.rule_ids.length) parts.push(t.rule_ids.join(","));
  if (t.min_risk) parts.push("risk≥" + t.min_risk);
  if (t.incidents_only) parts.push("incidents");
  return parts.join(" · ") || "any alert";
}
function playbookRow(p) {
  const modeClass = p.mode === "enforce" ? "sev-high" : p.mode === "dry-run" ? "sev-low" : "muted";
  const actions = el("td", {});
  const test = el("button", { class: "btn ghost sm", text: "Test" });
  test.addEventListener("click", () => testPlaybook(p.id));
  const edit = el("button", { class: "btn ghost sm", text: "Edit" });
  edit.addEventListener("click", () => playbookForm(p));
  const del = el("button", { class: "btn ghost sm", text: "✕" });
  del.addEventListener("click", () => deletePlaybook(p.id));
  actions.append(test, edit, del);
  return el("tr", {},
    el("td", { class: "mono", text: p.id }),
    el("td", { class: "wrap", text: p.name }),
    el("td", {}, el("span", { class: modeClass, text: p.mode })),
    el("td", { class: "muted", text: triggerText(p.trigger || {}) }),
    el("td", { class: "mono", text: (p.steps || []).map((s) => s.type).join(", ") }),
    actions);
}
async function toggleSOAR() {
  try { await postJSON("/api/soar/enable", { enabled: !soarEnabled }); renderAutomation(); }
  catch (e) { toast(String(e.message || e)); }
}
async function testPlaybook(id) {
  try {
    const run = await postJSON("/api/playbooks/" + id + "/test", {});
    const lines = (run.outcomes || []).map((o) => (o.executed ? "✓ " : "○ ") + o.detail).join("\n");
    openTextDrawer("Test run · " + run.mode, lines || "No outcomes (no alert matched).");
    renderRuns();
  } catch (e) { toast(String(e.message || e)); }
}
async function deletePlaybook(id) {
  try { await fetch("/api/playbooks/" + id, { method: "DELETE" }); renderAutomation(); }
  catch (e) { toast(String(e.message || e)); }
}
async function renderRuns() {
  let runs = [];
  try { runs = await getJSON("/api/soar/runs"); } catch (_) {}
  const wrap = $("#soar-runs");
  if (!runs.length) { wrap.replaceChildren(el("div", { class: "empty", text: "No playbook runs yet." })); return; }
  wrap.replaceChildren(...runs.map((run) => el("div", { class: "card run" },
    el("div", {}, el("strong", { text: run.playbook + " " }), el("span", { class: "muted", text: run.mode + " · " + fmtTime(run.time) })),
    el("ul", { class: "steps" }, ...(run.outcomes || []).map((o) =>
      el("li", { class: o.executed ? "" : "muted", text: (o.executed ? "✓ " : "○ ") + o.detail + (o.error ? " — " + o.error : "") })))
  )));
}

const STEP_TYPES = ["notify", "open_case", "run_hunt", "kill_process", "quarantine"];
function playbookForm(existing) {
  const steps = existing ? existing.steps.map((s) => ({ ...s })) : [];
  const field = (id, label, value) => el("label", { class: "form-row" },
    el("span", { text: label }), el("input", { id, type: "text", value: value || "" }));
  const modeSel = el("select", { id: "pb-mode" }, ...["off", "dry-run", "enforce"].map((m) =>
    el("option", existing && existing.mode === m ? { value: m, selected: "selected" } : { value: m }, document.createTextNode(m))));
  const stepList = el("div", { class: "chips", id: "pb-steps" });
  const drawStepChips = () => stepList.replaceChildren(...steps.map((s, i) => {
    const chip = el("span", { class: "chip klass" }, document.createTextNode(s.type + (s.query ? " (" + s.query + ")" : "") + " "));
    const x = el("button", { class: "chip-x", type: "button", text: "✕" });
    x.addEventListener("click", () => { steps.splice(i, 1); drawStepChips(); });
    chip.append(x);
    return chip;
  }));
  drawStepChips();
  const addSel = el("select", { id: "pb-addstep" }, ...STEP_TYPES.map((t) => el("option", { value: t }, document.createTextNode(t))));
  const addBtn = el("button", { class: "btn ghost", text: "+ step" });
  addBtn.addEventListener("click", () => {
    const type = addSel.value;
    const step = { type };
    if (type === "run_hunt") { step.query = prompt("ARQL query for this hunt step:") || ""; if (!step.query) return; }
    steps.push(step); drawStepChips();
  });
  const save = el("button", { class: "btn", text: existing ? "Save playbook" : "Create playbook" });
  save.addEventListener("click", async () => {
    const payload = {
      name: $("#pb-name").value.trim(),
      mode: $("#pb-mode").value,
      trigger: {
        severities: splitList($("#pb-sev").value),
        techniques: splitList($("#pb-tech").value),
        min_risk: parseInt($("#pb-risk").value, 10) || 0,
      },
      steps,
    };
    try {
      if (existing) await fetchJSON("PUT", "/api/playbooks/" + existing.id, payload);
      else await postJSON("/api/playbooks", payload);
      closeDrawer(); renderAutomation();
    } catch (e) { toast(String(e.message || e)); }
  });
  $("#drawer").replaceChildren(
    el("button", { class: "icon-btn close", "aria-label": "Close" }, document.createTextNode("✕")),
    el("h3", { text: existing ? "Edit playbook" : "New playbook" }),
    field("pb-name", "Name", existing && existing.name),
    el("div", { class: "form-row" }, el("span", { text: "Mode" }), modeSel),
    field("pb-sev", "Trigger severities (comma)", existing && (existing.trigger.severities || []).join(",")),
    field("pb-tech", "Trigger techniques (comma)", existing && (existing.trigger.techniques || []).join(",")),
    field("pb-risk", "Min risk", existing && existing.trigger.min_risk),
    el("div", { class: "form-row" }, el("span", { text: "Steps" }), stepList, el("div", { class: "toolbar" }, addSel, addBtn)),
    save);
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawer").classList.add("show");
  $("#overlay").classList.add("show");
}
const splitList = (s) => (s || "").split(",").map((x) => x.trim()).filter(Boolean);
async function fetchJSON(method, url, body) {
  const res = await fetch(url, { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `${url}: ${res.status}`);
  return data;
}
function openTextDrawer(title, text) {
  $("#drawer").replaceChildren(
    el("button", { class: "icon-btn close", "aria-label": "Close" }, document.createTextNode("✕")),
    el("h3", { text: title }), el("pre", { class: "draft", text }));
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawer").classList.add("show");
  $("#overlay").classList.add("show");
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
  drawMatrix();
  drawRules();
}

// drawMatrix renders an ATT&CK-Navigator-style coverage grid: one column per
// tactic (in kill-chain order), each technique a cell shaded by how many rules
// cover it. It is the in-console companion to the downloadable Navigator layer.
const tacticOrder = ["initial-access", "execution", "persistence", "privilege-escalation",
  "defense-evasion", "credential-access", "discovery", "lateral-movement", "collection",
  "command-and-control", "exfiltration", "impact"];
function drawMatrix() {
  const byTactic = {};
  for (const r of allRules) {
    const tactic = (r.technique && r.technique.tactic) || "uncategorized";
    const id = (r.technique && r.technique.id) || "—";
    (byTactic[tactic] = byTactic[tactic] || {});
    (byTactic[tactic][id] = byTactic[tactic][id] || { count: 0, name: (r.technique && r.technique.name) || "" }).count++;
  }
  const tactics = Object.keys(byTactic).sort((a, b) => {
    const ia = tacticOrder.indexOf(a), ib = tacticOrder.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });
  const maxCount = Math.max(1, ...Object.values(byTactic).flatMap((t) => Object.values(t).map((x) => x.count)));
  $("#matrix").replaceChildren(...tactics.map((tactic) => {
    const techs = Object.entries(byTactic[tactic]).sort();
    const cells = techs.map(([id, info]) => {
      const intensity = 0.25 + 0.75 * (info.count / maxCount);
      const cell = el("div", { class: "mx-cell", title: `${id} ${info.name} · ${info.count} rule(s)`,
        style: `background: color-mix(in srgb, var(--accent) ${Math.round(intensity * 100)}%, var(--surface))` });
      cell.append(el("span", { class: "mx-id", text: id }), el("span", { class: "mx-n", text: String(info.count) }));
      return cell;
    });
    return el("div", { class: "mx-col" },
      el("div", { class: "mx-head", text: tactic.replace(/-/g, " ") }), ...cells);
  }));
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
  { label: "Go to Hunt", ic: "⌕", run: () => navigate("hunt") },
  { label: "Go to Investigation", ic: "⌖", run: () => navigate("investigation") },
  { label: "Go to Detections", ic: "❡", run: () => navigate("detections") },
  { label: "Go to Automation", ic: "⚙", run: () => navigate("automation") },
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
  $("#q-run").addEventListener("click", runHunt);
  $("#q-rule").addEventListener("click", saveAsRule);
  $("#q-input").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); runHunt(); }
  });
  $("#i-load").addEventListener("click", renderInvestigation);
  $("#i-newcase").addEventListener("click", newCaseForm);
  $("#soar-toggle").addEventListener("click", toggleSOAR);
  $("#pb-new").addEventListener("click", () => playbookForm(null));
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

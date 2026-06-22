"use strict";

// The ARGUS console: dependency-free. It reads the admin HTTP API on the same
// origin and subscribes to the alert stream over Server-Sent Events. No build
// step, no framework — just fetch, EventSource and DOM.

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const kid of kids) node.append(kid);
  return node;
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
const sevClass = (s) => "sev sev-" + String(s || "").toLowerCase();
const sevText = (s) => (typeof s === "number" ? ["", "low", "medium", "high", "critical"][s] || s : s);

// ---- tab routing ---------------------------------------------------------
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
    tab.classList.add("active");
    $("#" + tab.dataset.view).classList.add("active");
    if (tab.dataset.view === "rules") loadRules();
  });
});

// ---- fleet ---------------------------------------------------------------
async function loadFleet() {
  let agents = [];
  try { agents = await getJSON("/api/agents"); } catch (e) { return; }
  const online = agents.filter((a) => a.online).length;
  const events = agents.reduce((n, a) => n + (a.events_processed || 0), 0);
  const alerts = agents.reduce((n, a) => n + (a.alerts || 0), 0);
  const incidents = agents.reduce((n, a) => n + (a.incidents || 0), 0);

  const cards = $("#fleet-cards");
  cards.replaceChildren(
    card(agents.length, "agents"),
    card(online, "online"),
    card(events.toLocaleString(), "events"),
    card(alerts.toLocaleString(), "alerts"),
    card(incidents.toLocaleString(), "incidents"),
  );

  const body = $("#agents tbody");
  body.replaceChildren(...agents.map((a) =>
    el("tr", {},
      el("td", { text: a.hostname || a.id }),
      el("td", { class: a.online ? "dot-online" : "dot-offline", text: a.online ? "● online" : "○ offline" }),
      el("td", { text: a.version || "—" }),
      el("td", { text: a.kernel || "—" }),
      el("td", { text: (a.events_processed || 0).toLocaleString() }),
      el("td", { text: a.alerts || 0 }),
      el("td", { text: a.incidents || 0 }),
      el("td", { text: a.rules_version || "—" }),
      el("td", { text: fmtTime(a.last_seen) }),
    )));
}
const card = (n, l) => el("div", { class: "card" }, el("div", { class: "n", text: String(n) }), el("div", { class: "l", text: l }));

// ---- alerts (history + live) --------------------------------------------
function alertRow(a) {
  return el("tr", {},
    el("td", { text: fmtTime(a.Time || a.time) }),
    el("td", { class: sevClass(a.Severity || a.severity), text: sevText(a.Severity || a.severity) || "—" }),
    el("td", { text: a.RuleID || a.rule_id || "—" }),
    el("td", { text: a.TechniqueID || a.technique_id || "—" }),
    el("td", { text: a.Hostname || a.hostname || "—" }),
    el("td", { text: a.PID || a.pid || "—" }),
    el("td", { text: a.ProcessName || a.process_name || "—" }),
    el("td", { text: a.DestinationIP || a.destination_ip || "—" }),
    el("td", { text: a.RiskScore || a.risk_score || 0 }),
  );
}

async function loadAlerts() {
  const params = new URLSearchParams();
  const host = $("#f-host").value.trim();
  const sev = $("#f-sev").value;
  const tech = $("#f-tech").value.trim();
  if (host) params.set("host", host);
  if (sev) params.set("severity", sev);
  if (tech) params.set("technique", tech);
  if ($("#f-inc").checked) params.set("incidents", "true");
  params.set("limit", "200");
  let rows = [];
  try { rows = await getJSON("/api/alerts?" + params.toString()); } catch (e) { return; }
  $("#alerts-count").textContent = `${rows.length} alert(s)`;
  $("#alerts-table tbody").replaceChildren(...rows.map(alertRow));
}
$("#f-apply").addEventListener("click", loadAlerts);

function prependLiveAlert(a) {
  // Only show the live alert if it passes the active filter inputs.
  const host = $("#f-host").value.trim();
  const sev = $("#f-sev").value;
  const tech = $("#f-tech").value.trim();
  if (host && (a.Hostname || a.hostname) !== host) return;
  if (sev && String(a.Severity || a.severity).toLowerCase() !== sev) return;
  if (tech && (a.TechniqueID || a.technique_id) !== tech) return;
  if ($("#f-inc").checked && !(a.IsIncident || a.is_incident)) return;
  const row = alertRow(a);
  row.classList.add("flash");
  $("#alerts-table tbody").prepend(row);
}

// ---- incident timeline ---------------------------------------------------
async function loadTimeline() {
  const host = $("#i-host").value.trim();
  const tl = $("#timeline");
  if (!host) { tl.replaceChildren(el("div", { class: "empty", text: "Enter a host to reconstruct its alert chain." })); return; }
  let rows = [];
  try { rows = await getJSON("/api/alerts?limit=500&host=" + encodeURIComponent(host)); } catch (e) { return; }
  if (!rows.length) { tl.replaceChildren(el("div", { class: "empty", text: "No alerts for " + host })); return; }
  $("#triage").replaceChildren();
  tl.replaceChildren(...rows.map((a) => {
    const proc = a.ProcessExecutable || a.process_executable || a.ProcessName || a.process_name || "process";
    const tech = (a.TechniqueID || a.technique_id) ? `${a.TechniqueID || a.technique_id} ${a.TechniqueName || a.technique_name || ""}` : "";
    const dest = a.DestinationIP || a.destination_ip;
    const chain = [proc, tech && `▶ ${tech}`, dest && `▶ ${dest}`].filter(Boolean).join("  ");
    const body = el("div", { class: "body" },
      el("span", { class: sevClass(a.Severity || a.severity), text: (sevText(a.Severity || a.severity) || "") + "  " }),
      el("strong", { text: (a.RuleID || a.rule_id || "") + "  " }),
      el("span", { text: a.RuleName || a.rule_name || "" }),
      el("div", { class: "chain", text: chain }),
    );
    if (a.IsIncident || a.is_incident) {
      const btn = el("button", { class: "triage-btn", text: "Triage" });
      btn.addEventListener("click", () => renderTriage(a.ID || a.id));
      body.append(btn);
    }
    return el("div", { class: "node" }, el("div", { class: "ts", text: fmtTime(a.Time || a.time) }), body);
  }));
}

// renderTriage asks the control plane for an incident's triage report (offline
// template by default, Claude when the operator enabled it) and renders it below
// the timeline.
async function renderTriage(id) {
  const panel = $("#triage");
  panel.replaceChildren(el("div", { class: "muted", text: "Running triage…" }));
  let r;
  try { r = await getJSON("/api/alerts/" + encodeURIComponent(id) + "/triage"); }
  catch (e) { panel.replaceChildren(el("div", { class: "empty", text: "Triage unavailable." })); return; }
  const kids = [
    el("h3", {},
      el("span", { text: "Triage  " }),
      el("span", { class: sevClass(r.severity), text: sevText(r.severity) || "" }),
      el("span", { class: "src", text: "  · " + (r.source || "") })),
    el("p", { class: "summary", text: r.summary || "" }),
    el("ul", { class: "steps" }, ...(r.containment || []).map((s) => el("li", { text: s }))),
  ];
  if (r.rule_draft) kids.push(el("pre", { class: "draft", text: r.rule_draft }));
  panel.replaceChildren(...kids);
}
$("#i-load").addEventListener("click", loadTimeline);

// ---- rule catalogue ------------------------------------------------------
async function loadRules() {
  let data;
  try { data = await getJSON("/api/rules"); } catch (e) { return; }
  $("#rules-meta").textContent = `version ${data.version} · ${data.rules.length} rules`;
  $("#rules-table tbody").replaceChildren(...data.rules.map((r) =>
    el("tr", {},
      el("td", { text: r.id }),
      el("td", { class: "wrap", text: r.name }),
      el("td", { class: sevClass(r.severity), text: r.severity }),
      el("td", { text: (r.technique && r.technique.id) || "—" }),
      el("td", { text: (r.technique && r.technique.tactic) || "—" }),
      el("td", { text: r.risk_score }),
      el("td", { text: r.enabled ? "✓" : "✗" }),
    )));
}

// ---- live stream ---------------------------------------------------------
function connectStream() {
  const src = new EventSource("/api/stream");
  src.addEventListener("open", () => setConn(true));
  src.addEventListener("error", () => setConn(false));
  src.addEventListener("alert", (ev) => {
    try {
      const a = JSON.parse(ev.data);
      prependLiveAlert(a);
      loadFleet();
    } catch (_) {}
  });
}
function setConn(on) {
  const pill = $("#conn");
  pill.textContent = on ? "live: connected" : "live: offline";
  pill.className = "pill " + (on ? "pill-on" : "pill-off");
}

// ---- boot ----------------------------------------------------------------
async function boot() {
  try { const v = await getJSON("/version"); $("#version").textContent = "v" + (v.version || "?"); } catch (_) {}
  loadFleet();
  loadAlerts();
  connectStream();
  setInterval(loadFleet, 10000);
}
boot();

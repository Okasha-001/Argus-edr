package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/argus-edr/argus/internal/eventstore"
	"github.com/argus-edr/argus/internal/fleet"
	"github.com/argus-edr/argus/internal/fleet/fleetpb"
	"github.com/argus-edr/argus/internal/triage"
	"github.com/argus-edr/argus/internal/version"
	"github.com/argus-edr/argus/server/cases"
	"github.com/argus-edr/argus/server/correlate"
	"github.com/argus-edr/argus/server/ruleset"
	"github.com/argus-edr/argus/server/soar"
	"github.com/argus-edr/argus/server/store"
)

// triageHostAlerts bounds how many of a host's recent alerts feed an incident's
// triage context, so a noisy host cannot blow up the prompt or the template.
const triageHostAlerts = 50

const (
	maxRetainedSignals = 200
	defaultAlertLimit  = 100
)

// adminAPI exposes read-only fleet visibility and command queueing over JSON.
// It is meant to bind to localhost or sit behind an authenticating proxy. State-
// changing endpoints require a bearer token; when no token is configured they are
// refused outright, so the control plane can never expose an unauthenticated way
// to kill or quarantine hosts. Read-only endpoints stay open for local dashboards.
type adminAPI struct {
	store  store.Store
	rules  *ruleset.Provider
	ttl    time.Duration
	authz  *authz
	logger *slog.Logger

	// issuer mints rotated agent certificates. It is nil unless the server was
	// started with the CA key (--ca-key or --dev), in which case the rotate-cert
	// endpoint is disabled rather than minting from a CA it does not hold.
	issuer *fleet.CertIssuer

	// summarizer produces incident triage. It defaults to the offline template;
	// serve.go upgrades it to the Claude provider when explicitly enabled.
	summarizer triage.Summarizer

	// lake is the queryable event history the threat-hunting engine searches. It
	// is nil unless the operator configured an event store (--event-store), in
	// which case the hunt endpoints report that hunting is unavailable rather than
	// pretending an empty result.
	lake eventstore.Store

	// cases holds investigation cases. It is in-memory by default (single-binary
	// mode); the Store interface is ready for a durable backend.
	cases cases.Store

	// soar is the response-playbook engine. It is off by default (and every
	// playbook defaults to dry-run); serve.go enables it and wires notifications.
	soar *soar.Engine

	stream  *broadcaster
	metrics *serverMetrics
	audit   *auditLog

	mu      sync.Mutex
	signals []correlate.Signal
}

func newAdminAPI(backing store.Store, rules *ruleset.Provider, ttl time.Duration, rbac *authz, issuer *fleet.CertIssuer, lake eventstore.Store, logger *slog.Logger) *adminAPI {
	a := &adminAPI{
		store: backing, rules: rules, ttl: ttl, authz: rbac, issuer: issuer, lake: lake, logger: logger,
		summarizer: triage.New(triage.Config{}, logger), // template by default; serve.go may upgrade
		cases:      cases.NewMemory(),
		stream:     newBroadcaster(), metrics: newServerMetrics(backing),
		audit: newAuditLog(nil, nil, logger), // serve.go upgrades this to a signed, file-backed log
	}
	// The playbook engine reaches the rest of the platform through adapters so
	// server/soar stays decoupled from the concrete stores. It is off by default.
	a.soar = soar.NewEngine(soar.Deps{
		Store:     soar.NewPlaybookStore(),
		Cases:     caseOpener{a.cases},
		Commander: commander{a.store},
		Hunter:    lakeHunter{a.lake},
		Logger:    logger,
	})
	return a
}

// recordSignal is the OnSignal hook for the gRPC service: it keeps the most
// recent cross-host findings for the admin API to surface.
func (a *adminAPI) recordSignal(signal correlate.Signal) {
	a.metrics.signals.Inc()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signals = append(a.signals, signal)
	if len(a.signals) > maxRetainedSignals {
		a.signals = a.signals[len(a.signals)-maxRetainedSignals:]
	}
}

func (a *adminAPI) mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /version", a.handleVersion)
	mux.HandleFunc("GET /api/agents", a.handleAgents)
	mux.HandleFunc("GET /api/alerts", a.handleAlerts)
	mux.HandleFunc("GET /api/alerts/{id}", a.handleAlertByID)
	mux.HandleFunc("GET /api/alerts/{id}/triage", a.handleTriage)
	mux.HandleFunc("GET /api/signals", a.handleSignals)
	mux.HandleFunc("GET /api/rules", a.handleRules)
	mux.HandleFunc("GET /api/detections/navigator", a.handleNavigator)
	mux.HandleFunc("GET /api/stream", a.handleStream)
	// Threat hunting is read-only analysis over the event lake: it queries history,
	// it never changes fleet state, so it stays open like the other read endpoints.
	mux.HandleFunc("GET /api/hunt/fields", a.handleHuntFields)
	mux.HandleFunc("POST /api/hunt", a.handleHunt)
	mux.HandleFunc("POST /api/hunt/to-rule", a.handleHuntToRule)
	// Investigation reconstructs a host's attack graph from the lake (read-only).
	mux.HandleFunc("GET /api/investigate/graph", a.handleInvestigateGraph)
	// Case management is analyst workflow: it groups alerts into investigations and
	// never touches the fleet, so — like the read endpoints — it stays open in
	// single-binary mode. Every mutation is still written to the audit log.
	mux.HandleFunc("GET /api/cases", a.handleCases)
	mux.HandleFunc("POST /api/cases", a.handleCreateCase)
	mux.HandleFunc("GET /api/cases/{id}", a.handleCaseByID)
	mux.HandleFunc("POST /api/cases/{id}/assign", a.handleAssignCase)
	mux.HandleFunc("POST /api/cases/{id}/status", a.handleCaseStatus)
	mux.HandleFunc("POST /api/cases/{id}/comments", a.handleCaseComment)
	mux.HandleFunc("POST /api/cases/{id}/evidence", a.handleCaseEvidence)
	mux.HandleFunc("GET /api/cases/{id}/report", a.handleCaseReport)
	// SOAR playbooks. Mutations are audited; the engine is off by default, every
	// playbook defaults to dry-run, and host actions are still clamped by the
	// agent's response.mode — three independent gates before anything acts.
	mux.HandleFunc("GET /api/soar/status", a.handleSOARStatus)
	mux.HandleFunc("POST /api/soar/enable", a.handleSOAREnable)
	mux.HandleFunc("GET /api/soar/runs", a.handleSOARRuns)
	mux.HandleFunc("GET /api/playbooks", a.handlePlaybooks)
	mux.HandleFunc("POST /api/playbooks", a.handleCreatePlaybook)
	mux.HandleFunc("GET /api/playbooks/{id}", a.handlePlaybookByID)
	mux.HandleFunc("PUT /api/playbooks/{id}", a.handleUpdatePlaybook)
	mux.HandleFunc("DELETE /api/playbooks/{id}", a.handleDeletePlaybook)
	mux.HandleFunc("POST /api/playbooks/{id}/test", a.handleTestPlaybook)
	mux.Handle("GET /metrics", a.metrics.registry.Handler())
	// State-changing endpoints are authorized by role: enqueuing a command (which
	// reaches an agent as kill/quarantine/posture) needs an operator; reloading the
	// served ruleset, which affects the whole fleet, needs an admin.
	mux.HandleFunc("POST /api/agents/{id}/commands", a.requireRole(RoleOperator, a.handleEnqueueCommand))
	mux.HandleFunc("POST /api/agents/{id}/rotate-cert", a.requireRole(RoleAdmin, a.handleRotateCert))
	mux.HandleFunc("POST /api/rules/reload", a.requireRole(RoleAdmin, a.handleReloadRules))
	return mux
}

// requireRole guards a handler with bearer-token authorization at minRole or
// above. With no tokens configured the endpoint is refused (503), never silently
// open, so a misconfiguration cannot expose the fleet's kill switch. The caller's
// role is stashed on the request for the audit log.
func (a *adminAPI) requireRole(minRole Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authz.configured() {
			a.logger.Warn("admin command refused: no tokens configured", "path", r.URL.Path, "from", r.RemoteAddr)
			writeError(w, http.StatusServiceUnavailable, "no admin tokens configured (set --admin-token or --rbac-file)")
			return
		}
		role := RoleNone
		if presented, ok := bearerToken(r); ok {
			role = a.authz.role(presented)
		}
		if role == RoleNone {
			a.logger.Warn("admin command rejected: missing or invalid token", "path", r.URL.Path, "from", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		if role < minRole {
			a.logger.Warn("admin command rejected: insufficient role",
				"path", r.URL.Path, "from", r.RemoteAddr, "have", role, "need", minRole)
			writeError(w, http.StatusForbidden, "token lacks the required role")
			return
		}
		next(w, r.WithContext(withRole(r.Context(), role)))
	}
}

func bearerToken(r *http.Request) (string, bool) {
	return strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// handleReloadRules re-reads the rule directory and bumps the served version.
// Agents pick up the change on their next heartbeat via an UPDATE_RULES command.
// A reload that fails validation leaves the previous ruleset serving.
func (a *adminAPI) handleReloadRules(w http.ResponseWriter, r *http.Request) {
	if err := a.rules.Reload(); err != nil {
		writeError(w, http.StatusInternalServerError, "reload failed: "+err.Error())
		return
	}
	a.audit.record(roleFromContext(r.Context()).String(), "rules_reload", a.rules.Version(), r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded", "version": a.rules.Version()})
}

func (a *adminAPI) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (a *adminAPI) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version":    version.Version,
		"build_date": version.BuildDate,
	})
}

type agentView struct {
	ID              string    `json:"id"`
	Hostname        string    `json:"hostname"`
	Version         string    `json:"version"`
	Kernel          string    `json:"kernel"`
	Online          bool      `json:"online"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	EventsProcessed uint64    `json:"events_processed"`
	Alerts          uint64    `json:"alerts"`
	Incidents       uint64    `json:"incidents"`
	RulesVersion    string    `json:"rules_version"`
}

func (a *adminAPI) handleAgents(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	agents := a.store.List()
	views := make([]agentView, 0, len(agents))
	for _, agent := range agents {
		views = append(views, agentView{
			ID: agent.ID, Hostname: agent.Hostname, Version: agent.Version, Kernel: agent.Kernel,
			Online: agent.Online(now, a.ttl), FirstSeen: agent.FirstSeen, LastSeen: agent.LastSeen,
			EventsProcessed: agent.EventsProcessed, Alerts: agent.Alerts, Incidents: agent.Incidents,
			RulesVersion: agent.RulesVersion,
		})
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *adminAPI) handleAlerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.QueryAlerts(alertFilterFromQuery(r)))
}

// alertFilterFromQuery reads the optional host/severity/technique/since/until/
// incidents/limit query parameters into a store.AlertFilter. Missing parameters
// leave the corresponding field zero, which the filter treats as "match all".
func alertFilterFromQuery(r *http.Request) store.AlertFilter {
	query := r.URL.Query()
	filter := store.AlertFilter{
		Hostname:      query.Get("host"),
		Severity:      query.Get("severity"),
		TechniqueID:   query.Get("technique"),
		IncidentsOnly: query.Get("incidents") == "true",
		Limit:         defaultAlertLimit,
	}
	if raw := query.Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			filter.Limit = parsed
		}
	}
	if since, err := time.Parse(time.RFC3339, query.Get("since")); err == nil {
		filter.Since = since
	}
	if until, err := time.Parse(time.RFC3339, query.Get("until")); err == nil {
		filter.Until = until
	}
	return filter
}

func (a *adminAPI) handleAlertByID(w http.ResponseWriter, r *http.Request) {
	record, ok := a.store.AlertByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown alert")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

// handleTriage produces a triage report for one alert (typically an incident): a
// natural-language summary, severity, containment steps, and an optional rule
// draft. It reconstructs the incident's context from the host's recent alerts,
// then runs the configured summarizer — the offline template by default, or Claude
// when the operator enabled it. Read-only: it surfaces analysis, queues nothing.
func (a *adminAPI) handleTriage(w http.ResponseWriter, r *http.Request) {
	record, ok := a.store.AlertByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown alert")
		return
	}
	incident := a.buildTriageIncident(record)
	report, err := a.summarizer.Summarize(r.Context(), incident)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "triage failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// buildTriageIncident assembles the structured incident triage needs from one
// alert plus the host's recent alert history, deduping techniques so the kill
// chain reads cleanly. The ATT&CK tactic for each technique is read from the
// served ruleset itself, so containment advice stays in sync with the rules that
// fired rather than a hand-maintained table.
func (a *adminAPI) buildTriageIncident(record store.AlertRecord) triage.Incident {
	tactics := a.tacticIndex()
	history := a.store.QueryAlerts(store.AlertFilter{Hostname: record.Hostname, Limit: triageHostAlerts})
	incident := triage.Incident{
		ID: record.ID, Hostname: record.Hostname, ProcessName: record.ProcessName,
		PID: record.PID, RiskScore: record.RiskScore,
	}
	seenTechnique := map[string]bool{}
	for _, alert := range history {
		incident.Alerts = append(incident.Alerts, triage.Alert{
			RuleID: alert.RuleID, RuleName: alert.RuleName,
			Severity: alert.Severity, Technique: alert.TechniqueID,
		})
		if alert.TechniqueID != "" && !seenTechnique[alert.TechniqueID] {
			seenTechnique[alert.TechniqueID] = true
			incident.Techniques = append(incident.Techniques, triage.Technique{
				ID: alert.TechniqueID, Name: alert.TechniqueName, Tactic: tactics[alert.TechniqueID],
			})
		}
	}
	return incident
}

// tacticIndex maps each technique id in the served ruleset to its ATT&CK tactic.
// A catalogue error yields an empty index — triage degrades to generic containment
// rather than failing.
func (a *adminAPI) tacticIndex() map[string]string {
	catalogue, err := a.rules.Catalogue()
	if err != nil {
		a.logger.Warn("triage tactic index unavailable", "err", err)
		return nil
	}
	index := make(map[string]string, len(catalogue))
	for _, rule := range catalogue {
		if rule.Technique.ID != "" {
			index[rule.Technique.ID] = rule.Technique.Tactic
		}
	}
	return index
}

// handleRules serves the rule catalogue (id/name/severity/technique) the console
// displays, plus the served bundle version.
func (a *adminAPI) handleRules(w http.ResponseWriter, _ *http.Request) {
	catalogue, err := a.rules.Catalogue()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rule catalogue: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": a.rules.Version(), "rules": catalogue})
}

func (a *adminAPI) handleSignals(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	out := make([]correlate.Signal, len(a.signals))
	for i, signal := range a.signals {
		out[len(a.signals)-1-i] = signal // most recent first
	}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

type commandRequest struct {
	Kind     string `json:"kind"`
	Argument string `json:"argument"`
}

func (a *adminAPI) handleEnqueueCommand(w http.ResponseWriter, r *http.Request) {
	var req commandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if value, ok := fleetpb.Command_Kind_value[req.Kind]; !ok || value == 0 {
		writeError(w, http.StatusBadRequest, "unknown command kind (want UPDATE_RULES|SET_RESPONSE_MODE|KILL_PROCESS|QUARANTINE)")
		return
	}
	agentID := r.PathValue("id")
	if !a.store.EnqueueCommand(agentID, store.Command{Kind: req.Kind, Argument: req.Argument}) {
		writeError(w, http.StatusNotFound, "unknown agent")
		return
	}
	// Audit every queued command: these reach an agent as kill/quarantine/posture
	// changes, so who-asked-for-what must be on the tamper-evident record.
	a.audit.record(roleFromContext(r.Context()).String(), "enqueue_command",
		agentID, fmt.Sprintf("%s %s from %s", req.Kind, req.Argument, r.RemoteAddr))
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued", "agent": agentID, "kind": req.Kind})
}

type rotatedCert struct {
	Agent       string `json:"agent"`
	Fingerprint string `json:"fingerprint"`
	Cert        string `json:"cert"`
	Key         string `json:"key"`
}

// handleRotateCert mints a fresh client certificate for an agent and stages it as
// the agent's pending identity, returning the new keypair for the operator to
// deliver to the host. The agent keeps using its current certificate until it
// reconnects with the new one, which the server then promotes — so a rotation
// never locks an agent out. Minting needs the CA key; without it the endpoint is
// disabled. The new private key crosses the wire once, on the audited, token-
// gated, localhost admin API — the same trust boundary as gen-certs.
func (a *adminAPI) handleRotateCert(w http.ResponseWriter, r *http.Request) {
	if a.issuer == nil {
		writeError(w, http.StatusNotImplemented, "certificate rotation disabled: start the server with --ca-key (or --dev)")
		return
	}
	agentID := r.PathValue("id")
	agent, ok := a.store.Get(agentID)
	if !ok {
		writeError(w, http.StatusNotFound, "unknown agent")
		return
	}
	commonName := agent.Hostname
	if commonName == "" {
		commonName = agentID
	}
	pair, fingerprint, err := a.issuer.Issue(commonName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue certificate: "+err.Error())
		return
	}
	if !a.store.SetPendingCert(agentID, fingerprint) {
		writeError(w, http.StatusNotFound, "unknown agent")
		return
	}
	a.audit.record(roleFromContext(r.Context()).String(), "rotate_cert", agentID,
		fmt.Sprintf("fingerprint %s from %s", fingerprint, r.RemoteAddr))
	writeJSON(w, http.StatusOK, rotatedCert{
		Agent: agentID, Fingerprint: fingerprint,
		Cert: string(pair.Cert), Key: string(pair.Key),
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/argus-edr/argus/internal/fleet/fleetpb"
	"github.com/argus-edr/argus/internal/version"
	"github.com/argus-edr/argus/server/correlate"
	"github.com/argus-edr/argus/server/ruleset"
	"github.com/argus-edr/argus/server/store"
)

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

	stream  *broadcaster
	metrics *serverMetrics

	mu      sync.Mutex
	signals []correlate.Signal
}

func newAdminAPI(backing store.Store, rules *ruleset.Provider, ttl time.Duration, rbac *authz, logger *slog.Logger) *adminAPI {
	return &adminAPI{
		store: backing, rules: rules, ttl: ttl, authz: rbac, logger: logger,
		stream: newBroadcaster(), metrics: newServerMetrics(backing),
	}
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
	mux.HandleFunc("GET /api/signals", a.handleSignals)
	mux.HandleFunc("GET /api/rules", a.handleRules)
	mux.HandleFunc("GET /api/stream", a.handleStream)
	mux.Handle("GET /metrics", a.metrics.registry.Handler())
	// State-changing endpoints are authorized by role: enqueuing a command (which
	// reaches an agent as kill/quarantine/posture) needs an operator; reloading the
	// served ruleset, which affects the whole fleet, needs an admin.
	mux.HandleFunc("POST /api/agents/{id}/commands", a.requireRole(RoleOperator, a.handleEnqueueCommand))
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
	a.logger.Info("admin audit", "action", "rules_reload", "from", r.RemoteAddr, "version", a.rules.Version())
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
	// changes, so who-asked-for-what must be on the record.
	a.logger.Info("admin audit", "action", "enqueue_command",
		"from", r.RemoteAddr, "agent", agentID, "kind", req.Kind, "argument", req.Argument)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued", "agent": agentID, "kind": req.Kind})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

package main

import (
	"encoding/json"
	"net/http"
	"strconv"
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
// It is meant to bind to localhost or sit behind an authenticating proxy: unlike
// the gRPC plane it is not mutually authenticated, so it must not face agents
// or the internet directly.
type adminAPI struct {
	store store.Store
	rules *ruleset.Provider
	ttl   time.Duration

	mu      sync.Mutex
	signals []correlate.Signal
}

func newAdminAPI(backing store.Store, rules *ruleset.Provider, ttl time.Duration) *adminAPI {
	return &adminAPI{store: backing, rules: rules, ttl: ttl}
}

// recordSignal is the OnSignal hook for the gRPC service: it keeps the most
// recent cross-host findings for the admin API to surface.
func (a *adminAPI) recordSignal(signal correlate.Signal) {
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
	mux.HandleFunc("GET /api/signals", a.handleSignals)
	mux.HandleFunc("POST /api/agents/{id}/commands", a.handleEnqueueCommand)
	mux.HandleFunc("POST /api/rules/reload", a.handleReloadRules)
	return mux
}

// handleReloadRules re-reads the rule directory and bumps the served version.
// Agents pick up the change on their next heartbeat via an UPDATE_RULES command.
// A reload that fails validation leaves the previous ruleset serving.
func (a *adminAPI) handleReloadRules(w http.ResponseWriter, _ *http.Request) {
	if err := a.rules.Reload(); err != nil {
		writeError(w, http.StatusInternalServerError, "reload failed: "+err.Error())
		return
	}
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
	limit := defaultAlertLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	writeJSON(w, http.StatusOK, a.store.RecentAlerts(limit))
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

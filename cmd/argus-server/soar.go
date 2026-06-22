package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/argus-edr/argus/internal/eventstore"
	"github.com/argus-edr/argus/internal/hunt"
	"github.com/argus-edr/argus/server/cases"
	"github.com/argus-edr/argus/server/soar"
	"github.com/argus-edr/argus/server/store"
)

// Adapters connect the decoupled soar engine to the concrete platform stores, so
// server/soar depends on none of them directly.

type caseOpener struct{ store cases.Store }

func (c caseOpener) OpenCase(title, severity, host string, evidence []string) (string, error) {
	created, err := c.store.Create(cases.CreateInput{Title: title, Severity: severity, Host: host, Evidence: evidence})
	if err != nil {
		return "", err
	}
	return created.ID, nil
}

type commander struct{ store store.Store }

func (c commander) Enqueue(agentID, kind, argument string) bool {
	return c.store.EnqueueCommand(agentID, store.Command{Kind: kind, Argument: argument})
}

type lakeHunter struct{ lake eventstore.Store }

func (h lakeHunter) Hunt(ctx context.Context, query string) (int, error) {
	if h.lake == nil {
		return 0, fmt.Errorf("event lake not configured")
	}
	compiled, err := hunt.Compile(query)
	if err != nil {
		return 0, err
	}
	result, err := compiled.Run(ctx, h.lake)
	if err != nil {
		return 0, err
	}
	return result.Count(), nil
}

// toSoarAlert projects a stored alert into the slice the engine reasons about.
func toSoarAlert(record store.AlertRecord) soar.AlertInfo {
	return soar.AlertInfo{
		AlertID: record.ID, AgentID: record.AgentID, Hostname: record.Hostname,
		RuleID: record.RuleID, RuleName: record.RuleName, Severity: record.Severity,
		TechniqueID: record.TechniqueID, PID: record.PID, DestinationIP: record.DestinationIP,
		RiskScore: record.RiskScore, IsIncident: record.IsIncident,
	}
}

func (a *adminAPI) handleSOARStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":   a.soar.Enabled(),
		"playbooks": len(a.soar.Store().List()),
	})
}

func (a *adminAPI) handleSOAREnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	a.soar.SetEnabled(req.Enabled)
	a.audit.record(r.RemoteAddr, "soar_enable", "engine", fmt.Sprintf("enabled=%t", req.Enabled))
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": req.Enabled})
}

func (a *adminAPI) handleSOARRuns(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.soar.Runs())
}

func (a *adminAPI) handlePlaybooks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.soar.Store().List())
}

func (a *adminAPI) handlePlaybookByID(w http.ResponseWriter, r *http.Request) {
	playbook, ok := a.soar.Store().Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown playbook")
		return
	}
	writeJSON(w, http.StatusOK, playbook)
}

func (a *adminAPI) handleCreatePlaybook(w http.ResponseWriter, r *http.Request) {
	var playbook soar.Playbook
	if err := json.NewDecoder(r.Body).Decode(&playbook); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	created, err := a.soar.Store().Create(playbook)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.audit.record(r.RemoteAddr, "playbook_create", created.ID, created.Name+" mode="+created.Mode)
	writeJSON(w, http.StatusCreated, created)
}

func (a *adminAPI) handleUpdatePlaybook(w http.ResponseWriter, r *http.Request) {
	var playbook soar.Playbook
	if err := json.NewDecoder(r.Body).Decode(&playbook); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	id := r.PathValue("id")
	updated, err := a.soar.Store().Update(id, playbook)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.audit.record(r.RemoteAddr, "playbook_update", id, updated.Name+" mode="+updated.Mode)
	writeJSON(w, http.StatusOK, updated)
}

func (a *adminAPI) handleDeletePlaybook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !a.soar.Store().Delete(id) {
		writeError(w, http.StatusNotFound, "unknown playbook")
		return
	}
	a.audit.record(r.RemoteAddr, "playbook_delete", id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}

// handleTestPlaybook rehearses a playbook in forced dry-run against a real alert —
// the alert id from the body, or the most recent alert if none is given — so an
// operator sees exactly what it would do before switching it to enforce.
func (a *adminAPI) handleTestPlaybook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AlertID string `json:"alert_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body is optional

	record, ok := a.resolveTestAlert(req.AlertID)
	if !ok {
		writeError(w, http.StatusBadRequest, "no alert to test against (record an alert first or pass alert_id)")
		return
	}
	run, err := a.soar.Test(r.Context(), r.PathValue("id"), toSoarAlert(record))
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (a *adminAPI) resolveTestAlert(alertID string) (store.AlertRecord, bool) {
	if alertID != "" {
		return a.store.AlertByID(alertID)
	}
	if recent := a.store.RecentAlerts(1); len(recent) > 0 {
		return recent[0], true
	}
	return store.AlertRecord{}, false
}

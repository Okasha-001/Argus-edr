package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/argus-edr/argus/internal/eventstore"
	"github.com/argus-edr/argus/internal/triage"
	"github.com/argus-edr/argus/server/cases"
	"github.com/argus-edr/argus/server/investigate"
	"github.com/argus-edr/argus/server/store"
)

// graphEventLimit bounds how many of a host's events feed one attack graph, so a
// busy host produces a readable picture, not an unbounded one.
const graphEventLimit = 2000

// graphAlertLimit bounds the alerts that annotate the graph with ATT&CK context.
const graphAlertLimit = 500

// handleInvestigateGraph reconstructs a host's attack graph from the event lake,
// annotated with the techniques its alerts fired. Read-only.
func (a *adminAPI) handleInvestigateGraph(w http.ResponseWriter, r *http.Request) {
	if a.lake == nil {
		writeError(w, http.StatusServiceUnavailable, "event lake not configured (start argus-server with --event-store)")
		return
	}
	host := r.URL.Query().Get("host")
	if host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}
	query := eventstore.Query{Host: host, Limit: graphEventLimit, Ascending: true}
	if since, err := time.Parse(time.RFC3339, r.URL.Query().Get("since")); err == nil {
		query.Since = since
	}
	events, err := a.lake.Query(r.Context(), query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query lake: "+err.Error())
		return
	}
	alerts := a.store.QueryAlerts(store.AlertFilter{Hostname: host, Limit: graphAlertLimit})
	annotations := make([]investigate.Annotation, 0, len(alerts))
	for _, alert := range alerts {
		annotations = append(annotations, investigate.Annotation{
			PID: alert.PID, TechniqueID: alert.TechniqueID, Severity: alert.Severity,
		})
	}
	writeJSON(w, http.StatusOK, investigate.Build(host, events, annotations))
}

func (a *adminAPI) handleCases(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.cases.List(cases.Filter{
		Status:   r.URL.Query().Get("status"),
		Assignee: r.URL.Query().Get("assignee"),
	}))
}

func (a *adminAPI) handleCaseByID(w http.ResponseWriter, r *http.Request) {
	record, ok := a.cases.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown case")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

type createCaseRequest struct {
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Host     string   `json:"host"`
	Tags     []string `json:"tags"`
	Evidence []string `json:"evidence"`
}

func (a *adminAPI) handleCreateCase(w http.ResponseWriter, r *http.Request) {
	var req createCaseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	created, err := a.cases.Create(cases.CreateInput{
		Title: req.Title, Severity: req.Severity, Host: req.Host, Tags: req.Tags, Evidence: req.Evidence,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.auditCase(r, "case_create", created.ID, created.Title)
	writeJSON(w, http.StatusCreated, created)
}

func (a *adminAPI) handleAssignCase(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Assignee string `json:"assignee"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	a.mutateCase(w, r, "case_assign", req.Assignee, func(id string) (cases.Case, error) {
		return a.cases.Assign(id, req.Assignee)
	})
}

func (a *adminAPI) handleCaseStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	a.mutateCase(w, r, "case_status", req.Status, func(id string) (cases.Case, error) {
		return a.cases.SetStatus(id, req.Status)
	})
}

func (a *adminAPI) handleCaseComment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Author string `json:"author"`
		Body   string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	a.mutateCase(w, r, "case_comment", req.Author, func(id string) (cases.Case, error) {
		return a.cases.AddComment(id, cases.Comment{Author: req.Author, Body: req.Body})
	})
}

func (a *adminAPI) handleCaseEvidence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AlertIDs []string `json:"alert_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	a.mutateCase(w, r, "case_evidence", fmt.Sprintf("%d alert(s)", len(req.AlertIDs)), func(id string) (cases.Case, error) {
		return a.cases.AddEvidence(id, req.AlertIDs...)
	})
}

// mutateCase runs a case mutation, maps a missing case to 404 and any other error
// to 400, audits the change, and returns the updated case. It is the one path
// every state change shares, so error handling and the audit trail are uniform.
func (a *adminAPI) mutateCase(w http.ResponseWriter, r *http.Request, action, detail string, apply func(id string) (cases.Case, error)) {
	id := r.PathValue("id")
	updated, err := apply(id)
	if err != nil {
		if err == cases.ErrNotFound {
			writeError(w, http.StatusNotFound, "unknown case")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a.auditCase(r, action, id, detail)
	writeJSON(w, http.StatusOK, updated)
}

func (a *adminAPI) auditCase(r *http.Request, action, id, detail string) {
	a.audit.record(r.RemoteAddr, action, id, detail)
}

// handleCaseReport renders a case as a Markdown report, reusing the triage
// summarizer for the narrative and resolving each piece of evidence to its alert.
func (a *adminAPI) handleCaseReport(w http.ResponseWriter, r *http.Request) {
	record, ok := a.cases.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown case")
		return
	}
	evidence, incident := a.resolveEvidence(record)
	report, err := a.summarizer.Summarize(r.Context(), incident)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report narrative failed: "+err.Error())
		return
	}
	markdown := cases.Report(cases.ReportInput{Case: record, Triage: report, Evidence: evidence})
	writeJSON(w, http.StatusOK, map[string]string{"report": markdown})
}

// resolveEvidence turns a case's evidence alert ids into report rows and a triage
// incident. Techniques are deduped and their ATT&CK tactic is read from the
// served ruleset, so the narrative matches the rules that actually fired.
func (a *adminAPI) resolveEvidence(record cases.Case) ([]cases.EvidenceRow, triage.Incident) {
	tactics := a.tacticIndex()
	incident := triage.Incident{ID: record.ID, Hostname: record.Host}
	var rows []cases.EvidenceRow
	seenTechnique := map[string]bool{}
	for _, alertID := range record.Evidence {
		alert, ok := a.store.AlertByID(alertID)
		if !ok {
			continue
		}
		rows = append(rows, cases.EvidenceRow{
			RuleID: alert.RuleID, RuleName: alert.RuleName, Severity: alert.Severity,
			Technique: alert.TechniqueID, Time: alert.Time,
		})
		incident.Alerts = append(incident.Alerts, triage.Alert{
			RuleID: alert.RuleID, RuleName: alert.RuleName, Severity: alert.Severity, Technique: alert.TechniqueID,
		})
		if incident.ProcessName == "" {
			incident.ProcessName, incident.PID = alert.ProcessName, alert.PID
		}
		if alert.RiskScore > incident.RiskScore {
			incident.RiskScore = alert.RiskScore
		}
		if alert.TechniqueID != "" && !seenTechnique[alert.TechniqueID] {
			seenTechnique[alert.TechniqueID] = true
			incident.Techniques = append(incident.Techniques, triage.Technique{
				ID: alert.TechniqueID, Name: alert.TechniqueName, Tactic: tactics[alert.TechniqueID],
			})
		}
	}
	return rows, incident
}

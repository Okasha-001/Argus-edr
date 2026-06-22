package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/argus-edr/argus/internal/hunt"
	"github.com/argus-edr/argus/internal/model"
)

// defaultHuntLimit bounds an interactive hunt's result set when the caller does
// not ask for fewer, so a broad query returns a screenful, not a lake.
const defaultHuntLimit = 200

// handleHuntFields lists the addressable fields and event classes a query can
// use, so the console can offer autocompletion without hard-coding the schema.
func (a *adminAPI) handleHuntFields(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"fields":  model.KnownFields(),
		"classes": hunt.Classes(),
	})
}

type huntRequest struct {
	Query string `json:"query"`
	Limit int    `json:"limit"`
}

type huntEventRow struct {
	Time        time.Time `json:"time"`
	Host        string    `json:"host,omitempty"`
	Action      string    `json:"action,omitempty"`
	PID         uint32    `json:"pid,omitempty"`
	Process     string    `json:"process,omitempty"`
	Executable  string    `json:"executable,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	Parent      string    `json:"parent,omitempty"`
	User        string    `json:"user,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Domain      string    `json:"domain,omitempty"`
	File        string    `json:"file,omitempty"`
}

type huntResponse struct {
	Query     string           `json:"query"`
	Count     int              `json:"count"`
	ElapsedMS int64            `json:"elapsed_ms"`
	Events    []huntEventRow   `json:"events,omitempty"`
	Sequences [][]huntEventRow `json:"sequences,omitempty"`
}

// handleHunt compiles and runs an ARQL query against the event lake. A query
// that fails to compile is a 400 with the parser's message (the analyst's typo);
// a run failure is a 500 (the lake's problem). With no lake configured it reports
// 503 rather than an empty result, so "no hits" never hides "not wired up".
func (a *adminAPI) handleHunt(w http.ResponseWriter, r *http.Request) {
	if a.lake == nil {
		writeError(w, http.StatusServiceUnavailable, "event lake not configured (start argus-server with --event-store)")
		return
	}
	var req huntRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	query, err := hunt.Compile(req.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "query error: "+err.Error())
		return
	}
	start := time.Now()
	result, err := query.Run(r.Context(), a.lake)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hunt failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, buildHuntResponse(req, result, time.Since(start)))
}

func buildHuntResponse(req huntRequest, result hunt.Result, elapsed time.Duration) huntResponse {
	resp := huntResponse{Query: req.Query, Count: result.Count(), ElapsedMS: elapsed.Milliseconds()}
	limit := req.Limit
	if limit <= 0 {
		limit = defaultHuntLimit
	}
	if result.Sequences != nil {
		for _, chain := range capChains(result.Sequences, limit) {
			resp.Sequences = append(resp.Sequences, huntRows(chain))
		}
		return resp
	}
	resp.Events = huntRows(capEvents(result.Events, limit))
	return resp
}

func capEvents(events []*model.Event, limit int) []*model.Event {
	if len(events) > limit {
		return events[:limit]
	}
	return events
}

func capChains(chains [][]*model.Event, limit int) [][]*model.Event {
	if len(chains) > limit {
		return chains[:limit]
	}
	return chains
}

func huntRows(events []*model.Event) []huntEventRow {
	rows := make([]huntEventRow, 0, len(events))
	for _, event := range events {
		rows = append(rows, huntRow(event))
	}
	return rows
}

// huntRow flattens an event into the compact projection the results table shows.
// It is deliberately a subset: the columns an analyst scans, not the whole event.
func huntRow(event *model.Event) huntEventRow {
	row := huntEventRow{
		Time: event.Timestamp, Host: event.Host, Action: event.Action,
		PID: event.Process.PID, Process: event.Process.Name,
		Executable: event.Process.Executable, CommandLine: event.Process.CommandLine,
		Parent: event.Process.ParentName, User: event.User.Name,
		Domain: event.Network.Domain, File: event.File.Path,
	}
	if event.Network.DstIP != "" {
		row.Destination = event.Network.DstIP
		if event.Network.DstPort != 0 {
			row.Destination += ":" + strconv.Itoa(int(event.Network.DstPort))
		}
	}
	return row
}

type huntToRuleRequest struct {
	Query       string `json:"query"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	RiskScore   int    `json:"risk_score"`
	Response    string `json:"response"`
	Technique   struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Tactic string `json:"tactic"`
	} `json:"technique"`
}

// handleHuntToRule turns a saved hunt into a detection rule and returns the YAML,
// closing the loop to Phase 16. It only generates content — it does not install
// the rule (that is an audited admin action: drop it in the rules dir and reload),
// so this endpoint stays read-only and open like the rest of hunting.
func (a *adminAPI) handleHuntToRule(w http.ResponseWriter, r *http.Request) {
	var req huntToRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	query, err := hunt.Compile(req.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, "query error: "+err.Error())
		return
	}
	yamlBytes, err := query.ToRule(hunt.RuleMeta{
		ID: req.ID, Name: req.Name, Description: req.Description,
		Severity: req.Severity, RiskScore: req.RiskScore, Response: req.Response,
		Technique: hunt.Technique{ID: req.Technique.ID, Name: req.Technique.Name, Tactic: req.Technique.Tactic},
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot convert hunt to rule: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"yaml": string(yamlBytes)})
}

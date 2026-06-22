package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/argus-edr/argus/server/cases"
	"github.com/argus-edr/argus/server/investigate"
	"github.com/argus-edr/argus/server/store"
)

func TestInvestigateGraphEndpoint(t *testing.T) {
	api := testAdminAPI(t, "")
	seedLake(t, api) // processes 100 (nginx) -> 200 (bash) -> connect 4444 on web-01
	api.store.RecordAlert(store.AlertRecord{
		RuleID: "R-0007", Hostname: "web-01", PID: 200, TechniqueID: "T1059", Severity: "critical",
		Time: time.Now(),
	})

	rec := httptest.NewRecorder()
	api.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/investigate/graph?host=web-01", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("graph = %d body=%s", rec.Code, rec.Body.String())
	}
	var graph investigate.Graph
	if err := json.Unmarshal(rec.Body.Bytes(), &graph); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if graph.Host != "web-01" || len(graph.Nodes) == 0 {
		t.Fatalf("graph = %+v", graph)
	}
	var found bool
	for _, node := range graph.Nodes {
		if node.ID == "proc:200" {
			found = true
			if !node.Alerting || len(node.Techniques) != 1 || node.Techniques[0] != "T1059" {
				t.Errorf("bash node should carry the T1059 alert: %+v", node)
			}
		}
	}
	if !found {
		t.Error("expected a process node for pid 200")
	}
}

func TestInvestigateGraphRequiresHost(t *testing.T) {
	api := testAdminAPI(t, "")
	rec := httptest.NewRecorder()
	api.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/investigate/graph", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing host = %d, want 400", rec.Code)
	}
}

func TestCaseEndpointsLifecycle(t *testing.T) {
	api := testAdminAPI(t, "")
	handler := api.mux()
	// An alert we will attach as evidence, so the report can resolve it.
	api.store.RecordAlert(store.AlertRecord{RuleID: "R-0007", Hostname: "web-01", Severity: "critical", TechniqueID: "T1059", Time: time.Now()})
	evidenceID := api.store.RecentAlerts(1)[0].ID

	created := postJSON(handler, "/api/cases", `{"title":"Reverse shell on web-01","severity":"high","host":"web-01"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create case = %d body=%s", created.Code, created.Body.String())
	}
	var c cases.Case
	if err := json.Unmarshal(created.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}

	steps := []struct {
		path, body string
	}{
		{"/api/cases/" + c.ID + "/assign", `{"assignee":"analyst-1"}`},
		{"/api/cases/" + c.ID + "/status", `{"status":"triage"}`},
		{"/api/cases/" + c.ID + "/comments", `{"author":"analyst-1","body":"working it"}`},
		{"/api/cases/" + c.ID + "/evidence", `{"alert_ids":["` + evidenceID + `"]}`},
	}
	for _, step := range steps {
		if rec := postJSON(handler, step.path, step.body); rec.Code != http.StatusOK {
			t.Fatalf("%s = %d body=%s", step.path, rec.Code, rec.Body.String())
		}
	}

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/cases?status=triage", nil))
	var listed []cases.Case
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Assignee != "analyst-1" {
		t.Errorf("list = %+v", listed)
	}

	report := httptest.NewRecorder()
	handler.ServeHTTP(report, httptest.NewRequest(http.MethodGet, "/api/cases/"+c.ID+"/report", nil))
	var out struct {
		Report string `json:"report"`
	}
	if err := json.Unmarshal(report.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Report, c.ID) || !strings.Contains(out.Report, "R-0007") {
		t.Errorf("report missing case id or evidence:\n%s", out.Report)
	}
}

func TestCaseStatusRejectsInvalid(t *testing.T) {
	api := testAdminAPI(t, "")
	handler := api.mux()
	created := postJSON(handler, "/api/cases", `{"title":"x"}`)
	var c cases.Case
	if err := json.Unmarshal(created.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if rec := postJSON(handler, "/api/cases/"+c.ID+"/status", `{"status":"frozen"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid status = %d, want 400", rec.Code)
	}
	if rec := postJSON(handler, "/api/cases/NOPE/status", `{"status":"closed"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown case = %d, want 404", rec.Code)
	}
}

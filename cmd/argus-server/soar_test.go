package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/argus-edr/argus/server/soar"
	"github.com/argus-edr/argus/server/store"
)

func TestPlaybookCreateDefaultsToDryRun(t *testing.T) {
	api := testAdminAPI(t, "")
	body := `{"name":"Contain reverse shell","trigger":{"severities":["critical"]},"steps":[{"type":"notify"},{"type":"open_case"}]}`
	rec := postJSON(api.mux(), "/api/playbooks", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create playbook = %d body=%s", rec.Code, rec.Body.String())
	}
	var pb soar.Playbook
	if err := json.Unmarshal(rec.Body.Bytes(), &pb); err != nil {
		t.Fatal(err)
	}
	if pb.ID == "" || pb.Mode != soar.ModeDryRun {
		t.Errorf("new playbook = %+v, want a dry-run default", pb)
	}
}

func TestPlaybookRejectsBadStep(t *testing.T) {
	api := testAdminAPI(t, "")
	rec := postJSON(api.mux(), "/api/playbooks", `{"name":"x","steps":[{"type":"detonate"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad step = %d, want 400", rec.Code)
	}
}

func TestPlaybookTestRunsInDryRun(t *testing.T) {
	api := testAdminAPI(t, "")
	handler := api.mux()
	api.store.RecordAlert(store.AlertRecord{
		RuleID: "R-0007", RuleName: "Reverse shell", Hostname: "web-01", Severity: "critical",
		PID: 4123, RiskScore: 90, IsIncident: true, Time: time.Now(),
	})

	created := postJSON(handler, "/api/playbooks",
		`{"name":"Contain","mode":"enforce","trigger":{"severities":["critical"]},"steps":[{"type":"notify"},{"type":"kill_process"}]}`)
	var pb soar.Playbook
	if err := json.Unmarshal(created.Body.Bytes(), &pb); err != nil {
		t.Fatal(err)
	}

	rec := postJSON(handler, "/api/playbooks/"+pb.ID+"/test", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("test = %d body=%s", rec.Code, rec.Body.String())
	}
	var run soar.RunRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.Mode != soar.ModeDryRun || len(run.Outcomes) != 2 {
		t.Fatalf("run = %+v, want forced dry-run with 2 outcomes", run)
	}
	for _, outcome := range run.Outcomes {
		if outcome.Executed {
			t.Errorf("a test run must not execute side effects: %+v", outcome)
		}
	}
}

func TestSOAREnableTogglesEngine(t *testing.T) {
	api := testAdminAPI(t, "")
	handler := api.mux()
	if rec := postJSON(handler, "/api/soar/enable", `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("enable = %d", rec.Code)
	}
	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/soar/status", nil))
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled {
		t.Error("engine should report enabled after POST /api/soar/enable")
	}
}

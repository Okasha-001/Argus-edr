package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

func seedLake(t *testing.T, api *adminAPI) {
	t.Helper()
	base := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	mk := func(action string, offset time.Duration, fn func(*model.Event)) *model.Event {
		e := &model.Event{Timestamp: base.Add(offset), Host: "web-01", Action: action}
		fn(e)
		e.Normalize()
		return e
	}
	events := []*model.Event{
		mk("exec", 0, func(e *model.Event) { e.Process = model.Process{PID: 100, Name: "nginx"} }),
		mk("exec", time.Minute, func(e *model.Event) {
			e.Process = model.Process{PID: 200, Name: "bash", ParentName: "nginx"}
		}),
		mk("connect", 2*time.Minute, func(e *model.Event) {
			e.Network = model.Network{DstIP: "203.0.113.9", DstPort: 4444}
		}),
	}
	if err := api.lake.Append(context.Background(), events...); err != nil {
		t.Fatalf("seed lake: %v", err)
	}
}

func postJSON(handler http.Handler, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

func TestHuntEndpointReturnsMatches(t *testing.T) {
	api := testAdminAPI(t, "")
	seedLake(t, api)

	rec := postJSON(api.mux(), "/api/hunt", `{"query":"exec where process.name == \"bash\""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/hunt = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp huntResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || len(resp.Events) != 1 || resp.Events[0].Process != "bash" {
		t.Errorf("hunt result = %+v", resp)
	}
}

func TestHuntEndpointRejectsBadQuery(t *testing.T) {
	api := testAdminAPI(t, "")
	rec := postJSON(api.mux(), "/api/hunt", `{"query":"exec where bogus.field == \"x\""}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad query = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestHuntEndpointUnavailableWithoutLake(t *testing.T) {
	api := testAdminAPI(t, "")
	api.lake = nil
	rec := postJSON(api.mux(), "/api/hunt", `{"query":"exec where process.name == \"bash\""}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no lake = %d, want 503", rec.Code)
	}
}

func TestHuntFieldsEndpoint(t *testing.T) {
	api := testAdminAPI(t, "")
	rec := httptest.NewRecorder()
	api.mux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/hunt/fields", nil))
	var body struct {
		Fields  []string `json:"fields"`
		Classes []string `json:"classes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !contains(body.Fields, "process.name") || !contains(body.Classes, "exec") {
		t.Errorf("fields=%v classes=%v", body.Fields, body.Classes)
	}
}

func TestHuntToRuleEndpoint(t *testing.T) {
	api := testAdminAPI(t, "")
	body := `{"query":"connect where destination.port == 4444","id":"R-HUNT-9","name":"C2 beacon","severity":"high"}`
	rec := postJSON(api.mux(), "/api/hunt/to-rule", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("to-rule = %d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.YAML, "R-HUNT-9") || !strings.Contains(out.YAML, "destination.port") {
		t.Errorf("generated rule missing expected content:\n%s", out.YAML)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

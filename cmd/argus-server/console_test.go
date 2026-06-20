package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/argus-edr/argus/server/store"
	"github.com/argus-edr/argus/ui"
)

func TestRuleCatalogue(t *testing.T) {
	rec := httptest.NewRecorder()
	testAdmin(t, "").ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/rules = %d", rec.Code)
	}
	var body struct {
		Version string             `json:"version"`
		Rules   []ruleCatalogueRow `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Version == "" || len(body.Rules) != 1 || body.Rules[0].ID != "R-T" {
		t.Errorf("catalogue = %+v", body)
	}
}

type ruleCatalogueRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func TestAlertByIDEndpoint(t *testing.T) {
	api := testAdminAPI(t, "")
	api.store.RecordAlert(store.AlertRecord{RuleID: "R-0001", Hostname: "web-01", Time: time.Unix(100, 0).UTC()})
	stored := api.store.RecentAlerts(1)
	handler := api.mux()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/alerts/"+stored[0].ID, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "R-0001") {
		t.Errorf("GET /api/alerts/{id} = %d body=%s", rec.Code, rec.Body.String())
	}

	miss := httptest.NewRecorder()
	handler.ServeHTTP(miss, httptest.NewRequest(http.MethodGet, "/api/alerts/nope", nil))
	if miss.Code != http.StatusNotFound {
		t.Errorf("unknown alert id = %d, want 404", miss.Code)
	}
}

func TestAlertFilterEndpoint(t *testing.T) {
	api := testAdminAPI(t, "")
	api.store.RecordAlert(store.AlertRecord{Severity: "high", Hostname: "web-01", Time: time.Unix(1, 0)})
	api.store.RecordAlert(store.AlertRecord{Severity: "low", Hostname: "web-02", Time: time.Unix(2, 0)})
	handler := api.mux()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/alerts?severity=high", nil))
	var rows []store.AlertRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Severity != "high" {
		t.Errorf("filtered alerts = %+v", rows)
	}
}

func TestConsoleServesUIAndDelegatesAPI(t *testing.T) {
	handler := consoleHandler(testAdmin(t, ""), ui.Assets())

	root := httptest.NewRecorder()
	handler.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusOK || !strings.Contains(root.Body.String(), "ARGUS") {
		t.Errorf("console root = %d, body should contain ARGUS", root.Code)
	}

	api := httptest.NewRecorder()
	handler.ServeHTTP(api, httptest.NewRequest(http.MethodGet, "/api/agents", nil))
	if api.Code != http.StatusOK {
		t.Errorf("console should delegate /api/agents, got %d", api.Code)
	}
}

func TestStreamDeliversLiveAlert(t *testing.T) {
	api := testAdminAPI(t, "")
	srv := httptest.NewServer(api.mux())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/stream")
	if err != nil {
		t.Fatalf("connect stream: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}

	reader := bufio.NewReader(resp.Body)
	// The handler subscribes before writing the preamble, so once we have read
	// it we are guaranteed to be a registered subscriber.
	readUntil(t, reader, ": connected")
	api.recordAlert(store.AlertRecord{ID: "a1", RuleID: "R-LIVE", Severity: "high"})
	if line := readUntil(t, reader, "R-LIVE"); !strings.HasPrefix(strings.TrimSpace(line), "data:") {
		t.Errorf("live alert not delivered as an SSE data line: %q", line)
	}
}

// readUntil reads lines until one contains want, failing the test on timeout.
func readUntil(t *testing.T, r *bufio.Reader, want string) string {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		type lineResult struct {
			line string
			err  error
		}
		ch := make(chan lineResult, 1)
		go func() {
			line, err := r.ReadString('\n')
			ch <- lineResult{line, err}
		}()
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
			return ""
		case got := <-ch:
			if got.err != nil {
				t.Fatalf("read stream: %v", got.err)
			}
			if strings.Contains(got.line, want) {
				return got.line
			}
		}
	}
}

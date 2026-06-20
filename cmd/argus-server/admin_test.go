package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/argus-edr/argus/server/ruleset"
	"github.com/argus-edr/argus/server/store"
)

func testAdmin(t *testing.T, token string) http.Handler {
	t.Helper()
	dir := t.TempDir()
	rule := "- id: R-T\n  severity: low\n  match: {field: event.action, op: eq, value: exec}\n"
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := ruleset.NewProvider(dir)
	if err != nil {
		t.Fatalf("ruleset: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newAdminAPI(store.NewMemory(), rules, time.Minute, token, logger).mux()
}

func postCommand(handler http.Handler, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/agents/x/commands",
		strings.NewReader(`{"kind":"KILL_PROCESS","argument":"123"}`))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAdminCommandRequiresValidToken(t *testing.T) {
	handler := testAdmin(t, "s3cret")
	cases := []struct {
		name, auth string
		want       int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"valid token passes auth", "Bearer s3cret", http.StatusNotFound}, // agent unknown, but auth cleared
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := postCommand(handler, tc.auth).Code; got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAdminCommandRefusedWhenNoTokenConfigured(t *testing.T) {
	// Secure default: with no admin token set, the kill/quarantine endpoint is
	// refused outright rather than silently open.
	if got := postCommand(testAdmin(t, ""), "Bearer anything").Code; got != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when no admin token configured", got)
	}
}

func TestAdminReadEndpointsStayOpen(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	rec := httptest.NewRecorder()
	testAdmin(t, "s3cret").ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/agents = %d, want 200 (reads stay open)", rec.Code)
	}
}

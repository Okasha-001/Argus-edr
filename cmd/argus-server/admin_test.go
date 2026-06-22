package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/fleet"
	"github.com/argus-edr/argus/internal/triage"
	"github.com/argus-edr/argus/server/ruleset"
	"github.com/argus-edr/argus/server/store"
)

func testAdminAPI(t *testing.T, token string) *adminAPI {
	t.Helper()
	dir := t.TempDir()
	rule := "- id: R-T\n  severity: low\n  match: {field: event.action, op: eq, value: exec}\n"
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := ruleset.NewProvider(dir, "")
	if err != nil {
		t.Fatalf("ruleset: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rbac, err := newAuthz(token, "")
	if err != nil {
		t.Fatalf("authz: %v", err)
	}
	return newAdminAPI(store.NewMemory(), rules, time.Minute, rbac, nil, logger)
}

func adminWithAuthz(t *testing.T, rbac *authz) http.Handler {
	t.Helper()
	api := testAdminAPI(t, "")
	api.authz = rbac
	return api.mux()
}

func testAdmin(t *testing.T, token string) http.Handler {
	t.Helper()
	return testAdminAPI(t, token).mux()
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

func TestAdminRBACRolesGateByEndpoint(t *testing.T) {
	rbac := &authz{grants: []grant{
		{token: "view", role: RoleViewer},
		{token: "op", role: RoleOperator},
		{token: "boss", role: RoleAdmin},
	}}
	handler := adminWithAuthz(t, rbac)

	postReload := func(auth string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/rules/reload", nil)
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	// Enqueue (needs operator): viewer forbidden, operator passes auth.
	if got := postCommand(handler, "Bearer view").Code; got != http.StatusForbidden {
		t.Errorf("viewer enqueue = %d, want 403", got)
	}
	if got := postCommand(handler, "Bearer op").Code; got != http.StatusNotFound {
		t.Errorf("operator enqueue = %d, want 404 (auth cleared, agent unknown)", got)
	}
	// Reload (needs admin): operator forbidden, admin passes.
	if got := postReload("Bearer op"); got != http.StatusForbidden {
		t.Errorf("operator reload = %d, want 403", got)
	}
	if got := postReload("Bearer boss"); got != http.StatusOK {
		t.Errorf("admin reload = %d, want 200", got)
	}
}

func issuerForTest(t *testing.T) *fleet.CertIssuer {
	t.Helper()
	certs, err := fleet.GenerateDevCerts("argus-server")
	if err != nil {
		t.Fatalf("dev certs: %v", err)
	}
	issuer, err := fleet.NewCertIssuer(certs.CA.Cert, certs.CA.Key)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return issuer
}

func rotateCert(handler http.Handler, agentID, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/agents/"+agentID+"/rotate-cert", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestRotateCertStagesPendingIdentity(t *testing.T) {
	api := testAdminAPI(t, "adm1n")
	api.issuer = issuerForTest(t)
	agent := api.store.Enroll("web-01", "1.0", "6.8.0", "fp-current")
	handler := api.mux()

	rec := rotateCert(handler, agent.ID, "Bearer adm1n")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate-cert = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var body rotatedCert
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Cert == "" || body.Key == "" || body.Fingerprint == "" {
		t.Fatalf("response should carry the new cert, key and fingerprint: %+v", body)
	}
	// The minted fingerprint must be staged as the agent's pending identity, with
	// its current identity untouched until the agent adopts the new cert.
	stored, _ := api.store.Get(agent.ID)
	if stored.PendingCertFingerprint != body.Fingerprint {
		t.Errorf("pending = %q, want the issued fingerprint %q", stored.PendingCertFingerprint, body.Fingerprint)
	}
	if stored.CertFingerprint != "fp-current" {
		t.Errorf("current identity should be unchanged, got %q", stored.CertFingerprint)
	}
}

func TestRotateCertDisabledWithoutIssuer(t *testing.T) {
	api := testAdminAPI(t, "adm1n") // no issuer configured
	agent := api.store.Enroll("web-01", "1.0", "6.8.0", "fp")
	if rec := rotateCert(api.mux(), agent.ID, "Bearer adm1n"); rec.Code != http.StatusNotImplemented {
		t.Errorf("rotate-cert without an issuer = %d, want 501", rec.Code)
	}
}

func TestRotateCertRequiresAdmin(t *testing.T) {
	api := testAdminAPI(t, "")
	api.authz = &authz{grants: []grant{{token: "op", role: RoleOperator}, {token: "boss", role: RoleAdmin}}}
	api.issuer = issuerForTest(t)
	agent := api.store.Enroll("web-01", "1.0", "6.8.0", "fp")
	handler := api.mux()

	if rec := rotateCert(handler, agent.ID, "Bearer op"); rec.Code != http.StatusForbidden {
		t.Errorf("operator rotate-cert = %d, want 403", rec.Code)
	}
	if rec := rotateCert(handler, agent.ID, "Bearer boss"); rec.Code != http.StatusOK {
		t.Errorf("admin rotate-cert = %d, want 200", rec.Code)
	}
}

func TestTriageEndpointReturnsTemplateReport(t *testing.T) {
	api := testAdminAPI(t, "") // default summarizer is the offline template
	api.store.RecordAlert(store.AlertRecord{
		ID: "INC-1", Hostname: "web-01", ProcessName: "kdevtmpfsi", PID: 4200,
		RiskScore: 90, TechniqueID: "T1036", IsIncident: true,
	})
	handler := api.mux()

	req := httptest.NewRequest(http.MethodGet, "/api/alerts/INC-1/triage", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("triage = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var report triage.Report
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Source != triage.ProviderTemplate {
		t.Errorf("source = %q, want template", report.Source)
	}
	if report.Severity != "critical" {
		t.Errorf("severity = %q, want critical for risk 90", report.Severity)
	}
	if !strings.Contains(report.Summary, "web-01") || len(report.Containment) == 0 {
		t.Errorf("incoherent report: %+v", report)
	}
}

func TestTriageEndpointUnknownAlert(t *testing.T) {
	handler := testAdminAPI(t, "").mux()
	req := httptest.NewRequest(http.MethodGet, "/api/alerts/nope/triage", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("triage of unknown alert = %d, want 404", rec.Code)
	}
}

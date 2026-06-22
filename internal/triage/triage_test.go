package triage

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// killChain mirrors the replay demo incident: a temp-dir exec that then beacons
// out — two techniques, risk 90.
func killChain() Incident {
	return Incident{
		ID:          "INC-web-01-1",
		Hostname:    "web-01",
		ProcessName: "kdevtmpfsi",
		PID:         4200,
		RiskScore:   90,
		Techniques: []Technique{
			{ID: "T1036", Name: "Masquerading", Tactic: "execution"},
			{ID: "T1571", Name: "Non-Standard Port", Tactic: "command-and-control"},
		},
		Alerts: []Alert{
			{RuleID: "R-0001", RuleName: "Execution from a temporary directory", Severity: "high", Technique: "T1036"},
			{RuleID: "R-0008", RuleName: "Outbound connection to a suspicious port", Severity: "high", Technique: "T1571"},
		},
	}
}

func TestTemplateSummaryIsCoherent(t *testing.T) {
	report, err := (&templateSummarizer{}).Summarize(context.Background(), killChain())
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if report.Source != ProviderTemplate {
		t.Errorf("source = %q, want template", report.Source)
	}
	if report.Severity != "critical" {
		t.Errorf("severity = %q, want critical for risk 90", report.Severity)
	}
	for _, want := range []string{"web-01", "kdevtmpfsi", "4200", "T1036", "T1571"} {
		if !strings.Contains(report.Summary, want) {
			t.Errorf("summary missing %q: %s", want, report.Summary)
		}
	}
	if len(report.Containment) == 0 {
		t.Fatal("template should propose containment steps")
	}
	// Execution + C2 tactics should yield kill+isolate and an egress-block step.
	joined := strings.Join(report.Containment, " ")
	for _, want := range []string{"Kill the offending process", "Block egress"} {
		if !strings.Contains(joined, want) {
			t.Errorf("containment missing %q: %v", want, report.Containment)
		}
	}
}

func TestSeverityForRisk(t *testing.T) {
	cases := map[int]string{10: "low", 50: "medium", 75: "high", 90: "critical", 100: "critical"}
	for risk, want := range cases {
		if got := SeverityForRisk(risk); got != want {
			t.Errorf("SeverityForRisk(%d) = %q, want %q", risk, got, want)
		}
	}
}

func TestTemplateHandlesEmptyIncident(t *testing.T) {
	report, err := (&templateSummarizer{}).Summarize(context.Background(), Incident{})
	if err != nil {
		t.Fatalf("summarize empty: %v", err)
	}
	if !strings.Contains(report.Summary, "unknown") {
		t.Errorf("empty incident should read as unknown host/process: %s", report.Summary)
	}
	if len(report.Containment) != 1 {
		t.Errorf("no tactics should leave only the evidence step, got %v", report.Containment)
	}
}

func TestNewSelectsTemplateUnlessOptedIn(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name string
		cfg  Config
	}{
		{"disabled", Config{Enabled: false, Provider: ProviderClaude, APIKey: "k"}},
		{"template provider", Config{Enabled: true, Provider: ProviderTemplate, APIKey: "k"}},
		{"no key", Config{Enabled: true, Provider: ProviderClaude, APIKey: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := New(tc.cfg, logger).(*templateSummarizer); !ok {
				t.Errorf("expected the template summarizer for %s", tc.name)
			}
		})
	}
	enabled := Config{Enabled: true, Provider: ProviderClaude, APIKey: "k"}
	if _, ok := New(enabled, logger).(*fallbackSummarizer); !ok {
		t.Error("enabled Claude provider with a key should return the fallback summarizer")
	}
}

func TestClaudeSummarizerParsesReport(t *testing.T) {
	want := Report{Summary: "Cryptominer beaconing out.", Severity: "critical",
		Containment: []string{"Isolate the host."}, RuleDraft: "rule X {}"}
	server := stubAPI(t, http.StatusOK, claudeJSON(t, want, "end_turn"))
	defer server.Close()

	summarizer := newClaudeSummarizer(Config{APIKey: "k", Endpoint: server.URL})
	got, err := summarizer.Summarize(context.Background(), killChain())
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	if got.Summary != want.Summary || got.Severity != want.Severity || got.RuleDraft != want.RuleDraft {
		t.Errorf("parsed report = %+v, want %+v", got, want)
	}
	if got.Source != ProviderClaude {
		t.Errorf("source = %q, want claude", got.Source)
	}
}

func TestClaudeRefusalFallsBackToTemplate(t *testing.T) {
	server := stubAPI(t, http.StatusOK, claudeJSON(t, Report{Summary: "ignored"}, "refusal"))
	defer server.Close()
	assertFallsBackToTemplate(t, server.URL)
}

func TestClaudeHTTPErrorFallsBackToTemplate(t *testing.T) {
	server := stubAPI(t, http.StatusInternalServerError, []byte(`{"error":"overloaded"}`))
	defer server.Close()
	assertFallsBackToTemplate(t, server.URL)
}

// assertFallsBackToTemplate drives the full New() seam against a failing API and
// asserts the analyst still gets a deterministic template report.
func assertFallsBackToTemplate(t *testing.T, endpoint string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	summarizer := New(Config{Enabled: true, Provider: ProviderClaude, APIKey: "k", Endpoint: endpoint}, logger)
	report, err := summarizer.Summarize(context.Background(), killChain())
	if err != nil {
		t.Fatalf("fallback should not error: %v", err)
	}
	if report.Source != ProviderTemplate {
		t.Errorf("source = %q, want template after API failure", report.Source)
	}
}

func stubAPI(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("missing required headers: %v", r.Header)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

// claudeJSON builds a Messages API response whose single text block is the JSON
// report — the exact shape parseReport expects.
func claudeJSON(t *testing.T, report Report, stopReason string) []byte {
	t.Helper()
	inner, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := json.Marshal(messagesResponse{
		Content:    []contentBlock{{Type: "text", Text: string(inner)}},
		StopReason: stopReason,
	})
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

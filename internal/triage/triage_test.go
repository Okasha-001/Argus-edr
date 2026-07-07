package triage

import (
	"context"
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

func TestNewReturnsTemplateSummarizer(t *testing.T) {
	summarizer := New()
	if _, ok := summarizer.(*templateSummarizer); !ok {
		t.Error("New() should return the template summarizer")
	}
}

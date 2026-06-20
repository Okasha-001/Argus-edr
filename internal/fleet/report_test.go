package fleet

import (
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

func TestAlertReportFromAlert(t *testing.T) {
	when := time.Unix(1700, 0).UTC()
	alert := &model.Alert{
		Timestamp: when,
		RuleID:    "R-0001",
		RuleName:  "temp exec",
		Severity:  model.SeverityHigh,
		Technique: model.Technique{ID: "T1059", Name: "Scripting"},
		RiskScore: 50,
		Event: &model.Event{
			Process: model.Process{PID: 4242, Name: "bash", Executable: "/tmp/x"},
			Network: model.Network{DstIP: "203.0.113.7"},
		},
	}

	report := AlertReportFromAlert("agent-1", "web-01", alert)
	if report.GetAgentId() != "agent-1" || report.GetHostname() != "web-01" {
		t.Errorf("identity = %q/%q", report.GetAgentId(), report.GetHostname())
	}
	if report.GetSeverity() != "high" {
		t.Errorf("severity = %q, want high", report.GetSeverity())
	}
	if report.GetPid() != 4242 || report.GetProcessExecutable() != "/tmp/x" {
		t.Errorf("process = %d/%q", report.GetPid(), report.GetProcessExecutable())
	}
	if report.GetDestinationIp() != "203.0.113.7" {
		t.Errorf("dst = %q", report.GetDestinationIp())
	}
	if report.GetRiskScore() != 50 || report.GetTechniqueId() != "T1059" {
		t.Errorf("risk/technique = %d/%q", report.GetRiskScore(), report.GetTechniqueId())
	}
	if report.GetIsIncident() {
		t.Error("an alert is not an incident")
	}
	if !report.GetTimestamp().AsTime().Equal(when) {
		t.Errorf("timestamp = %v, want %v", report.GetTimestamp().AsTime(), when)
	}
}

func TestAlertReportFromIncident(t *testing.T) {
	incident := &model.Incident{
		ID:         "INC-7",
		Summary:    "chain on web-01",
		RiskScore:  120,
		Techniques: []string{"T1003", "T1059"},
		LastSeen:   time.Unix(1800, 0).UTC(),
	}
	report := AlertReportFromIncident("agent-1", "web-01", incident)
	if !report.GetIsIncident() {
		t.Error("incident report must set is_incident")
	}
	if report.GetSeverity() != "critical" {
		t.Errorf("severity = %q, want critical", report.GetSeverity())
	}
	if report.GetTechniqueId() != "T1003" {
		t.Errorf("technique = %q, want the lead T1003", report.GetTechniqueId())
	}
	if report.GetRuleId() != "INC-7" || report.GetRiskScore() != 120 {
		t.Errorf("id/risk = %q/%d", report.GetRuleId(), report.GetRiskScore())
	}
}

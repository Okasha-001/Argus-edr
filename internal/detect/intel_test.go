package detect

import (
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

// stubIntel is a fixed threat-intel source for testing the engine integration.
type stubIntel struct {
	hits []model.IntelHit
}

func (s stubIntel) Match(*model.Event) []model.IntelHit { return s.hits }

func TestEngineRaisesIntelAlerts(t *testing.T) {
	engine := NewEngine(nil, nil) // no rules: isolate the intel path
	engine.SetIntel(stubIntel{hits: []model.IntelHit{
		{Indicator: "203.0.113.66", Type: "ip", Field: "destination.ip", Source: "iocs.txt"},
	}})

	event := &model.Event{Type: model.EventConnect, Network: model.Network{DstIP: "203.0.113.66"}}
	result := engine.Evaluate(event)
	if len(result.Alerts) != 1 {
		t.Fatalf("got %d alerts, want 1", len(result.Alerts))
	}
	alert := result.Alerts[0]
	if alert.RuleID != "INTEL-IP" {
		t.Errorf("rule id = %q, want INTEL-IP", alert.RuleID)
	}
	if alert.Technique.ID != "T1071" {
		t.Errorf("network intel hit should map to T1071, got %q", alert.Technique.ID)
	}
	if alert.Severity != model.SeverityHigh {
		t.Errorf("severity = %v, want high", alert.Severity)
	}
}

func TestEngineWithoutIntelIsUnaffected(t *testing.T) {
	engine := NewEngine(nil, nil)
	if result := engine.Evaluate(&model.Event{Type: model.EventConnect}); len(result.Alerts) != 0 {
		t.Errorf("no rules and no intel should yield no alerts, got %d", len(result.Alerts))
	}
}

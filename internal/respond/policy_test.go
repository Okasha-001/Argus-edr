package respond

import (
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

func TestPolicyActionLadder(t *testing.T) {
	policy := DefaultPolicy()

	withDst := &model.Event{}
	withDst.Network.DstIP = "203.0.113.9" // TEST-NET, never a real host
	noDst := &model.Event{}

	tests := []struct {
		name  string
		alert *model.Alert
		want  Action
	}{
		// An explicit rule response overrides the ladder, even a low-risk one.
		{"rule action wins over score", &model.Alert{RequestedAction: "kill", RiskScore: 10, Event: noDst}, ActionKill},

		// Score selects the rung.
		{"score >= kill", &model.Alert{RiskScore: 95, Event: noDst}, ActionKill},
		{"score in block band, with destination", &model.Alert{RiskScore: 80, Event: withDst}, ActionNetworkBlock},
		{"score in block band, no destination falls to throttle", &model.Alert{RiskScore: 80, Event: noDst}, ActionThrottle},
		{"score in throttle band", &model.Alert{RiskScore: 60, Event: noDst}, ActionThrottle},
		{"score below throttle is alert-only", &model.Alert{RiskScore: 20, Event: noDst}, ActionAlertOnly},

		// With no explicit score, severity stands in at the canonical rungs.
		{"severity critical -> kill", &model.Alert{Severity: model.SeverityCritical, Event: noDst}, ActionKill},
		{"severity high + destination -> block", &model.Alert{Severity: model.SeverityHigh, Event: withDst}, ActionNetworkBlock},
		{"severity high, no destination -> throttle", &model.Alert{Severity: model.SeverityHigh, Event: noDst}, ActionThrottle},
		{"severity medium -> throttle", &model.Alert{Severity: model.SeverityMedium, Event: noDst}, ActionThrottle},
		{"severity low -> alert-only", &model.Alert{Severity: model.SeverityLow, Event: noDst}, ActionAlertOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := policy.Action(tt.alert); got != tt.want {
				t.Errorf("Action() = %q, want %q", got, tt.want)
			}
		})
	}
}

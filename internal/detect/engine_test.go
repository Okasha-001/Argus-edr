package detect

import (
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

func reverseShellEvent() *model.Event {
	return &model.Event{
		Type:    model.EventExec,
		Action:  "exec",
		Process: model.Process{PID: 4123, Name: "bash", Executable: "/usr/bin/bash", ParentName: "nginx", StdioSocket: true},
		Network: model.Network{DstIP: "203.0.113.9", DstPort: 4444},
	}
}

func TestLeafOperators(t *testing.T) {
	cases := []struct {
		name string
		cond *Condition
		want bool
	}{
		{"eq string match", &Condition{Field: "event.type", Op: "eq", Value: "exec"}, true},
		{"eq string miss", &Condition{Field: "event.type", Op: "eq", Value: "open"}, false},
		{"eq bool", &Condition{Field: "process.stdio_socket", Op: "eq", Value: true}, true},
		{"startswith", &Condition{Field: "process.executable", Op: "startswith", Value: "/usr/"}, true},
		{"in list", &Condition{Field: "process.name", Op: "in", Value: []any{"sh", "bash"}}, true},
		{"not_in list", &Condition{Field: "process.name", Op: "not_in", Value: []any{"sh", "zsh"}}, true},
		{"ge numeric", &Condition{Field: "destination.port", Op: "ge", Value: 1024}, true},
		{"lt numeric", &Condition{Field: "destination.port", Op: "lt", Value: 1024}, false},
		{"cidr match", &Condition{Field: "destination.ip", Op: "cidr", Value: "203.0.113.0/24"}, true},
		{"regex", &Condition{Field: "process.executable", Op: "regex", Value: `^/usr/bin/(ba|z)?sh$`}, true},
		{"exists", &Condition{Field: "process.executable", Op: "exists"}, true},
	}
	event := reverseShellEvent()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cond.Compile(); err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := tc.cond.Eval(event); got != tc.want {
				t.Errorf("Eval = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNestedCondition(t *testing.T) {
	cond := &Condition{
		All: []*Condition{
			{Field: "event.type", Op: "eq", Value: "exec"},
			{Any: []*Condition{
				{Field: "process.name", Op: "eq", Value: "zsh"},
				{Field: "process.name", Op: "eq", Value: "bash"},
			}},
		},
	}
	if err := cond.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !cond.Eval(reverseShellEvent()) {
		t.Error("nested all/any should match the reverse shell event")
	}
}

func TestCompileRejectsUnknownField(t *testing.T) {
	cond := &Condition{Field: "process.nonexistent", Op: "eq", Value: "x"}
	if err := cond.Compile(); err == nil {
		t.Fatal("expected compile error for an unknown field")
	}
}

func TestCompileRejectsAmbiguousNode(t *testing.T) {
	cond := &Condition{
		Field: "event.type", Op: "eq", Value: "exec",
		Any: []*Condition{{Field: "process.name", Op: "exists"}},
	}
	if err := cond.Compile(); err == nil {
		t.Fatal("expected compile error: a node cannot be both a leaf and a group")
	}
}

func TestRepoRulesFireOnReverseShell(t *testing.T) {
	rules, err := LoadDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	engine := NewEngine(rules, nil)

	result := engine.Evaluate(reverseShellEvent())
	if !containsRule(result.Alerts, "R-0007") {
		t.Errorf("expected R-0007 to fire, got alerts %v", ruleIDs(result.Alerts))
	}
}

func TestCorrelatorOpensIncidentAtThreshold(t *testing.T) {
	correlator := NewCorrelator(30*time.Second, 75)
	event := &model.Event{
		Host:      "web-01",
		Timestamp: time.Unix(1_700_000_000, 0),
		Process:   model.Process{PID: 4200, StartTimeNs: 3000},
	}

	if incident := correlator.Observe(event, []*model.Alert{alert("R-0001", 50, "T1036")}); incident != nil {
		t.Fatal("incident opened below threshold")
	}
	incident := correlator.Observe(event, []*model.Alert{alert("R-0008", 40, "T1571")})
	if incident == nil {
		t.Fatal("incident should open once accumulated risk crosses the threshold")
	}
	if incident.RiskScore != 90 {
		t.Errorf("incident risk = %d, want 90", incident.RiskScore)
	}
	if len(incident.Techniques) != 2 {
		t.Errorf("incident techniques = %v, want 2", incident.Techniques)
	}
}

func alert(ruleID string, risk int, technique string) *model.Alert {
	return &model.Alert{RuleID: ruleID, RiskScore: risk, Technique: model.Technique{ID: technique}}
}

func containsRule(alerts []*model.Alert, id string) bool {
	for _, a := range alerts {
		if a.RuleID == id {
			return true
		}
	}
	return false
}

func ruleIDs(alerts []*model.Alert) []string {
	ids := make([]string, len(alerts))
	for i, a := range alerts {
		ids[i] = a.RuleID
	}
	return ids
}

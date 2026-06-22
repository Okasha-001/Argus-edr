package hunt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/model"
)

// TestToRuleRoundTrips proves the converter emits a rule the real detection
// engine loads and runs: the generated rule must fire on an event the hunt
// matched and stay silent on one it did not. This is the Phase 14 → Phase 16
// promise — a proven hunt becomes a working rule — enforced, not asserted on text.
func TestToRuleRoundTrips(t *testing.T) {
	query, err := Compile(`exec where process.name in ("bash", "sh") and process.parent.name == "nginx"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	yamlBytes, err := query.ToRule(RuleMeta{
		ID: "R-HUNT-1", Name: "Shell spawned by nginx", Severity: "high", RiskScore: 70,
		Technique: Technique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "execution"},
	})
	if err != nil {
		t.Fatalf("to rule: %v", err)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hunt.yaml"), yamlBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := detect.LoadDir(dir)
	if err != nil {
		t.Fatalf("the generated rule did not load: %v\n--- yaml ---\n%s", err, yamlBytes)
	}
	if len(rules) != 1 {
		t.Fatalf("loaded %d rules, want 1", len(rules))
	}
	engine := detect.NewEngine(rules, nil)

	fires := newEvent("exec", func(e *model.Event) {
		e.Process = model.Process{PID: 10, Name: "bash", ParentName: "nginx"}
	})
	if got := engine.Evaluate(fires).Alerts; len(got) != 1 {
		t.Errorf("rule should fire on a matching event, got %d alerts", len(got))
	}

	silent := newEvent("exec", func(e *model.Event) {
		e.Process = model.Process{PID: 11, Name: "bash", ParentName: "sshd"} // wrong parent
	})
	if got := engine.Evaluate(silent).Alerts; len(got) != 0 {
		t.Errorf("rule should stay silent on a non-matching event, got %d alerts", len(got))
	}
}

func TestToRuleRejectsSequences(t *testing.T) {
	query, err := Compile(`sequence by host.name within 5m:
		exec where process.name == "curl";
		connect where destination.port == 4444`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, err := query.ToRule(RuleMeta{ID: "R-X", Name: "x"}); err == nil {
		t.Fatal("a sequence query must not convert to a single rule")
	}
}

func TestToRuleNeedsIdentity(t *testing.T) {
	query, _ := Compile(`exec where process.name == "bash"`)
	if _, err := query.ToRule(RuleMeta{Name: "no id"}); err == nil {
		t.Fatal("a rule without an id must be rejected")
	}
}

func newEvent(action string, fn func(*model.Event)) *model.Event {
	e := &model.Event{Action: action}
	fn(e)
	e.Normalize()
	return e
}

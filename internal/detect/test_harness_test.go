package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunRuleTests(t *testing.T) {
	rules, err := LoadDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	tests := []RuleTest{
		{
			Name: "temp-dir exec fires", Rule: "R-0001", Expect: ExpectFire,
			Event: map[string]any{"action": "exec", "process": map[string]any{"name": "x", "executable": "/tmp/x"}},
		},
		{
			Name: "system binary does not", Rule: "R-0001", Expect: ExpectNoFire,
			Event: map[string]any{"action": "exec", "process": map[string]any{"name": "ls", "executable": "/usr/bin/ls"}},
		},
	}
	report, err := RunRuleTests(rules, tests)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Failed() != 0 {
		t.Errorf("expected all passing, got %d failures: %+v", report.Failed(), report.Results)
	}
	if report.FalsePositiveRate() != 0 {
		t.Errorf("FP rate = %v, want 0", report.FalsePositiveRate())
	}
	if !report.TestedRules["R-0001"] {
		t.Error("R-0001 should be marked tested")
	}
}

func TestRunRuleTestsCatchesRegressions(t *testing.T) {
	rules, err := LoadDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	// A no-fire assertion that actually fires is a false positive; a fire
	// assertion on an unknown rule fails too.
	tests := []RuleTest{
		{
			Name: "false positive", Rule: "R-0001", Expect: ExpectNoFire,
			Event: map[string]any{"action": "exec", "process": map[string]any{"executable": "/tmp/evil"}},
		},
		{Name: "ghost rule", Rule: "R-9999", Expect: ExpectFire, Event: map[string]any{"action": "exec"}},
	}
	report, err := RunRuleTests(rules, tests)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Failed() != 2 {
		t.Errorf("expected 2 failures, got %d", report.Failed())
	}
	if report.FalsePositives != 1 {
		t.Errorf("expected 1 false positive, got %d", report.FalsePositives)
	}
}

func TestLoadRuleTestsValidates(t *testing.T) {
	dir := t.TempDir()
	bad := "- name: x\n  rule: R-1\n  expect: maybe\n  event: {action: exec}\n"
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRuleTests(dir); err == nil {
		t.Fatal("an invalid expect value must be rejected at load")
	}
}

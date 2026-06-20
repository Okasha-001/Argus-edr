package detect

import (
	"testing"

	"github.com/argus-edr/argus/internal/model"
	"gopkg.in/yaml.v3"
)

// FuzzRuleCompile fuzzes the YAML rule parser and condition compiler — the path
// that turns operator-supplied (and, in a fleet, pushed) rule files into live
// matchers. It must reject malformed rules with an error, never a panic, and any
// rule that compiles must evaluate safely against an event.
func FuzzRuleCompile(f *testing.F) {
	f.Add([]byte("- id: R-1\n  severity: high\n  match:\n    all:\n      - {field: event.type, op: eq, value: exec}\n"))
	f.Add([]byte("- id: R-2\n  severity: low\n  match: {field: process.executable, op: regex, value: \"(\"}\n"))
	f.Add([]byte("- id: R-3\n  match: {field: destination.port, op: ge, value: notanumber}\n"))
	f.Add([]byte("not: [valid"))

	event := &model.Event{
		Type:    model.EventExec,
		Action:  "exec",
		Process: model.Process{PID: 1, Name: "bash", Executable: "/usr/bin/bash"},
		Network: model.Network{DstIP: "203.0.113.1", DstPort: 4444},
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var docs []ruleYAML
		if err := yaml.Unmarshal(data, &docs); err != nil {
			return // malformed YAML is expected; it must not panic
		}
		for _, doc := range docs {
			rule, err := compileRule(doc)
			if err != nil {
				continue // invalid rules are rejected, not fatal
			}
			_ = rule.Matches(event) // a compiled rule must evaluate without panicking
		}
	})
}

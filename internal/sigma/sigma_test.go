package sigma

import (
	"strings"
	"testing"
)

func TestConvertMapsMetadata(t *testing.T) {
	rule, err := Convert([]byte(`
title: Netcat Reverse Shell
id: 7e2dca1a-1111-2222-3333-444455556666
description: Detects a netcat reverse shell.
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
  condition: selection
`))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if rule.ID() != "SIGMA-7E2DCA1A" {
		t.Errorf("id = %q, want SIGMA-7E2DCA1A", rule.ID())
	}
	if rule.doc.Severity != "high" || rule.doc.RiskScore != 70 {
		t.Errorf("severity/risk = %q/%d, want high/70", rule.doc.Severity, rule.doc.RiskScore)
	}
	if rule.doc.Technique == nil || rule.doc.Technique.ID != "T1059.004" || rule.doc.Technique.Tactic != "execution" {
		t.Errorf("technique = %+v, want T1059.004/execution", rule.doc.Technique)
	}
}

func TestConvertInfersStringOperators(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantOp    string
		wantValue any
	}{
		{"exact", "/usr/bin/nc", "eq", "/usr/bin/nc"},
		{"prefix", "/tmp/*", "startswith", "/tmp/"},
		{"suffix", "*/nc", "endswith", "/nc"},
		{"contains", "*reverse*", "contains", "reverse"},
		{"interior wildcard", "/tmp/*.sh", "regex", `^/tmp/.*\.sh$`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leaf := singleLeaf(t, "CommandLine", test.value)
			if leaf.Op != test.wantOp || leaf.Value != test.wantValue {
				t.Errorf("op/value = %q/%v, want %q/%v", leaf.Op, leaf.Value, test.wantOp, test.wantValue)
			}
		})
	}
}

func TestConvertListIsOredByDefault(t *testing.T) {
	rule := mustConvert(t, `
title: List selection
level: low
logsource: {category: process_creation}
detection:
  selection:
    CommandLine|contains:
      - -e
      - /bin/sh
  condition: selection
`)
	// match = all[ event.action, any[ contains -e, contains /bin/sh ] ]
	detection := rule.doc.Match.All[1]
	if len(detection.Any) != 2 {
		t.Fatalf("expected an OR of 2 leaves, got %+v", detection)
	}
}

func TestConvertAllModifierAndsList(t *testing.T) {
	rule := mustConvert(t, `
title: All-modifier selection
level: low
logsource: {category: process_creation}
detection:
  selection:
    CommandLine|contains|all:
      - -e
      - /bin/sh
  condition: selection
`)
	// The detection is a pure AND, so it flattens into the action-guarded top
	// level: [event.action guard, contains -e, contains /bin/sh].
	if len(rule.doc.Match.All) != 3 {
		t.Fatalf("expected guard + 2 anded leaves, got %+v", rule.doc.Match.All)
	}
	for _, node := range rule.doc.Match.All[1:] {
		if node.Op != "contains" {
			t.Errorf("expected a contains leaf, got %+v", node)
		}
	}
}

func TestConvertConditionNegation(t *testing.T) {
	rule := mustConvert(t, `
title: Selection and not filter
level: medium
logsource: {category: process_creation}
detection:
  selection:
    Image|endswith: /bash
  filter:
    User: root
  condition: selection and not filter
`)
	// match = all[ event.action, image-leaf, not[ user-leaf ] ]
	top := rule.doc.Match.All
	if len(top) != 3 {
		t.Fatalf("expected 3 anded nodes, got %d: %+v", len(top), top)
	}
	if top[2].Not == nil || top[2].Not.Field != "user.name" {
		t.Errorf("third node should negate user.name, got %+v", top[2])
	}
}

func TestConvertQuantifier(t *testing.T) {
	rule := mustConvert(t, `
title: One of many
level: medium
logsource: {category: process_creation}
detection:
  selection_a:
    Image|endswith: /nc
  selection_b:
    Image|endswith: /ncat
  condition: 1 of selection_*
`)
	detection := rule.doc.Match.All[1]
	if len(detection.Any) != 2 {
		t.Fatalf("expected OR of 2 selections, got %+v", detection)
	}
}

func TestConvertRejectsUnsupported(t *testing.T) {
	tests := map[string]string{
		"windows product": `
title: Windows rule
logsource: {category: process_creation, product: windows}
detection: {selection: {Image: x}, condition: selection}`,
		"unknown category": `
title: Registry rule
logsource: {category: registry_set}
detection: {selection: {TargetObject: x}, condition: selection}`,
		"unknown modifier": `
title: Base64 rule
logsource: {category: process_creation}
detection: {selection: {CommandLine|base64: x}, condition: selection}`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Convert([]byte(document))
			if !IsUnsupported(err) {
				t.Errorf("err = %v, want UnsupportedError", err)
			}
		})
	}
}

func TestConvertRejectsUncompilableValues(t *testing.T) {
	// A rule that converts but then fails to load is the worst outcome, so an
	// invalid regex/CIDR must fail at convert time instead.
	tests := map[string]string{
		"invalid regex": `
title: Bad regex
logsource: {category: process_creation}
detection: {selection: {CommandLine|re: '('}, condition: selection}`,
		"invalid cidr": `
title: Bad cidr
logsource: {category: network_connection}
detection: {selection: {DestinationIp|cidr: 'not-a-cidr'}, condition: selection}`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Convert([]byte(document)); err == nil {
				t.Error("expected convert to reject an uncompilable value")
			}
		})
	}
}

func TestConvertUnknownFieldIsUnsupported(t *testing.T) {
	_, err := Convert([]byte(`
title: Unknown field
logsource: {category: process_creation}
detection: {selection: {IntegrityLevel: High}, condition: selection}`))
	if !IsUnsupported(err) {
		t.Fatalf("err = %v, want UnsupportedError for unknown field", err)
	}
}

func mustConvert(t *testing.T, document string) *Rule {
	t.Helper()
	rule, err := Convert([]byte(document))
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	return rule
}

// singleLeaf converts a one-field process_creation rule and returns the field
// leaf, peeling off the event-action guard.
func singleLeaf(t *testing.T, field, value string) *condDoc {
	t.Helper()
	rule := mustConvert(t, strings.Join([]string{
		"title: One field",
		"level: low",
		"logsource: {category: process_creation}",
		"detection:",
		"  selection:",
		"    " + field + ": '" + value + "'",
		"  condition: selection",
	}, "\n"))
	return rule.doc.Match.All[1]
}

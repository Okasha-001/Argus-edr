package sigma_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/sigma"
)

// FuzzConvert fuzzes the Sigma importer with arbitrary YAML — the path that
// ingests untrusted community rules. It enforces the importer's core contract:
// Convert never panics, and any rule it accepts must marshal to YAML that the
// production loader compiles and can evaluate without panicking. A converted
// rule the agent then fails to load would be the worst outcome, so the fuzzer
// closes exactly that gap.
func FuzzConvert(f *testing.F) {
	seeds := []string{
		"title: A\nlevel: high\nlogsource: {category: process_creation}\ndetection: {selection: {Image|endswith: /nc}, condition: selection}\n",
		"title: B\nlogsource: {category: network_connection}\ndetection: {sel: {DestinationIp|cidr: 203.0.113.0/24}, condition: sel}\n",
		"title: C\nlogsource: {category: process_creation}\ndetection: {a: {CommandLine|re: 'foo.*bar'}, b: {Image: '*/sh'}, condition: a and not b}\n",
		"title: D\nlogsource: {category: process_creation}\ndetection: {s1: {Image: x}, s2: {Image: y}, condition: 1 of s*}\n",
		"title: E\nlogsource: {category: dns_query}\ndetection: {sel: {QueryName|contains: evil}, condition: sel}\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	dir := f.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	event := &model.Event{
		Type:    model.EventExec,
		Action:  "exec",
		Process: model.Process{PID: 1, Name: "sh", Executable: "/bin/sh", CommandLine: "sh -c id"},
		Network: model.Network{DstIP: "203.0.113.10", DstPort: 443, Domain: "evil.example"},
		File:    model.File{Path: "/tmp/x"},
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		rule, err := sigma.Convert(data)
		if err != nil {
			return // malformed or unsupported rules are rejected, not fatal
		}

		bundle, err := sigma.MarshalRules([]*sigma.Rule{rule})
		if err != nil {
			t.Fatalf("converted rule failed to marshal: %v", err)
		}
		if err := os.WriteFile(rulePath, bundle, 0o644); err != nil {
			t.Fatalf("write bundle: %v", err)
		}
		rules, err := detect.LoadDir(dir)
		if err != nil {
			t.Fatalf("converted rule failed to load: %v\n%s", err, bundle)
		}
		for _, loaded := range rules {
			_ = loaded.Matches(event) // a converted rule must evaluate without panicking
		}
	})
}

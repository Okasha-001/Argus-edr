package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func parseAudit(t *testing.T, sink *bytes.Buffer) []auditEntry {
	t.Helper()
	var entries []auditEntry
	for _, line := range strings.Split(strings.TrimSpace(sink.String()), "\n") {
		if line == "" {
			continue
		}
		var entry auditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("unmarshal audit line: %v", err)
		}
		entries = append(entries, entry)
	}
	return entries
}

func TestAuditChainVerifies(t *testing.T) {
	var sink bytes.Buffer
	log := newAuditLog(&sink, []byte("k3y"), nil)
	log.record("admin", "rules_reload", "v1", "")
	log.record("operator", "enqueue_command", "agent-1", "KILL_PROCESS 123")

	entries := parseAudit(t, &sink)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if err := verifyAuditChain(entries, []byte("k3y")); err != nil {
		t.Errorf("an intact chain should verify: %v", err)
	}
}

func TestAuditDetectsTamperedRecord(t *testing.T) {
	var sink bytes.Buffer
	log := newAuditLog(&sink, nil, nil) // unkeyed: the hash chain alone
	log.record("admin", "rules_reload", "v1", "")
	log.record("admin", "enqueue_command", "agent-1", "QUARANTINE 10.0.0.9")

	entries := parseAudit(t, &sink)
	entries[0].Action = "nothing_happened" // someone edits a past entry
	if err := verifyAuditChain(entries, nil); err == nil {
		t.Error("a tampered record must fail verification")
	}
}

func TestAuditDetectsForgedSignature(t *testing.T) {
	var sink bytes.Buffer
	log := newAuditLog(&sink, []byte("real-key"), nil)
	log.record("admin", "rules_reload", "v1", "")

	if err := verifyAuditChain(parseAudit(t, &sink), []byte("wrong-key")); err == nil {
		t.Error("verification with the wrong key must fail")
	}
}

func TestAuditDetectsReorder(t *testing.T) {
	var sink bytes.Buffer
	log := newAuditLog(&sink, nil, nil)
	log.record("admin", "first", "", "")
	log.record("admin", "second", "", "")

	entries := parseAudit(t, &sink)
	entries[0], entries[1] = entries[1], entries[0] // reorder the log
	if err := verifyAuditChain(entries, nil); err == nil {
		t.Error("a reordered chain must fail verification")
	}
}

package ruleset

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const ruleTemplate = `- id: %s
  name: test
  severity: high
  technique: { id: T1059, name: Scripting, tactic: execution }
  match:
    all:
      - { field: event.type, op: eq, value: exec }
`

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProviderLoadsAndVersions(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "00.yaml", fmt.Sprintf(ruleTemplate, "R-1"))
	writeRule(t, dir, "10.yaml", fmt.Sprintf(ruleTemplate, "R-2"))

	provider, err := NewProvider(dir)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	version, files := provider.Bundle()
	if version == "" {
		t.Error("version should not be empty")
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want 2", len(files))
	}
	if provider.Version() != version {
		t.Error("Version and Bundle disagree")
	}
}

func TestVersionStableAndChanges(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "00.yaml", fmt.Sprintf(ruleTemplate, "R-1"))
	provider, err := NewProvider(dir)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	original := provider.Version()

	if err := provider.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if provider.Version() != original {
		t.Error("version changed without a content change")
	}

	writeRule(t, dir, "10.yaml", fmt.Sprintf(ruleTemplate, "R-2"))
	if err := provider.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if provider.Version() == original {
		t.Error("version should change after adding a rule file")
	}
}

func TestProviderRejectsInvalidRules(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", "- id: R-1\n  name: no match block\n  severity: high\n")
	if _, err := NewProvider(dir); err == nil {
		t.Fatal("expected NewProvider to reject a rule with no match block")
	}
}

func TestReloadKeepsLastGoodBundle(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "00.yaml", fmt.Sprintf(ruleTemplate, "R-1"))
	provider, err := NewProvider(dir)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	good := provider.Version()

	writeRule(t, dir, "00.yaml", "this is not a valid rule list")
	if err := provider.Reload(); err == nil {
		t.Fatal("expected reload of a broken ruleset to fail")
	}
	if provider.Version() != good {
		t.Error("a failed reload must leave the previous good bundle in place")
	}
}

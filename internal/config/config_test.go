package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsAreValid(t *testing.T) {
	if _, err := Load(""); err != nil {
		t.Fatalf("built-in defaults should be valid: %v", err)
	}
}

func TestLoadOverlaysFileOntoDefaults(t *testing.T) {
	path := writeConfig(t, "input:\n  source: replay\n  replay_file: events.ndjson\nresponse:\n  mode: dry-run\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Input.Source != SourceReplay {
		t.Errorf("source = %q, want replay", cfg.Input.Source)
	}
	if cfg.Response.Mode != ModeDryRun {
		t.Errorf("mode = %q, want dry-run", cfg.Response.Mode)
	}
	if !cfg.Enrichment.ProcessTree {
		t.Error("unspecified default process_tree should remain true after overlay")
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	path := writeConfig(t, "agent:\n  bogus_key: 1\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an unknown config key")
	}
}

func TestLoadRejectsInvalidMode(t *testing.T) {
	path := writeConfig(t, "response:\n  mode: destroy\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an invalid response mode")
	}
}

func TestMaxModeDefaultsToMode(t *testing.T) {
	cfg, err := Load(writeConfig(t, "response:\n  mode: dry-run\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Response.MaxMode != ModeDryRun {
		t.Errorf("max_mode = %q, want it defaulted to mode (dry-run)", cfg.Response.MaxMode)
	}
}

func TestLoadRejectsModeAboveMaxMode(t *testing.T) {
	path := writeConfig(t, "response:\n  mode: enforce\n  max_mode: dry-run\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error when mode exceeds max_mode")
	}
}

func TestLoadRejectsOverlongCredReader(t *testing.T) {
	// "this-comm-is-far-too-long" exceeds the 15-char comm the kernel stores, so
	// it could never match and must be rejected rather than silently ignored.
	path := writeConfig(t, "response:\n  cred_reader_allowlist: [this-comm-is-far-too-long]\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a cred-reader comm longer than 15 chars")
	}
}

func TestDefaultsIncludeAuthStackReaders(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if len(cfg.Response.CredReaderAllowlist) == 0 {
		t.Fatal("default cred-reader allowlist must protect the auth stack, got none")
	}
	for _, comm := range cfg.Response.CredReaderAllowlist {
		if len(comm) > maxCommLen {
			t.Errorf("default cred-reader %q exceeds the kernel comm limit", comm)
		}
	}
}

func TestModeValue(t *testing.T) {
	for mode, want := range map[string]uint32{ModeOff: 0, ModeDryRun: 1, ModeEnforce: 2} {
		if got := (Response{Mode: mode}).ModeValue(); got != want {
			t.Errorf("ModeValue(%q) = %d, want %d", mode, got, want)
		}
	}
}

func TestFleetEnabledRequiresConnectionFields(t *testing.T) {
	path := writeConfig(t, "fleet:\n  enabled: true\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error when fleet is enabled without connection fields")
	}
}

func TestFleetFullySpecifiedIsValid(t *testing.T) {
	body := "fleet:\n" +
		"  enabled: true\n" +
		"  server_address: argus.example.com:8443\n" +
		"  server_name: argus.example.com\n" +
		"  ca_file: /etc/argus/fleet/ca.pem\n" +
		"  cert_file: /etc/argus/fleet/agent.pem\n" +
		"  key_file: /etc/argus/fleet/agent-key.pem\n" +
		"  heartbeat_seconds: 15\n"
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("a fully specified fleet config should be valid: %v", err)
	}
	if !cfg.Fleet.Enabled || cfg.Fleet.HeartbeatSeconds != 15 {
		t.Errorf("fleet config not applied: %+v", cfg.Fleet)
	}
}

func TestFleetDisabledByDefault(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if cfg.Fleet.Enabled {
		t.Error("fleet must be disabled by default")
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

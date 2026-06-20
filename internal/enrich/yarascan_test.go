package enrich

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/yara"
)

// The genuine EICAR test string — a real, standardized signature, not fabricated.
const eicarBody = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func TestYaraScanMarksExecutable(t *testing.T) {
	engine, err := yara.Compile(`rule EICAR_Test_File { strings: $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $e }`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	enricher := New(Options{Yara: engine, YaraMaxBytes: 1 << 20})
	dir := t.TempDir()

	infected := filepath.Join(dir, "sample.bin")
	if err := os.WriteFile(infected, []byte(eicarBody), 0o755); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	event := &model.Event{Type: model.EventExec, Action: "exec"}
	event.Process.Executable = infected
	enricher.Enrich(event)
	if !slices.Contains(event.Process.YaraMatches, "EICAR_Test_File") {
		t.Errorf("yara matches = %v, want EICAR_Test_File", event.Process.YaraMatches)
	}

	clean := filepath.Join(dir, "clean.bin")
	if err := os.WriteFile(clean, []byte("harmless content"), 0o755); err != nil {
		t.Fatalf("write clean: %v", err)
	}
	benign := &model.Event{Type: model.EventExec, Action: "exec"}
	benign.Process.Executable = clean
	enricher.Enrich(benign)
	if len(benign.Process.YaraMatches) != 0 {
		t.Errorf("clean file matched: %v", benign.Process.YaraMatches)
	}
}

package respond

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSelfIntegrityReportsBinaryChange(t *testing.T) {
	var reported []*model.Alert
	hash := "aaaa"
	check := &SelfIntegrity{
		path:     "/proc/self/exe",
		baseline: "aaaa",
		report:   func(a *model.Alert) { reported = append(reported, a) },
		logger:   quietLogger(),
		hashFile: func(string) (string, error) { return hash, nil },
	}

	check.check() // unchanged
	if len(reported) != 0 {
		t.Fatalf("an unchanged binary must not report, got %d", len(reported))
	}

	hash = "bbbb" // the binary was swapped underneath us
	check.check()
	if len(reported) != 1 {
		t.Fatalf("a changed binary should report once, got %d", len(reported))
	}
	if reported[0].RuleID != "R-SELF-INTEGRITY" || reported[0].Severity != model.SeverityCritical {
		t.Errorf("alert = %+v, want critical R-SELF-INTEGRITY", reported[0])
	}

	check.check() // still bbbb — re-baselined, so no repeat
	if len(reported) != 1 {
		t.Errorf("a persistent change should alert once, got %d", len(reported))
	}
}

func TestSelfIntegrityIgnoresHashError(t *testing.T) {
	reported := 0
	check := &SelfIntegrity{
		path:     "x",
		baseline: "aaaa",
		report:   func(*model.Alert) { reported++ },
		logger:   quietLogger(),
		hashFile: func(string) (string, error) { return "", errors.New("gone") },
	}
	check.check()
	if reported != 0 {
		t.Errorf("a transient hash error must not be reported as tampering, got %d", reported)
	}
}

func TestNewSelfIntegrityHashesRealFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "argus")
	if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	check, err := NewSelfIntegrity(path, time.Minute, func(*model.Alert) {}, quietLogger())
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if check.baseline == "" {
		t.Error("a real file should yield a non-empty baseline hash")
	}
}

func TestNewSelfIntegrityFailsOnMissingBinary(t *testing.T) {
	if _, err := NewSelfIntegrity("/no/such/argus", time.Minute, func(*model.Alert) {}, quietLogger()); err == nil {
		t.Fatal("expected an error when the binary cannot be hashed")
	}
}

func TestWatchdogReportsStallOnce(t *testing.T) {
	var reported []*model.Alert
	const timeout = 10 * time.Second
	watchdog := NewWatchdog(timeout, func(a *model.Alert) { reported = append(reported, a) }, quietLogger())
	base := time.Unix(0, watchdog.lastKick.Load())

	watchdog.checkAt(base.Add(time.Second)) // well within the timeout
	if len(reported) != 0 {
		t.Fatalf("a fresh kick should not stall, got %d", len(reported))
	}

	watchdog.checkAt(base.Add(11 * time.Second)) // past the timeout, no kick
	if len(reported) != 1 {
		t.Fatalf("a missed heartbeat should report, got %d", len(reported))
	}
	if reported[0].RuleID != "R-SELF-WATCHDOG" {
		t.Errorf("rule = %q, want R-SELF-WATCHDOG", reported[0].RuleID)
	}

	watchdog.checkAt(base.Add(20 * time.Second)) // still stalled
	if len(reported) != 1 {
		t.Errorf("a persistent stall should report once, got %d", len(reported))
	}
}

func TestWatchdogRecoversAfterKick(t *testing.T) {
	reported := 0
	const timeout = 10 * time.Second
	watchdog := NewWatchdog(timeout, func(*model.Alert) { reported++ }, quietLogger())

	watchdog.checkAt(time.Unix(0, watchdog.lastKick.Load()).Add(11 * time.Second))
	if reported != 1 || !watchdog.stalled.Load() {
		t.Fatalf("expected a stall; reported=%d stalled=%v", reported, watchdog.stalled.Load())
	}

	watchdog.Kick() // the pipeline made progress again
	if watchdog.stalled.Load() {
		t.Error("a kick should clear the stalled flag")
	}

	watchdog.checkAt(time.Unix(0, watchdog.lastKick.Load()).Add(11 * time.Second))
	if reported != 2 {
		t.Errorf("a fresh stall after recovery should report again, got %d", reported)
	}
}

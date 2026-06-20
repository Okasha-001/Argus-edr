package respond

import (
	"errors"
	"io"
	"log/slog"
	"testing"
)

func quietResponder(mode Mode) *Responder {
	// Ceiling at enforce so these tests exercise mode behaviour without clamping.
	return New(mode, ModeEnforce, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestSetModeClampsToCeiling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Operator pins the host observe-only: start dry-run, ceiling dry-run.
	responder := New(ModeDryRun, ModeDryRun, nil, logger)

	// A control-plane SET_RESPONSE_MODE enforce must not escalate past the ceiling.
	responder.SetMode(ModeEnforce)
	if got := responder.Mode(); got != ModeDryRun {
		t.Errorf("mode = %v after remote enforce, want clamped to dry-run", got)
	}

	// Lowering posture remotely is still allowed.
	responder.SetMode(ModeOff)
	if got := responder.Mode(); got != ModeOff {
		t.Errorf("mode = %v after remote off, want off", got)
	}
}

func TestNewClampsStartingMode(t *testing.T) {
	// A starting posture above the ceiling is itself clamped.
	responder := New(ModeEnforce, ModeOff, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := responder.Mode(); got != ModeOff {
		t.Errorf("mode = %v, want clamped to off", got)
	}
}

func TestRequestKillHonoursMode(t *testing.T) {
	responder := quietResponder(ModeOff)
	var killed bool
	responder.kill = func(uint32, string) error { killed = true; return nil }

	if got := responder.RequestKill(123, ""); got != "suppressed: response off" {
		t.Errorf("off mode result = %q", got)
	}
	if killed {
		t.Error("kill must not run while response mode is off")
	}

	responder.SetMode(ModeDryRun)
	if got := responder.RequestKill(123, ""); got != "dry-run" {
		t.Errorf("dry-run result = %q", got)
	}
	if killed {
		t.Error("kill must not run in dry-run")
	}

	responder.SetMode(ModeEnforce)
	if got := responder.RequestKill(123, ""); got != "success" {
		t.Errorf("enforce result = %q", got)
	}
	if !killed {
		t.Error("kill should run in enforce mode")
	}
}

func TestRequestKillReportsFailure(t *testing.T) {
	responder := quietResponder(ModeEnforce)
	responder.kill = func(uint32, string) error { return errors.New("gone") }
	if got := responder.RequestKill(7, "bash"); got != "failed: gone" {
		t.Errorf("result = %q, want failed: gone", got)
	}
}

func TestSetModeRoundTrip(t *testing.T) {
	responder := quietResponder(ModeOff)
	if responder.Mode() != ModeOff {
		t.Fatalf("initial mode = %v", responder.Mode())
	}
	responder.SetMode(ModeEnforce)
	if responder.Mode() != ModeEnforce {
		t.Errorf("mode after set = %v, want enforce", responder.Mode())
	}
}

func TestModeString(t *testing.T) {
	for mode, want := range map[Mode]string{ModeOff: "off", ModeDryRun: "dry-run", ModeEnforce: "enforce"} {
		if got := mode.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", mode, got, want)
		}
		if ParseMode(want) != mode {
			t.Errorf("ParseMode(%q) did not round-trip", want)
		}
	}
}

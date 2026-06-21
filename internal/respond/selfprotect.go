package respond

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

// selfTechnique is the ATT&CK technique every self-protection finding maps to:
// an attempt to impair the endpoint's own defences.
var selfTechnique = model.Technique{
	ID:     "T1562.001",
	Name:   "Impair Defenses: Disable or Modify Tools",
	Tactic: "defense-evasion",
}

// TamperReporter receives a self-protection finding (binary tampering or a
// watchdog stall) so the runtime can route it to the same sink as any detection.
type TamperReporter func(*model.Alert)

// tamperAlert builds the alert shared by the self-protection checks. It names no
// process to act on, so RequestedAction pins it to alert-only: a self finding is
// surfaced, never used to kill a pid the responder doesn't actually have.
func tamperAlert(ruleID, name, detail string) *model.Alert {
	return &model.Alert{
		Timestamp:       time.Now().UTC(),
		RuleID:          ruleID,
		RuleName:        name,
		Description:     detail,
		Severity:        model.SeverityCritical,
		Technique:       selfTechnique,
		RiskScore:       90,
		RequestedAction: string(ActionAlertOnly),
		Event:           &model.Event{},
	}
}

// SelfIntegrity guards the agent's own on-disk binary. It records a baseline
// SHA-256 at startup and re-hashes on an interval; a mismatch — the binary was
// swapped or patched underneath the running process — reports a tamper finding.
type SelfIntegrity struct {
	path     string
	interval time.Duration
	baseline string
	report   TamperReporter
	logger   *slog.Logger
	hashFile func(string) (string, error) // seam for tests
}

// NewSelfIntegrity records the baseline hash of path. It fails if the binary
// cannot be read — without a baseline there is nothing to compare against, so the
// caller logs and skips rather than running a check that can never fire.
func NewSelfIntegrity(path string, interval time.Duration, report TamperReporter, logger *slog.Logger) (*SelfIntegrity, error) {
	check := &SelfIntegrity{
		path:     path,
		interval: interval,
		report:   report,
		logger:   logger,
		hashFile: hashFileSHA256,
	}
	baseline, err := check.hashFile(path)
	if err != nil {
		return nil, fmt.Errorf("baseline self-integrity hash: %w", err)
	}
	check.baseline = baseline
	return check, nil
}

// Run re-checks the binary every interval until ctx is cancelled.
func (s *SelfIntegrity) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.check()
		}
	}
}

func (s *SelfIntegrity) check() {
	current, err := s.hashFile(s.path)
	if err != nil {
		// A transient read error (the file briefly replaced mid-upgrade) is not
		// itself proof of tampering; log and try again next tick.
		s.logger.Warn("self-integrity hash failed", "path", s.path, "err", err)
		return
	}
	if current == s.baseline {
		return
	}
	s.logger.Error("self-integrity violation: agent binary changed on disk",
		"path", s.path, "from", shortHash(s.baseline), "to", shortHash(current))
	s.report(tamperAlert("R-SELF-INTEGRITY", "ARGUS binary modified on disk",
		fmt.Sprintf("%s sha256 changed from %s to %s", s.path, shortHash(s.baseline), shortHash(current))))
	// Re-baseline so a persistent change alerts once, not on every tick.
	s.baseline = current
}

// Watchdog is a liveness deadman for the agent's hot path. The pipeline kicks it
// as it processes events; if no kick arrives within timeout the path is wedged (a
// deadlock or a blocked sink), and the watchdog reports once until it recovers.
// It cannot detect a fully frozen process — nothing in-process can — so the
// timeout should sit comfortably above the host's normal quiet periods.
type Watchdog struct {
	timeout  time.Duration
	report   TamperReporter
	logger   *slog.Logger
	lastKick atomic.Int64 // unix nano of the most recent kick
	stalled  atomic.Bool
}

// NewWatchdog starts the deadman primed as alive.
func NewWatchdog(timeout time.Duration, report TamperReporter, logger *slog.Logger) *Watchdog {
	watchdog := &Watchdog{timeout: timeout, report: report, logger: logger}
	watchdog.lastKick.Store(time.Now().UnixNano())
	return watchdog
}

// Kick records a heartbeat. It is safe to call from the hot path: a single atomic
// store, with the recovery log emitted only on the edge back from a stall.
func (w *Watchdog) Kick() {
	w.lastKick.Store(time.Now().UnixNano())
	if w.stalled.CompareAndSwap(true, false) {
		w.logger.Info("watchdog recovered: heartbeat resumed")
	}
}

// Run polls for a missed heartbeat until ctx is cancelled.
func (w *Watchdog) Run(ctx context.Context) {
	ticker := time.NewTicker(w.timeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			w.checkAt(now)
		}
	}
}

func (w *Watchdog) checkAt(now time.Time) {
	idle := now.Sub(time.Unix(0, w.lastKick.Load()))
	if idle < w.timeout {
		return
	}
	if w.stalled.CompareAndSwap(false, true) {
		rounded := idle.Round(time.Second)
		w.logger.Error("watchdog stall: no heartbeat from the pipeline", "idle", rounded)
		w.report(tamperAlert("R-SELF-WATCHDOG", "ARGUS pipeline heartbeat stalled",
			fmt.Sprintf("no event progress for %s — possible deadlock or tampering", rounded)))
	}
}

func hashFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// shortHash trims a hex digest to its first 12 characters for readable logs.
func shortHash(digest string) string {
	const prefix = 12
	if len(digest) <= prefix {
		return digest
	}
	return digest[:prefix]
}

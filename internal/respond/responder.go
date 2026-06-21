package respond

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/argus-edr/argus/internal/model"
)

// signalFunc delivers a signal to a process, given the pid and the comm we
// expect it to still have. It is a field so tests can substitute the syscall.
type signalFunc func(pid uint32, comm string) error

// Responder carries out (or, in dry-run, only records) the response to an alert.
// The mode is held atomically so the control plane can change the posture at
// runtime while the pipeline is handling alerts. maxMode is an immutable local
// ceiling: the control plane can lower the posture but never raise it past what
// the operator pinned, so a compromised or rogue server cannot turn enforcement
// on against a host configured to stay observe-only.
type Responder struct {
	mode      atomic.Int32
	maxMode   Mode
	policy    Policy
	allowlist map[string]bool
	logger    *slog.Logger
	kill      signalFunc
	freeze    signalFunc
	blocker   *networkBlocker
}

// New builds a responder. mode is the starting posture and maxMode the highest
// posture any runtime change (including a control-plane command) may reach; the
// starting posture is clamped to it. allowlistPaths name executables that must
// never be killed or blocked, so a misfire cannot take down the host's own
// plumbing.
func New(mode, maxMode Mode, allowlistPaths []string, logger *slog.Logger) *Responder {
	allowlist := make(map[string]bool, len(allowlistPaths))
	for _, path := range allowlistPaths {
		allowlist[path] = true
	}
	responder := &Responder{
		maxMode:   maxMode,
		policy:    DefaultPolicy(),
		allowlist: allowlist,
		logger:    logger,
		kill:      guardedKill,
		freeze:    guardedFreeze,
		blocker:   newNetworkBlocker(execCommand),
	}
	responder.mode.Store(int32(clampMode(mode, maxMode)))
	return responder
}

// Mode returns the current response posture.
func (r *Responder) Mode() Mode {
	return Mode(r.mode.Load())
}

// SetMode changes the response posture at runtime, the effect of a control-plane
// SET_RESPONSE_MODE command. The request is clamped to the local ceiling, so a
// remote command can lower the posture but never escalate past max_mode. It is
// safe to call while Handle runs.
func (r *Responder) SetMode(requested Mode) {
	mode := clampMode(requested, r.maxMode)
	if mode != requested {
		r.logger.Warn("response mode change clamped to local ceiling",
			"requested", requested, "ceiling", r.maxMode)
	}
	if previous := Mode(r.mode.Swap(int32(mode))); previous != mode {
		r.logger.Warn("response mode changed", "from", previous, "to", mode)
	}
}

// clampMode caps a requested posture at the configured ceiling.
func clampMode(requested, ceiling Mode) Mode {
	if requested > ceiling {
		return ceiling
	}
	return requested
}

// Handle decides and applies the response for one alert, annotating the alert
// with what was done.
func (r *Responder) Handle(alert *model.Alert) {
	mode := r.Mode()
	action := r.policy.Action(alert)
	if action == ActionAlertOnly || mode == ModeOff {
		return
	}
	if r.allowlisted(alert.Event) {
		r.logger.Info("response suppressed by allowlist",
			"rule", alert.RuleID, "executable", alert.Event.Process.Executable)
		return
	}
	if mode == ModeDryRun {
		alert.Response = &model.ResponseRecord{Action: string(action), Result: "dry-run"}
		r.logger.Warn("response withheld (dry-run)",
			"rule", alert.RuleID, "action", action, "pid", alert.Event.Process.PID)
		return
	}

	result := r.execute(action, alert)
	alert.Response = &model.ResponseRecord{Action: string(action), Result: result}
	r.logger.Warn("response executed",
		"rule", alert.RuleID, "action", action, "pid", alert.Event.Process.PID, "result", result)
}

// RequestKill terminates a process by pid for a control-plane KILL_PROCESS
// command. It honours the posture exactly like Handle: off refuses, dry-run only
// records intent, enforce kills. A remote command can never escalate past the
// locally configured mode. comm, when known, guards against PID reuse.
func (r *Responder) RequestKill(pid uint32, comm string) string {
	switch r.Mode() {
	case ModeOff:
		r.logger.Warn("remote kill refused: response mode is off", "pid", pid)
		return "suppressed: response off"
	case ModeDryRun:
		r.logger.Warn("remote kill withheld (dry-run)", "pid", pid)
		return "dry-run"
	default:
		if err := r.kill(pid, comm); err != nil {
			r.logger.Warn("remote kill failed", "pid", pid, "err", err)
			return "failed: " + err.Error()
		}
		r.logger.Warn("remote kill executed", "pid", pid)
		return "success"
	}
}

// RequestNetworkBlock drops egress to ip for a control-plane QUARANTINE command,
// honouring the response posture exactly like RequestKill: off refuses, dry-run
// records intent, enforce installs the nftables drop. A remote command can never
// enforce on an agent whose local posture is off.
func (r *Responder) RequestNetworkBlock(ip string) string {
	switch r.Mode() {
	case ModeOff:
		r.logger.Warn("remote network block refused: response mode is off", "ip", ip)
		return "suppressed: response off"
	case ModeDryRun:
		r.logger.Warn("remote network block withheld (dry-run)", "ip", ip)
		return "dry-run"
	default:
		if err := r.blocker.Block(ip); err != nil {
			r.logger.Warn("remote network block failed", "ip", ip, "err", err)
			return "failed: " + err.Error()
		}
		r.logger.Warn("remote network block executed", "ip", ip)
		return "blocked " + ip
	}
}

func (r *Responder) execute(action Action, alert *model.Alert) string {
	switch action {
	case ActionKill:
		if err := r.kill(alert.Event.Process.PID, alert.Event.Process.Name); err != nil {
			return "failed: " + err.Error()
		}
		return "success"
	case ActionThrottle:
		if err := r.freeze(alert.Event.Process.PID, alert.Event.Process.Name); err != nil {
			return "failed: " + err.Error()
		}
		return "suspended"
	case ActionNetworkBlock, ActionQuarantine:
		ip := alert.Event.Network.DstIP
		if ip == "" {
			return "no destination to block"
		}
		if err := r.blocker.Block(ip); err != nil {
			return "failed: " + err.Error()
		}
		return "blocked " + ip
	default:
		return "noop"
	}
}

func (r *Responder) allowlisted(event *model.Event) bool {
	return r.allowlist[event.Process.Executable]
}

// signalGuarded re-reads /proc/<pid>/comm and refuses if it no longer matches
// what the alert observed — a cheap guard against signalling the wrong process
// after PID reuse — then delivers sig.
func signalGuarded(pid uint32, comm string, sig syscall.Signal) error {
	if comm != "" {
		actual, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			return fmt.Errorf("process %d gone: %w", pid, err)
		}
		if current := strings.TrimSpace(string(actual)); current != comm {
			return fmt.Errorf("pid %d is now %q, not %q: refusing to signal", pid, current, comm)
		}
	}
	return syscall.Kill(int(pid), sig)
}

// guardedKill terminates a process; guardedFreeze suspends it with a reversible
// SIGSTOP (an analyst resumes it with SIGCONT). Both apply the PID-reuse guard.
func guardedKill(pid uint32, comm string) error   { return signalGuarded(pid, comm, syscall.SIGKILL) }
func guardedFreeze(pid uint32, comm string) error { return signalGuarded(pid, comm, syscall.SIGSTOP) }

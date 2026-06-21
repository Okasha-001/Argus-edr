// Package respond turns alerts into actions along a graduated ladder —
// alert-only, throttle, network-block, or kill. It is observe-only unless
// explicitly switched to enforce.
package respond

import "github.com/argus-edr/argus/internal/model"

// Action is a response the agent can take against an alert.
type Action string

const (
	ActionAlertOnly    Action = "alert_only"
	ActionThrottle     Action = "throttle"
	ActionNetworkBlock Action = "network_block"
	ActionQuarantine   Action = "quarantine"
	ActionKill         Action = "kill"
)

// Mode is the global response posture; nothing is enforced below ModeEnforce.
type Mode int

const (
	ModeOff Mode = iota
	ModeDryRun
	ModeEnforce
)

// ParseMode maps a config string to a Mode.
func ParseMode(mode string) Mode {
	switch mode {
	case "dry-run":
		return ModeDryRun
	case "enforce":
		return ModeEnforce
	default:
		return ModeOff
	}
}

// String renders the mode for logs and control-plane command arguments. It is
// the inverse of ParseMode.
func (m Mode) String() string {
	switch m {
	case ModeDryRun:
		return "dry-run"
	case ModeEnforce:
		return "enforce"
	default:
		return "off"
	}
}

// Policy maps an alert to a response along a graduated ladder —
// alert-only → throttle → network-block → kill — by the alert's risk score
// (or, when a rule sets none, a score derived from its severity). Each field is
// the lower bound of a rung. A rule that names an explicit response overrides
// the ladder entirely: the author's stated intent always wins.
type Policy struct {
	ThrottleScore int // at or above: suspend the process (SIGSTOP)
	BlockScore    int // at or above: cut egress (or suspend, with no destination)
	KillScore     int // at or above: terminate the process
}

// Default rung thresholds on the 0–100 risk scale. They line up with the
// severity ladder (medium≈50, high≈75, critical≈90) so a rule that sets no
// explicit risk score still lands on the matching rung.
const (
	defaultThrottleScore = 50
	defaultBlockScore    = 75
	defaultKillScore     = 90
)

// DefaultPolicy returns the graduated ladder used unless an operator tunes it.
func DefaultPolicy() Policy {
	return Policy{
		ThrottleScore: defaultThrottleScore,
		BlockScore:    defaultBlockScore,
		KillScore:     defaultKillScore,
	}
}

// Action picks the response for an alert. An explicit rule response wins;
// otherwise the alert's effective score selects a rung. The block rung needs a
// network destination to act on — without one it falls back to throttle, so the
// chosen action is always something the agent can actually carry out.
func (p Policy) Action(alert *model.Alert) Action {
	if alert.RequestedAction != "" {
		return Action(alert.RequestedAction)
	}
	switch score := effectiveScore(alert); {
	case score >= p.KillScore:
		return ActionKill
	case score >= p.BlockScore:
		if hasNetworkTarget(alert) {
			return ActionNetworkBlock
		}
		return ActionThrottle
	case score >= p.ThrottleScore:
		return ActionThrottle
	default:
		return ActionAlertOnly
	}
}

func hasNetworkTarget(alert *model.Alert) bool {
	return alert.Event != nil && alert.Event.Network.DstIP != ""
}

// effectiveScore is the alert's own risk score, or — when a rule sets none — a
// score derived from its severity so the ladder still has something to rank.
func effectiveScore(alert *model.Alert) int {
	if alert.RiskScore > 0 {
		return alert.RiskScore
	}
	return severityScore(alert.Severity)
}

// severityScore projects the ordered severity onto the same 0–100 scale as risk
// scores, using the canonical rung positions so a scoreless alert still ranks.
func severityScore(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return defaultKillScore
	case model.SeverityHigh:
		return defaultBlockScore
	case model.SeverityMedium:
		return defaultThrottleScore
	default:
		return 0
	}
}

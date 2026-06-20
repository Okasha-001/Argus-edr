// Package respond turns alerts into actions: kill, network-block, quarantine,
// or nothing. It is observe-only unless explicitly switched to enforce.
package respond

import "github.com/argus-edr/argus/internal/model"

// Action is a response the agent can take against an alert.
type Action string

const (
	ActionAlertOnly    Action = "alert_only"
	ActionKill         Action = "kill"
	ActionNetworkBlock Action = "network_block"
	ActionQuarantine   Action = "quarantine"
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

// actionFor decides what to do about an alert: the rule's explicit request wins,
// otherwise the severity drives a conservative graduated default.
func actionFor(alert *model.Alert) Action {
	if alert.RequestedAction != "" {
		return Action(alert.RequestedAction)
	}
	if alert.Severity == model.SeverityCritical {
		return ActionKill
	}
	return ActionAlertOnly
}

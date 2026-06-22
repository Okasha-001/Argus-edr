// Package soar runs response playbooks: when an alert matches a playbook's
// trigger, the engine works its steps — notify, open a case, run a hunt for
// context, or ask an agent to kill or quarantine. It is safe by construction:
// the engine is off until enabled, every playbook defaults to dry-run (steps are
// logged, not executed), the only side-effecting host actions are *requests*
// queued to an agent that still clamps them to its local response.mode (off by
// default), and read-only steps are the only ones that run during a dry-run.
// Three independent gates, all off by default — see docs/SOAR.md and SAFETY.md.
package soar

import (
	"fmt"
	"strings"
	"time"
)

// Playbook modes mirror the response ladder: off (never runs), dry-run (logs what
// it would do, executing only read-only steps), enforce (acts).
const (
	ModeOff     = "off"
	ModeDryRun  = "dry-run"
	ModeEnforce = "enforce"
)

// Step types. notify/open_case/kill_process/quarantine have side effects and are
// simulated in dry-run; run_hunt is read-only and runs in any mode.
const (
	StepNotify     = "notify"
	StepOpenCase   = "open_case"
	StepRunHunt    = "run_hunt"
	StepKill       = "kill_process"
	StepQuarantine = "quarantine"
)

func validMode(mode string) bool {
	return mode == ModeOff || mode == ModeDryRun || mode == ModeEnforce
}

func validStepType(stepType string) bool {
	switch stepType {
	case StepNotify, StepOpenCase, StepRunHunt, StepKill, StepQuarantine:
		return true
	default:
		return false
	}
}

// readOnly reports whether a step has no side effects, so it may run during a
// dry-run. Only hunting (a query against the lake) qualifies.
func readOnly(stepType string) bool { return stepType == StepRunHunt }

// Trigger decides which alerts a playbook reacts to. An empty field is a wildcard
// on that dimension; the conditions that are set must all hold (AND).
type Trigger struct {
	RuleIDs       []string `json:"rule_ids,omitempty"`
	Severities    []string `json:"severities,omitempty"`
	Techniques    []string `json:"techniques,omitempty"`
	MinRisk       int      `json:"min_risk,omitempty"`
	IncidentsOnly bool     `json:"incidents_only,omitempty"`
}

func (t Trigger) matches(alert AlertInfo) bool {
	if t.IncidentsOnly && !alert.IsIncident {
		return false
	}
	if alert.RiskScore < t.MinRisk {
		return false
	}
	if len(t.RuleIDs) > 0 && !contains(t.RuleIDs, alert.RuleID) {
		return false
	}
	if len(t.Severities) > 0 && !containsFold(t.Severities, alert.Severity) {
		return false
	}
	if len(t.Techniques) > 0 && !contains(t.Techniques, alert.TechniqueID) {
		return false
	}
	return true
}

// Step is one action in a playbook. Query is used by run_hunt; the other steps
// draw what they need (pid, host, destination) from the triggering alert.
type Step struct {
	Type  string `json:"type"`
	Query string `json:"query,omitempty"`
}

// Playbook is a trigger plus an ordered list of steps.
type Playbook struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Mode    string    `json:"mode"`
	Trigger Trigger   `json:"trigger"`
	Steps   []Step    `json:"steps"`
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

func (p Playbook) validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("a playbook needs a name")
	}
	if !validMode(p.Mode) {
		return fmt.Errorf("invalid mode %q (want off|dry-run|enforce)", p.Mode)
	}
	if len(p.Steps) == 0 {
		return fmt.Errorf("a playbook needs at least one step")
	}
	for i, step := range p.Steps {
		if !validStepType(step.Type) {
			return fmt.Errorf("step %d: unknown type %q", i, step.Type)
		}
		if step.Type == StepRunHunt && strings.TrimSpace(step.Query) == "" {
			return fmt.Errorf("step %d: run_hunt needs a query", i)
		}
	}
	return nil
}

// AlertInfo is the slice of an alert the engine reasons about — a plain struct so
// soar depends on neither the control-plane store nor the agent wire types.
type AlertInfo struct {
	AlertID       string
	AgentID       string
	Hostname      string
	RuleID        string
	RuleName      string
	Severity      string
	TechniqueID   string
	PID           uint32
	DestinationIP string
	RiskScore     int
	IsIncident    bool
}

// StepOutcome records what one step did (or, in dry-run, would have done).
type StepOutcome struct {
	Type     string `json:"type"`
	Detail   string `json:"detail"`
	Executed bool   `json:"executed"`
	Error    string `json:"error,omitempty"`
}

// RunRecord is one playbook execution against one alert, kept for the console and
// the audit trail.
type RunRecord struct {
	Time       time.Time     `json:"time"`
	PlaybookID string        `json:"playbook_id"`
	Playbook   string        `json:"playbook"`
	AlertID    string        `json:"alert_id"`
	Mode       string        `json:"mode"`
	Outcomes   []StepOutcome `json:"outcomes"`
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsFold(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

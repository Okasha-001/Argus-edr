package soar

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/argus-edr/argus/internal/integrations"
)

// maxRuns bounds the in-memory run history the console reads.
const maxRuns = 200

// CaseOpener opens an investigation case from a playbook step. The control plane
// adapts server/cases to this minimal shape.
type CaseOpener interface {
	OpenCase(title, severity, host string, evidence []string) (string, error)
}

// Commander queues a response command for an agent (e.g. KILL_PROCESS,
// QUARANTINE). The agent still clamps it to its local response.mode, so an
// enforce playbook cannot exceed the host's own posture.
type Commander interface {
	Enqueue(agentID, kind, argument string) bool
}

// Hunter runs an ARQL query for context-gathering steps and returns the hit count.
type Hunter interface {
	Hunt(ctx context.Context, query string) (int, error)
}

// Deps are the engine's collaborators. All are optional: a nil notifier, case
// opener, commander or hunter turns the matching step into a recorded no-op
// rather than an error, so a partially configured platform still runs playbooks.
type Deps struct {
	Store     *PlaybookStore
	Notifier  integrations.Notifier
	Cases     CaseOpener
	Commander Commander
	Hunter    Hunter
	Logger    *slog.Logger
}

// Engine evaluates alerts against the playbook store and runs matching playbooks.
type Engine struct {
	deps    Deps
	logger  *slog.Logger
	enabled bool // global kill switch, off until explicitly enabled

	mu   sync.Mutex
	runs []RunRecord
}

// NewEngine builds an engine. It is disabled until SetEnabled(true): no playbook
// runs while the engine is off, regardless of a playbook's own mode.
func NewEngine(deps Deps) *Engine {
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{deps: deps, logger: logger}
}

// SetEnabled toggles the global switch.
func (e *Engine) SetEnabled(on bool) {
	e.mu.Lock()
	e.enabled = on
	e.mu.Unlock()
}

// SetNotifier swaps the notification destinations, so the control plane can wire
// the configured integrations after the engine is built.
func (e *Engine) SetNotifier(notifier integrations.Notifier) {
	e.deps.Notifier = notifier
}

// Store exposes the playbook store the engine evaluates, for the admin API.
func (e *Engine) Store() *PlaybookStore { return e.deps.Store }

// Enabled reports the global switch.
func (e *Engine) Enabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enabled
}

// Observe runs every matching, non-off playbook against an alert. It is a no-op
// while the engine is disabled.
func (e *Engine) Observe(ctx context.Context, alert AlertInfo) {
	if !e.Enabled() {
		return
	}
	for _, playbook := range e.deps.Store.List() {
		if playbook.Mode == ModeOff || !playbook.Trigger.matches(alert) {
			continue
		}
		e.record(e.runPlaybook(ctx, playbook, alert, false))
	}
}

// Test runs one playbook against an alert forced into dry-run, regardless of the
// playbook's stored mode — the mandatory rehearsal before enforcing.
func (e *Engine) Test(ctx context.Context, playbookID string, alert AlertInfo) (RunRecord, error) {
	playbook, ok := e.deps.Store.Get(playbookID)
	if !ok {
		return RunRecord{}, fmt.Errorf("playbook %q not found", playbookID)
	}
	run := e.runPlaybook(ctx, playbook, alert, true)
	e.record(run)
	return run, nil
}

// runPlaybook executes a playbook's steps. forceDryRun overrides the playbook's
// mode (used by Test); otherwise dry-run is taken from the playbook itself.
func (e *Engine) runPlaybook(ctx context.Context, playbook Playbook, alert AlertInfo, forceDryRun bool) RunRecord {
	dryRun := forceDryRun || playbook.Mode != ModeEnforce
	run := RunRecord{
		Time: time.Now().UTC(), PlaybookID: playbook.ID, Playbook: playbook.Name,
		AlertID: alert.AlertID, Mode: effectiveMode(playbook.Mode, forceDryRun),
	}
	for _, step := range playbook.Steps {
		run.Outcomes = append(run.Outcomes, e.executeStep(ctx, step, alert, dryRun))
	}
	e.logger.Info("playbook run", "playbook", playbook.ID, "alert", alert.AlertID,
		"mode", run.Mode, "steps", len(run.Outcomes))
	return run
}

func effectiveMode(mode string, forceDryRun bool) string {
	if forceDryRun {
		return ModeDryRun
	}
	return mode
}

// executeStep performs one step. A side-effecting step in dry-run is recorded as
// "would …" without acting; a read-only step (run_hunt) runs in any mode.
func (e *Engine) executeStep(ctx context.Context, step Step, alert AlertInfo, dryRun bool) StepOutcome {
	if dryRun && !readOnly(step.Type) {
		return StepOutcome{Type: step.Type, Detail: "would " + describe(step, alert), Executed: false}
	}
	switch step.Type {
	case StepNotify:
		return e.doNotify(ctx, alert)
	case StepOpenCase:
		return e.doOpenCase(alert)
	case StepRunHunt:
		return e.doRunHunt(ctx, step.Query)
	case StepKill:
		return e.doCommand(alert.AgentID, "KILL_PROCESS", strconv.FormatUint(uint64(alert.PID), 10), "kill pid "+strconv.FormatUint(uint64(alert.PID), 10))
	case StepQuarantine:
		return e.doCommand(alert.AgentID, "QUARANTINE", alert.DestinationIP, "quarantine "+alert.DestinationIP)
	default:
		return StepOutcome{Type: step.Type, Detail: "unknown step", Error: "unknown step type"}
	}
}

func (e *Engine) doNotify(ctx context.Context, alert AlertInfo) StepOutcome {
	outcome := StepOutcome{Type: StepNotify, Executed: true}
	if e.deps.Notifier == nil {
		outcome.Executed, outcome.Detail = false, "no notifier configured"
		return outcome
	}
	err := e.deps.Notifier.Notify(ctx, integrations.Notification{
		Title: alert.RuleName, Severity: alert.Severity, Host: alert.Hostname,
		RuleID: alert.RuleID, Technique: alert.TechniqueID,
		Summary: fmt.Sprintf("risk %d on %s", alert.RiskScore, alert.Hostname),
	})
	outcome.Detail = "notified " + e.deps.Notifier.Name()
	if err != nil {
		outcome.Executed, outcome.Error = false, err.Error()
	}
	return outcome
}

func (e *Engine) doOpenCase(alert AlertInfo) StepOutcome {
	outcome := StepOutcome{Type: StepOpenCase, Executed: true}
	if e.deps.Cases == nil {
		outcome.Executed, outcome.Detail = false, "no case store configured"
		return outcome
	}
	title := alert.RuleName
	if title == "" {
		title = "Incident on " + alert.Hostname
	}
	var evidence []string
	if alert.AlertID != "" {
		evidence = []string{alert.AlertID}
	}
	id, err := e.deps.Cases.OpenCase(title, alert.Severity, alert.Hostname, evidence)
	if err != nil {
		outcome.Executed, outcome.Error = false, err.Error()
		return outcome
	}
	outcome.Detail = "opened case " + id
	return outcome
}

func (e *Engine) doRunHunt(ctx context.Context, query string) StepOutcome {
	outcome := StepOutcome{Type: StepRunHunt, Executed: true}
	if e.deps.Hunter == nil {
		outcome.Executed, outcome.Detail = false, "no hunt backend configured"
		return outcome
	}
	count, err := e.deps.Hunter.Hunt(ctx, query)
	if err != nil {
		outcome.Executed, outcome.Error = false, err.Error()
		return outcome
	}
	outcome.Detail = fmt.Sprintf("hunt %q matched %d event(s)", query, count)
	return outcome
}

func (e *Engine) doCommand(agentID, kind, argument, detail string) StepOutcome {
	outcome := StepOutcome{Type: stepForKind(kind), Executed: true, Detail: detail}
	if e.deps.Commander == nil {
		outcome.Executed, outcome.Detail = false, "no commander configured"
		return outcome
	}
	if argument == "" {
		outcome.Executed, outcome.Error = false, "missing target (no pid or destination on the alert)"
		return outcome
	}
	if !e.deps.Commander.Enqueue(agentID, kind, argument) {
		outcome.Executed, outcome.Error = false, "unknown agent "+agentID
	}
	return outcome
}

func stepForKind(kind string) string {
	if kind == "QUARANTINE" {
		return StepQuarantine
	}
	return StepKill
}

// describe renders the human-readable "would …" text for a dry-run step.
func describe(step Step, alert AlertInfo) string {
	switch step.Type {
	case StepNotify:
		return "notify on " + alert.RuleID
	case StepOpenCase:
		return "open a case for " + alert.Hostname
	case StepKill:
		return "ask " + alert.Hostname + " to kill pid " + strconv.FormatUint(uint64(alert.PID), 10)
	case StepQuarantine:
		return "quarantine " + alert.DestinationIP + " on " + alert.Hostname
	default:
		return step.Type
	}
}

func (e *Engine) record(run RunRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.runs = append(e.runs, run)
	if len(e.runs) > maxRuns {
		e.runs = e.runs[len(e.runs)-maxRuns:]
	}
}

// Runs returns the recent run history, newest first.
func (e *Engine) Runs() []RunRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]RunRecord, len(e.runs))
	for i, run := range e.runs {
		out[len(e.runs)-1-i] = run
	}
	return out
}

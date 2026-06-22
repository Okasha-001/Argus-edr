package soar

import (
	"context"
	"testing"

	"github.com/argus-edr/argus/internal/integrations"
)

type fakeNotifier struct{ calls int }

func (f *fakeNotifier) Notify(context.Context, integrations.Notification) error {
	f.calls++
	return nil
}
func (f *fakeNotifier) Name() string { return "fake" }

type fakeCases struct{ opened int }

func (f *fakeCases) OpenCase(string, string, string, []string) (string, error) {
	f.opened++
	return "CASE-0001", nil
}

type fakeCommander struct{ commands []string }

func (f *fakeCommander) Enqueue(agentID, kind, argument string) bool {
	f.commands = append(f.commands, kind+" "+argument)
	return true
}

func deps() (*Engine, *fakeNotifier, *fakeCases, *fakeCommander) {
	notifier, cases, commander := &fakeNotifier{}, &fakeCases{}, &fakeCommander{}
	engine := NewEngine(Deps{Store: NewPlaybookStore(), Notifier: notifier, Cases: cases, Commander: commander})
	return engine, notifier, cases, commander
}

var killchainAlert = AlertInfo{
	AlertID: "a1", AgentID: "agent-1", Hostname: "web-01", RuleID: "R-0007",
	RuleName: "Reverse shell", Severity: "critical", TechniqueID: "T1059", PID: 4123, RiskScore: 90, IsIncident: true,
}

func enforcePlaybook() Playbook {
	return Playbook{
		Name: "Contain reverse shell", Mode: ModeEnforce,
		Trigger: Trigger{Severities: []string{"critical"}},
		Steps:   []Step{{Type: StepNotify}, {Type: StepOpenCase}, {Type: StepKill}},
	}
}

func TestDisabledEngineDoesNothing(t *testing.T) {
	engine, notifier, _, commander := deps()
	if _, err := engine.deps.Store.Create(enforcePlaybook()); err != nil {
		t.Fatal(err)
	}
	engine.Observe(context.Background(), killchainAlert) // engine disabled by default
	if notifier.calls != 0 || len(commander.commands) != 0 {
		t.Error("a disabled engine must not run any step")
	}
}

func TestEnforceRunsSteps(t *testing.T) {
	engine, notifier, cases, commander := deps()
	if _, err := engine.deps.Store.Create(enforcePlaybook()); err != nil {
		t.Fatal(err)
	}
	engine.SetEnabled(true)
	engine.Observe(context.Background(), killchainAlert)

	if notifier.calls != 1 || cases.opened != 1 {
		t.Errorf("notify=%d case=%d, want 1/1", notifier.calls, cases.opened)
	}
	if len(commander.commands) != 1 || commander.commands[0] != "KILL_PROCESS 4123" {
		t.Errorf("commands = %v, want [KILL_PROCESS 4123]", commander.commands)
	}
}

func TestDryRunSimulatesSideEffects(t *testing.T) {
	engine, notifier, cases, commander := deps()
	pb := enforcePlaybook()
	pb.Mode = ModeDryRun
	if _, err := engine.deps.Store.Create(pb); err != nil {
		t.Fatal(err)
	}
	engine.SetEnabled(true)
	engine.Observe(context.Background(), killchainAlert)

	if notifier.calls != 0 || cases.opened != 0 || len(commander.commands) != 0 {
		t.Error("dry-run must not execute side-effecting steps")
	}
	runs := engine.Runs()
	if len(runs) != 1 || len(runs[0].Outcomes) != 3 {
		t.Fatalf("expected one run with three recorded outcomes, got %+v", runs)
	}
	for _, outcome := range runs[0].Outcomes {
		if outcome.Executed {
			t.Errorf("dry-run outcome should not be executed: %+v", outcome)
		}
	}
}

func TestTriggerMustMatch(t *testing.T) {
	engine, notifier, _, _ := deps()
	pb := enforcePlaybook()
	pb.Trigger = Trigger{Severities: []string{"low"}} // won't match a critical alert
	if _, err := engine.deps.Store.Create(pb); err != nil {
		t.Fatal(err)
	}
	engine.SetEnabled(true)
	engine.Observe(context.Background(), killchainAlert)
	if notifier.calls != 0 {
		t.Error("a non-matching trigger must not run the playbook")
	}
}

func TestTestForcesDryRun(t *testing.T) {
	engine, notifier, _, commander := deps()
	created, err := engine.deps.Store.Create(enforcePlaybook()) // enforce mode
	if err != nil {
		t.Fatal(err)
	}
	run, err := engine.Test(context.Background(), created.ID, killchainAlert)
	if err != nil {
		t.Fatal(err)
	}
	if run.Mode != ModeDryRun {
		t.Errorf("Test must force dry-run, got mode %q", run.Mode)
	}
	if notifier.calls != 0 || len(commander.commands) != 0 {
		t.Error("Test must not execute side effects even on an enforce playbook")
	}
}

func TestNewPlaybookDefaultsToDryRun(t *testing.T) {
	store := NewPlaybookStore()
	created, err := store.Create(Playbook{Name: "x", Steps: []Step{{Type: StepNotify}}})
	if err != nil {
		t.Fatal(err)
	}
	if created.Mode != ModeDryRun {
		t.Errorf("a new playbook must default to dry-run, got %q", created.Mode)
	}
}

func TestPlaybookValidation(t *testing.T) {
	store := NewPlaybookStore()
	if _, err := store.Create(Playbook{Name: "no steps", Mode: ModeDryRun}); err == nil {
		t.Error("a playbook with no steps must be rejected")
	}
	if _, err := store.Create(Playbook{Name: "bad step", Mode: ModeDryRun, Steps: []Step{{Type: "nuke"}}}); err == nil {
		t.Error("an unknown step type must be rejected")
	}
}

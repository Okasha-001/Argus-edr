package respond

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

// recordingRunner captures the nftables commands a blocker would run, so tests
// assert behaviour without a privileged host.
type recordingRunner struct {
	mu   sync.Mutex
	cmds [][]string
	err  error
}

func (r *recordingRunner) run(_ context.Context, name string, args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cmds = append(r.cmds, append([]string{name}, args...))
	return r.err
}

func (r *recordingRunner) calls() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cmds
}

func TestBlockInstallsNftDropRule(t *testing.T) {
	runner := &recordingRunner{}
	blocker := newNetworkBlocker(runner.run)

	if err := blocker.Block("203.0.113.5"); err != nil {
		t.Fatalf("block: %v", err)
	}
	cmds := runner.calls()
	if len(cmds) != 3 {
		t.Fatalf("expected table + chain + drop = 3 commands, got %d: %v", len(cmds), cmds)
	}
	if cmds[0][2] != "table" || cmds[1][2] != "chain" {
		t.Errorf("expected table then chain, got %v / %v", cmds[0], cmds[1])
	}
	drop := cmds[2]
	if drop[len(drop)-1] != "drop" || drop[len(drop)-2] != "203.0.113.5" || drop[len(drop)-3] != "daddr" {
		t.Errorf("unexpected drop rule: %v", drop)
	}
	if drop[len(drop)-4] != "ip" {
		t.Errorf("IPv4 should use the ip family, got %v", drop)
	}
}

func TestBlockIsIdempotent(t *testing.T) {
	runner := &recordingRunner{}
	blocker := newNetworkBlocker(runner.run)
	for i := 0; i < 3; i++ {
		if err := blocker.Block("203.0.113.5"); err != nil {
			t.Fatalf("block: %v", err)
		}
	}
	if got := len(runner.calls()); got != 3 {
		t.Errorf("repeated blocks of one ip should not add rules: got %d commands", got)
	}
}

func TestBlockIPv6UsesIp6Family(t *testing.T) {
	runner := &recordingRunner{}
	blocker := newNetworkBlocker(runner.run)
	if err := blocker.Block("2001:db8::1"); err != nil {
		t.Fatalf("block: %v", err)
	}
	drop := runner.calls()[2]
	if drop[len(drop)-4] != "ip6" {
		t.Errorf("IPv6 should use the ip6 family, got %v", drop)
	}
}

func TestBlockRejectsInvalidIP(t *testing.T) {
	runner := &recordingRunner{}
	blocker := newNetworkBlocker(runner.run)
	if err := blocker.Block("not-an-ip"); err == nil {
		t.Fatal("expected an error for an invalid ip")
	}
	if len(runner.calls()) != 0 {
		t.Error("an invalid ip must not run any command")
	}
}

func TestBlockSurfacesRunnerError(t *testing.T) {
	runner := &recordingRunner{err: errors.New("nft: permission denied")}
	blocker := newNetworkBlocker(runner.run)
	if err := blocker.Block("203.0.113.5"); err == nil {
		t.Fatal("expected the nft failure to surface")
	}
}

func blockingResponder(mode Mode, runner *recordingRunner) *Responder {
	responder := New(mode, ModeEnforce, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	responder.blocker = newNetworkBlocker(runner.run)
	return responder
}

func TestRequestNetworkBlockHonoursMode(t *testing.T) {
	runner := &recordingRunner{}
	responder := blockingResponder(ModeOff, runner)
	if got := responder.RequestNetworkBlock("203.0.113.5"); got != "suppressed: response off" {
		t.Errorf("off result = %q", got)
	}

	responder.SetMode(ModeDryRun)
	if got := responder.RequestNetworkBlock("203.0.113.5"); got != "dry-run" {
		t.Errorf("dry-run result = %q", got)
	}
	if len(runner.calls()) != 0 {
		t.Fatal("off and dry-run must not touch the firewall")
	}

	responder.SetMode(ModeEnforce)
	if got := responder.RequestNetworkBlock("203.0.113.5"); got != "blocked 203.0.113.5" {
		t.Errorf("enforce result = %q", got)
	}
	if len(runner.calls()) == 0 {
		t.Error("enforce mode should install the drop rule")
	}
}

func TestRuleDrivenNetworkBlock(t *testing.T) {
	runner := &recordingRunner{}
	responder := blockingResponder(ModeEnforce, runner)
	alert := &model.Alert{
		RuleID:          "R-0008",
		Severity:        model.SeverityHigh,
		RequestedAction: string(ActionNetworkBlock),
		Event:           &model.Event{Network: model.Network{DstIP: "198.51.100.9"}},
	}
	responder.Handle(alert)
	if alert.Response == nil || alert.Response.Result != "blocked 198.51.100.9" {
		t.Fatalf("expected the alert to record a block, got %+v", alert.Response)
	}
}

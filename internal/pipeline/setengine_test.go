package pipeline

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/model"
)

// gatedSource emits one event, waits for release, emits a second, then ends. It
// lets the test swap the engine exactly between the two events.
type gatedSource struct {
	first, second *model.Event
	release       <-chan struct{}
}

func (s *gatedSource) Run(ctx context.Context, out chan<- *model.Event) error {
	out <- s.first
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.release:
	}
	out <- s.second
	return nil
}

func (s *gatedSource) Close() error { return nil }

type countingSink struct {
	mu        sync.Mutex
	alerts    int
	firstSeen chan struct{}
	once      sync.Once
}

func (s *countingSink) WriteEvent(*model.Event) error {
	s.once.Do(func() { close(s.firstSeen) })
	return nil
}

func (s *countingSink) WriteAlert(*model.Alert) error {
	s.mu.Lock()
	s.alerts++
	s.mu.Unlock()
	return nil
}

func (s *countingSink) WriteIncident(*model.Incident) error { return nil }
func (s *countingSink) Flush() error                        { return nil }
func (s *countingSink) Close() error                        { return nil }

func loadTestEngine(t *testing.T, action string) *detect.Engine {
	t.Helper()
	dir := t.TempDir()
	rule := fmt.Sprintf(`- id: R-1
  name: match %[1]s
  severity: high
  technique: { id: T1, name: n, tactic: execution }
  match:
    all:
      - { field: event.type, op: eq, value: %[1]s }
`, action)
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := detect.LoadDir(dir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return detect.NewEngine(rules, nil)
}

func TestSetEngineSwapsRulesMidStream(t *testing.T) {
	matchesNothing := loadTestEngine(t, "exit")
	matchesExec := loadTestEngine(t, "exec")
	release := make(chan struct{})
	sink := &countingSink{firstSeen: make(chan struct{})}
	execEvent := func() *model.Event {
		return &model.Event{Type: model.EventExec, Action: "exec", Process: model.Process{PID: 1, Name: "x"}}
	}

	agent := New(Params{
		Source: &gatedSource{first: execEvent(), second: execEvent(), release: release},
		Engine: matchesNothing,
		Sink:   sink,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	done := make(chan error, 1)
	go func() { done <- agent.Run(context.Background()) }()

	<-sink.firstSeen // first event evaluated under the engine that matches nothing
	agent.SetEngine(matchesExec)
	close(release) // second event evaluated under the swapped-in engine

	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.alerts != 1 {
		t.Fatalf("alerts = %d, want 1 (none before the swap, one after)", sink.alerts)
	}
}

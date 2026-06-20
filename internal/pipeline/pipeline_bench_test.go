package pipeline

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/model"
)

// benchSource emits the same event n times, then ends — enough to measure
// steady-state per-event pipeline cost without source-side noise.
type benchSource struct {
	event *model.Event
	n     int
}

func (s *benchSource) Run(ctx context.Context, out chan<- *model.Event) error {
	for i := 0; i < s.n; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- s.event:
		}
	}
	return nil
}

func (s *benchSource) Close() error { return nil }

type benchNopSink struct{}

func (benchNopSink) WriteEvent(*model.Event) error       { return nil }
func (benchNopSink) WriteAlert(*model.Alert) error       { return nil }
func (benchNopSink) WriteIncident(*model.Incident) error { return nil }
func (benchNopSink) Flush() error                        { return nil }
func (benchNopSink) Close() error                        { return nil }

// BenchmarkPipelineThroughput measures end-to-end per-event cost through the
// ordered consumer: evaluate against the full ruleset and hand off to a sink.
// The event matches no rule, so the figure is the steady-state floor.
func BenchmarkPipelineThroughput(b *testing.B) {
	rules, err := detect.LoadDir("../../rules")
	if err != nil {
		b.Fatalf("load rules: %v", err)
	}
	event := &model.Event{
		Type:    model.EventExec,
		Action:  "exec",
		Process: model.Process{PID: 1000, Name: "nginx", Executable: "/usr/sbin/nginx"},
	}
	agent := New(Params{
		Source: &benchSource{event: event, n: b.N},
		Engine: detect.NewEngine(rules, nil),
		Sink:   benchNopSink{},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	b.ReportAllocs()
	b.ResetTimer()
	if err := agent.Run(context.Background()); err != nil {
		b.Fatalf("run: %v", err)
	}
}

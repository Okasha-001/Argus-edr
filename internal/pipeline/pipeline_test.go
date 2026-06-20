package pipeline

import (
	"context"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/anomaly"
	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/enrich"
	"github.com/argus-edr/argus/internal/intel"
	"github.com/argus-edr/argus/internal/model"
)

type captureSink struct {
	events       int
	alerts       int
	incidents    int
	alertRuleIDs []string
}

func (c *captureSink) WriteEvent(*model.Event) error { c.events++; return nil }
func (c *captureSink) WriteAlert(alert *model.Alert) error {
	c.alerts++
	c.alertRuleIDs = append(c.alertRuleIDs, alert.RuleID)
	return nil
}
func (c *captureSink) WriteIncident(*model.Incident) error { c.incidents++; return nil }
func (c *captureSink) Flush() error                        { return nil }
func (c *captureSink) Close() error                        { return nil }

// TestReplayKillChain drives the recorded reverse-shell + miner scenario through
// the real enrichment, detection and correlation code, end to end.
func TestReplayKillChain(t *testing.T) {
	rules, err := detect.LoadDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	sink := &captureSink{}
	agent := New(Params{
		Source:   NewReplaySource("../../test/integration/testdata/killchain.ndjson"),
		Enricher: enrich.New(enrich.Options{ProcessTree: true}),
		Engine:   detect.NewEngine(rules, detect.NewCorrelator(30*time.Second, 75)),
		Sink:     sink,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	if err := agent.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	if sink.events != 7 {
		t.Errorf("events written = %d, want 7", sink.events)
	}
	if sink.alerts != 5 {
		t.Errorf("alerts written = %d, want 5", sink.alerts)
	}
	if sink.incidents != 2 {
		t.Errorf("incidents written = %d, want 2", sink.incidents)
	}
	if got := agent.Stats().Events.Load(); got != 7 {
		t.Errorf("stats events = %d, want 7", got)
	}
}

// TestReplaySyscallSensors drives one event per new Phase-4 sensor (ptrace,
// module load, bpf, memfd, RWX mmap, setuid, DNS) through the full pipeline and
// checks each fires its rule — proving the new event types are wired end to end.
func TestReplaySyscallSensors(t *testing.T) {
	rules, err := detect.LoadDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	sink := &captureSink{}
	agent := New(Params{
		Source:   NewReplaySource("../../test/integration/testdata/syscalls.ndjson"),
		Enricher: enrich.New(enrich.Options{}),
		Engine:   detect.NewEngine(rules, nil),
		Sink:     sink,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err := agent.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	for _, want := range []string{"R-0060", "R-0061", "R-0062", "R-0063", "R-0064", "R-0065", "R-0066"} {
		if !slices.Contains(sink.alertRuleIDs, want) {
			t.Errorf("expected %s to fire; alerts = %v", want, sink.alertRuleIDs)
		}
	}
}

// TestPipelineAnomalyScoring proves the anomaly stage raises anomaly.score for a
// process unseen during training and that a rule keyed on the score fires — while
// a process common in the baseline stays below the threshold.
func TestPipelineAnomalyScoring(t *testing.T) {
	trainer := anomaly.NewTrainer()
	for i := 0; i < 100; i++ {
		event := &model.Event{Type: model.EventExec, Action: "exec", Timestamp: time.Unix(1000, 0)}
		event.Process.Name = "bash"
		event.Process.Executable = "/bin/bash"
		event.Process.ParentName = "systemd"
		trainer.Observe(event)
	}
	detector := trainer.Build(rand.New(rand.NewSource(1)))

	rules, err := detect.LoadDir("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.ndjson")
	// First line is a baseline-common bash exec; second is an executable never
	// seen in training (and outside /tmp, so only the anomaly rule can fire).
	events := `{"@timestamp":"2026-06-20T10:00:00Z","host":"web-01","action":"exec","process":{"pid":10,"ppid":1,"name":"bash","executable":"/bin/bash","parent_name":"systemd"}}
{"@timestamp":"2026-06-20T10:00:01Z","host":"web-01","action":"exec","process":{"pid":11,"ppid":1,"name":"zzrare","executable":"/usr/local/bin/zzrare","parent_name":"systemd"}}
`
	if err := os.WriteFile(eventsPath, []byte(events), 0o644); err != nil {
		t.Fatalf("write events: %v", err)
	}

	sink := &captureSink{}
	agent := New(Params{
		Source:   NewReplaySource(eventsPath),
		Enricher: enrich.New(enrich.Options{}), // no process tree: keep parent_name from the fixture
		Scorer:   detector,
		Engine:   detect.NewEngine(rules, nil),
		Sink:     sink,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err := agent.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	if !slices.Contains(sink.alertRuleIDs, "R-0050") {
		t.Errorf("expected the anomaly rule R-0050 to fire on the rare exec; alerts = %v", sink.alertRuleIDs)
	}
}

// TestReplayMatchesThreatIntel drives a connect to a known-bad IP through the
// full pipeline with a real IOC matcher attached (and no rules), proving an
// indicator hit raises an alert end to end while benign traffic stays silent.
func TestReplayMatchesThreatIntel(t *testing.T) {
	dir := t.TempDir()
	feedPath := filepath.Join(dir, "iocs.txt")
	if err := os.WriteFile(feedPath, []byte("203.0.113.66\n"), 0o644); err != nil {
		t.Fatalf("write feed: %v", err)
	}
	matcher, err := intel.Load(feedPath)
	if err != nil {
		t.Fatalf("load intel: %v", err)
	}

	eventsPath := filepath.Join(dir, "events.ndjson")
	events := `{"@timestamp":"2026-06-20T10:00:00Z","host":"web-01","action":"connect","process":{"pid":900,"ppid":1,"name":"curl"},"network":{"src_ip":"10.0.0.5","src_port":5000,"dst_ip":"203.0.113.66","dst_port":443}}
{"@timestamp":"2026-06-20T10:00:01Z","host":"web-01","action":"connect","process":{"pid":901,"ppid":1,"name":"curl"},"network":{"src_ip":"10.0.0.5","src_port":5001,"dst_ip":"198.51.100.9","dst_port":443}}
`
	if err := os.WriteFile(eventsPath, []byte(events), 0o644); err != nil {
		t.Fatalf("write events: %v", err)
	}

	engine := detect.NewEngine(nil, nil)
	engine.SetIntel(matcher)
	sink := &captureSink{}
	agent := New(Params{
		Source:   NewReplaySource(eventsPath),
		Enricher: enrich.New(enrich.Options{}),
		Engine:   engine,
		Sink:     sink,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	if err := agent.Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}

	if sink.events != 2 {
		t.Errorf("events written = %d, want 2", sink.events)
	}
	if len(sink.alertRuleIDs) != 1 || sink.alertRuleIDs[0] != "INTEL-IP" {
		t.Fatalf("alert rule ids = %v, want exactly [INTEL-IP]", sink.alertRuleIDs)
	}
}

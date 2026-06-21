package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/config"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestObservabilityDisabledYieldsNilObserver(t *testing.T) {
	guard := buildObservability(config.Defaults(), discardLogger()) // metrics off by default
	if guard != nil {
		t.Fatal("expected nil observability when metrics are disabled")
	}
	if guard.observer() != nil {
		t.Error("a nil observability must yield a nil pipeline observer")
	}
	guard.start(t.Context(), nil) // must be a safe no-op on the nil receiver
}

func TestAgentMetricsRecordAndExpose(t *testing.T) {
	cfg := config.Defaults()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Address = "127.0.0.1:0"

	guard := buildObservability(cfg, discardLogger())
	if guard == nil {
		t.Fatal("expected observability when metrics are enabled")
	}
	observer := guard.observer()
	observer.ObserveEvent()
	observer.ObserveEvent()
	observer.ObserveAlert()
	observer.ObserveIncident()
	observer.ObserveStage("detect", 2*time.Millisecond)
	guard.ringDrops.Set(7)

	rec := httptest.NewRecorder()
	guard.server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	for _, want := range []string{
		"argus_events_total 2",
		"argus_alerts_total 1",
		"argus_incidents_total 1",
		"argus_ring_drops_total 7",
		`argus_pipeline_stage_seconds_count{stage="detect"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output missing %q in:\n%s", want, body)
		}
	}
}

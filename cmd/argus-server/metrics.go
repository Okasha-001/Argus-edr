package main

import (
	"github.com/argus-edr/argus/internal/metrics"
	"github.com/argus-edr/argus/server/store"
)

// serverMetrics is the control plane's Prometheus exposition: counters bumped as
// alerts and signals arrive, and a gauge that reads the live agent count from the
// store at scrape time.
type serverMetrics struct {
	registry *metrics.Registry
	alerts   *metrics.Counter
	signals  *metrics.Counter
}

func newServerMetrics(backing store.Store) *serverMetrics {
	registry := metrics.New()
	collector := &serverMetrics{
		registry: registry,
		alerts:   registry.Counter("argus_server_alerts_total", "Alerts received from agents."),
		signals:  registry.Counter("argus_server_signals_total", "Cross-host correlation signals raised."),
	}
	registry.GaugeFunc("argus_server_agents", "Agents currently enrolled.",
		func() float64 { return float64(len(backing.List())) })
	return collector
}

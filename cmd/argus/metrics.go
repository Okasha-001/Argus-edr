package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/argus-edr/argus/internal/config"
	"github.com/argus-edr/argus/internal/metrics"
	"github.com/argus-edr/argus/internal/pipeline"
)

const (
	metricsSampleInterval = 10 * time.Second
	metricsShutdownGrace  = 5 * time.Second
)

// agentMetrics implements pipeline.Observer over the registry instruments. It is
// touched only by the single pipeline consumer, so the atomic metric stores are
// all the synchronisation it needs.
type agentMetrics struct {
	events    *metrics.Counter
	alerts    *metrics.Counter
	incidents *metrics.Counter
	stages    *metrics.HistogramVec
}

func (m *agentMetrics) ObserveEvent()    { m.events.Inc() }
func (m *agentMetrics) ObserveAlert()    { m.alerts.Inc() }
func (m *agentMetrics) ObserveIncident() { m.incidents.Inc() }

func (m *agentMetrics) ObserveStage(stage string, elapsed time.Duration) {
	m.stages.WithLabelValue(stage).Observe(elapsed.Seconds())
}

// observability owns the agent's metrics registry, the /metrics HTTP server, and
// the goroutine that samples kernel-side counters (ring-buffer loss).
type observability struct {
	agent     *agentMetrics
	ringDrops *metrics.Gauge
	server    *http.Server
	logger    *slog.Logger
}

// buildObservability constructs the registry and HTTP server, or returns nil when
// metrics are disabled — observer() then yields a nil pipeline.Observer and the
// pipeline pays nothing.
func buildObservability(cfg config.Config, logger *slog.Logger) *observability {
	if !cfg.Metrics.Enabled {
		return nil
	}
	registry := metrics.New()
	guard := &observability{
		agent: &agentMetrics{
			events:    registry.Counter("argus_events_total", "Events processed by the pipeline."),
			alerts:    registry.Counter("argus_alerts_total", "Alerts raised."),
			incidents: registry.Counter("argus_incidents_total", "Incidents opened."),
			stages: registry.HistogramVec("argus_pipeline_stage_seconds",
				"Per-stage pipeline processing latency in seconds.", "stage", metrics.DefaultLatencyBuckets),
		},
		ringDrops: registry.Gauge("argus_ring_drops_total",
			"Events the kernel dropped because the ring buffer was full."),
		logger: logger,
	}
	routes := http.NewServeMux()
	routes.Handle("GET /metrics", registry.Handler())
	guard.server = &http.Server{
		Addr:              cfg.Metrics.Address,
		Handler:           routes,
		ReadHeaderTimeout: metricsShutdownGrace,
	}
	return guard
}

// observer is the pipeline hook; nil when metrics are off.
func (o *observability) observer() pipeline.Observer {
	if o == nil {
		return nil
	}
	return o.agent
}

// start serves /metrics and samples kernel counters until ctx is cancelled.
func (o *observability) start(ctx context.Context, source pipeline.Source) {
	if o == nil {
		return
	}
	go o.serve(ctx)
	go o.sample(ctx, source)
}

func (o *observability) serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), metricsShutdownGrace)
		defer cancel()
		_ = o.server.Shutdown(shutdownCtx)
	}()
	o.logger.Info("metrics endpoint listening", "address", o.server.Addr)
	if err := o.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		o.logger.Error("metrics endpoint failed", "err", err)
	}
}

// ringDropReader is the optional capability a source exposes to report kernel
// ring-buffer loss; the live eBPF source has it, the replay source does not.
type ringDropReader interface{ RingDrops() uint64 }

func (o *observability) sample(ctx context.Context, source pipeline.Source) {
	reader, ok := source.(ringDropReader)
	if !ok {
		return
	}
	ticker := time.NewTicker(metricsSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.ringDrops.Set(float64(reader.RingDrops()))
		}
	}
}

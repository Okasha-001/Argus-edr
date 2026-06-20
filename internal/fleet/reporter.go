package fleet

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/argus-edr/argus/internal/fleet/fleetpb"
)

// reportReconnectDelay is how long Run waits before reopening a broken stream,
// trading prompt recovery against hammering an unreachable server.
const reportReconnectDelay = 5 * time.Second

// flushTimeout bounds the best-effort drain of queued reports at shutdown.
const flushTimeout = 3 * time.Second

const defaultReportQueue = 1024

// Reporter pushes alerts to the control plane over the ReportAlerts client
// stream. It decouples the pipeline from the network with a buffered queue:
// Enqueue never blocks, so a slow or down control plane can never stall
// detection. When the queue is full, reports are dropped and counted rather than
// applying back-pressure to the hot path.
type Reporter struct {
	client  *Client
	queue   chan *fleetpb.AlertReport
	logger  *slog.Logger
	dropped atomic.Uint64
}

// NewReporter creates a Reporter with the given queue depth (a non-positive
// value uses the default).
func (c *Client) NewReporter(queueDepth int, logger *slog.Logger) *Reporter {
	if queueDepth <= 0 {
		queueDepth = defaultReportQueue
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Reporter{
		client: c,
		queue:  make(chan *fleetpb.AlertReport, queueDepth),
		logger: logger,
	}
}

// Enqueue offers a report to the stream. It never blocks; if the queue is full
// the report is dropped and the running drop count logged.
func (r *Reporter) Enqueue(report *fleetpb.AlertReport) {
	select {
	case r.queue <- report:
	default:
		r.logger.Warn("fleet report dropped: queue full", "dropped_total", r.dropped.Add(1))
	}
}

// Dropped returns how many reports have been dropped because the queue was full.
func (r *Reporter) Dropped() uint64 {
	return r.dropped.Load()
}

// Run pumps queued reports to the server until ctx is cancelled, reopening the
// stream after a delay if it breaks. On shutdown it makes a best-effort attempt
// to flush whatever is still queued before returning.
func (r *Reporter) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		if err := r.pump(ctx); err != nil && ctx.Err() == nil {
			r.logger.Warn("fleet report stream broke, reconnecting",
				"err", err, "retry_in", reportReconnectDelay)
			sleep(ctx, reportReconnectDelay)
		}
	}
	r.flushRemaining()
	return ctx.Err()
}

func (r *Reporter) pump(ctx context.Context) error {
	stream, err := r.client.rpc.ReportAlerts(ctx)
	if err != nil {
		return fmt.Errorf("open report stream: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case report := <-r.queue:
			if err := stream.Send(report); err != nil {
				return fmt.Errorf("send report: %w", err)
			}
		}
	}
}

// flushRemaining drains any still-queued reports through a fresh, short-lived
// stream. The pump's stream is bound to the (now cancelled) run context, so a
// separate context is needed to push the backlog out on a clean shutdown. By the
// time this runs the pipeline has stopped, so the queue no longer grows.
func (r *Reporter) flushRemaining() {
	if len(r.queue) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	stream, err := r.client.rpc.ReportAlerts(ctx)
	if err != nil {
		return
	}
	for {
		select {
		case report := <-r.queue:
			if err := stream.Send(report); err != nil {
				return
			}
		default:
			_, _ = stream.CloseAndRecv()
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

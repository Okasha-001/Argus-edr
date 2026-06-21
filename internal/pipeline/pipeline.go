package pipeline

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/enrich"
	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/output"
	"github.com/argus-edr/argus/internal/respond"
)

const defaultBufferSize = 4096

// Stats are the running counters surfaced in logs and (later) metrics.
type Stats struct {
	Events    atomic.Uint64
	Alerts    atomic.Uint64
	Incidents atomic.Uint64
}

// Scorer assigns an event an anomaly score in [0,1]. The anomaly package's
// Detector satisfies it; the pipeline depends on the behaviour, not the package,
// so it never imports the scorer's implementation.
type Scorer interface {
	Score(*model.Event) float64
}

// Params are the collaborators a Pipeline drives. Enricher, Responder and Scorer
// may be nil; Source, Engine, Sink and Logger are required.
type Params struct {
	Source     Source
	Enricher   *enrich.Enricher
	Scorer     Scorer
	Engine     *detect.Engine
	Responder  *respond.Responder
	Sink       output.Sink
	Logger     *slog.Logger
	BufferSize int
	// Heartbeat, when set, is called once per processed event so a watchdog can
	// observe that the hot path is making progress.
	Heartbeat func()
}

// Pipeline reads from the source and runs each event through the stages. The
// engine is held in an atomic pointer so the control plane can swap in a freshly
// loaded ruleset without locking the hot path or restarting the agent.
type Pipeline struct {
	params Params
	engine atomic.Pointer[detect.Engine]
	stats  Stats
}

// New builds a pipeline from its collaborators.
func New(params Params) *Pipeline {
	if params.BufferSize <= 0 {
		params.BufferSize = defaultBufferSize
	}
	pipeline := &Pipeline{params: params}
	pipeline.engine.Store(params.Engine)
	return pipeline
}

// Stats returns the live counters.
func (p *Pipeline) Stats() *Stats {
	return &p.stats
}

// SetEngine atomically swaps the detection engine, the effect of a control-plane
// rule update. In-flight events finish on the previous engine; subsequent events
// use the new one.
func (p *Pipeline) SetEngine(engine *detect.Engine) {
	p.engine.Store(engine)
}

// Run drives the pipeline until the source ends or ctx is cancelled. The source
// runs in its own goroutine, decoupled by a buffered channel that absorbs
// bursts; the single consumer keeps event ordering intact.
func (p *Pipeline) Run(ctx context.Context) error {
	events := make(chan *model.Event, p.params.BufferSize)
	sourceErr := make(chan error, 1)
	go func() {
		err := p.params.Source.Run(ctx, events)
		close(events)
		sourceErr <- err
	}()

	for event := range events {
		p.process(event)
	}

	if err := p.params.Sink.Flush(); err != nil {
		p.params.Logger.Error("sink flush failed", "err", err)
	}

	err := <-sourceErr
	if ctx.Err() != nil {
		return nil // cancellation is a clean stop, not a failure
	}
	return err
}

func (p *Pipeline) process(event *model.Event) {
	p.stats.Events.Add(1)
	if p.params.Heartbeat != nil {
		p.params.Heartbeat()
	}

	if p.params.Enricher != nil {
		p.params.Enricher.Enrich(event)
	}
	// Anomaly scoring runs after enrichment (so it sees the process tree) and
	// before detection (so rules can match on anomaly.score).
	if p.params.Scorer != nil {
		event.AnomalyScore = p.params.Scorer.Score(event)
	}
	result := p.engine.Load().Evaluate(event)

	if p.params.Responder != nil {
		for _, alert := range result.Alerts {
			p.params.Responder.Handle(alert)
		}
	}

	if err := p.params.Sink.WriteEvent(event); err != nil {
		p.params.Logger.Error("write event", "err", err)
	}
	p.emitAlerts(result.Alerts)
	p.emitIncident(result.Incident)
}

func (p *Pipeline) emitAlerts(alerts []*model.Alert) {
	for _, alert := range alerts {
		p.stats.Alerts.Add(1)
		if err := p.params.Sink.WriteAlert(alert); err != nil {
			p.params.Logger.Error("write alert", "err", err)
		}
		p.params.Logger.Warn("alert",
			"rule", alert.RuleID, "name", alert.RuleName, "severity", alert.Severity.String(),
			"technique", alert.Technique.ID, "pid", alert.Event.Process.PID, "process", alert.Event.Process.Name)
	}
}

func (p *Pipeline) emitIncident(incident *model.Incident) {
	if incident == nil {
		return
	}
	p.stats.Incidents.Add(1)
	if err := p.params.Sink.WriteIncident(incident); err != nil {
		p.params.Logger.Error("write incident", "err", err)
	}
	p.params.Logger.Warn("incident opened",
		"id", incident.ID, "risk", incident.RiskScore, "techniques", incident.Techniques)
}

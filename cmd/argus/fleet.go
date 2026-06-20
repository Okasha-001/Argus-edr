package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/argus-edr/argus/internal/config"
	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/fleet"
	"github.com/argus-edr/argus/internal/intel"
	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/pipeline"
	"github.com/argus-edr/argus/internal/respond"
	"github.com/argus-edr/argus/internal/version"
)

const (
	enrollTimeout = 10 * time.Second
	rpcTimeout    = 10 * time.Second
)

// fleetConn is the agent's live connection to the control plane: the client, the
// alert reporter, and the sink that feeds the reporter from the pipeline. It is
// established before the pipeline so its sink can join the agent's outputs.
type fleetConn struct {
	client       *fleet.Client
	reporter     *fleet.Reporter
	sink         *fleetSink
	agentID      string
	rulesVersion string
}

// connectFleet dials and enrolls with the control plane. The returned sink must
// be added to the agent's outputs, and a fleetRunner started once the pipeline
// exists.
func connectFleet(cfg config.Config, logger *slog.Logger) (*fleetConn, error) {
	client, err := fleet.Dial(fleet.ClientConfig{
		ServerAddress:   cfg.Fleet.ServerAddress,
		ServerName:      cfg.Fleet.ServerName,
		CAFile:          cfg.Fleet.CAFile,
		CertFile:        cfg.Fleet.CertFile,
		KeyFile:         cfg.Fleet.KeyFile,
		Hostname:        cfg.Agent.Hostname,
		AgentVersion:    version.Version,
		Kernel:          kernelRelease(),
		EnrollmentToken: cfg.Fleet.EnrollmentToken,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), enrollTimeout)
	defer cancel()
	result, err := client.Enroll(ctx)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	logger.Info("enrolled with control plane",
		"server", cfg.Fleet.ServerAddress, "agent", result.AgentID, "rules_version", result.RulesVersion)

	reporter := client.NewReporter(0, logger)
	return &fleetConn{
		client:       client,
		reporter:     reporter,
		sink:         &fleetSink{reporter: reporter, agentID: result.AgentID, hostname: cfg.Agent.Hostname},
		agentID:      result.AgentID,
		rulesVersion: result.RulesVersion,
	}, nil
}

// fleetSink forwards alerts and incidents to the control plane via the reporter.
// Raw events are deliberately not shipped upstream — that volume belongs in the
// agent's local outputs (file/Loki), not on the fleet bus.
type fleetSink struct {
	reporter *fleet.Reporter
	agentID  string
	hostname string
}

func (s *fleetSink) WriteEvent(*model.Event) error { return nil }

func (s *fleetSink) WriteAlert(alert *model.Alert) error {
	s.reporter.Enqueue(fleet.AlertReportFromAlert(s.agentID, s.hostname, alert))
	return nil
}

func (s *fleetSink) WriteIncident(incident *model.Incident) error {
	s.reporter.Enqueue(fleet.AlertReportFromIncident(s.agentID, s.hostname, incident))
	return nil
}

func (s *fleetSink) Flush() error { return nil }
func (s *fleetSink) Close() error { return nil }

// fleetRunner heartbeats the control plane, applies pushed commands, and keeps
// the local ruleset in sync. It shares the pipeline's correlator across rule
// reloads so per-process correlation state survives an update.
type fleetRunner struct {
	conn       *fleetConn
	pipeline   *pipeline.Pipeline
	responder  *respond.Responder
	correlator *detect.Correlator
	intel      *intel.Matcher
	rulesDir   string
	interval   time.Duration
	logger     *slog.Logger
}

func newFleetRunner(conn *fleetConn, agent *pipeline.Pipeline, responder *respond.Responder,
	correlator *detect.Correlator, matcher *intel.Matcher, cfg config.Config, logger *slog.Logger) *fleetRunner {
	return &fleetRunner{
		conn:       conn,
		pipeline:   agent,
		responder:  responder,
		correlator: correlator,
		intel:      matcher,
		rulesDir:   cfg.Detection.RulesDir,
		interval:   time.Duration(cfg.Fleet.HeartbeatSeconds) * time.Second,
		logger:     logger,
	}
}

// Run drives the heartbeat loop until ctx is cancelled, then drains the reporter
// and closes the connection.
func (f *fleetRunner) Run(ctx context.Context) {
	reporterDone := make(chan struct{})
	go func() {
		defer close(reporterDone)
		_ = f.conn.reporter.Run(ctx)
	}()

	// Converge the ruleset immediately so a freshly enrolled agent does not run a
	// full heartbeat interval on stale rules.
	f.syncRules(ctx)

	ticker := time.NewTicker(f.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			<-reporterDone
			_ = f.conn.client.Close()
			return
		case <-ticker.C:
			f.heartbeat(ctx)
		}
	}
}

func (f *fleetRunner) heartbeat(ctx context.Context) {
	stats := f.pipeline.Stats()
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	commands, err := f.conn.client.Heartbeat(ctx, f.conn.agentID, fleet.Stats{
		EventsProcessed: stats.Events.Load(),
		Alerts:          stats.Alerts.Load(),
		Incidents:       stats.Incidents.Load(),
		RulesVersion:    f.conn.rulesVersion,
	})
	if err != nil {
		if ctx.Err() == nil { // a cancelled RPC is just clean shutdown, not a failure
			f.logger.Warn("heartbeat failed", "err", err)
		}
		return
	}
	for _, command := range commands {
		f.applyCommand(ctx, command)
	}
}

func (f *fleetRunner) applyCommand(ctx context.Context, command fleet.Command) {
	switch command.Kind {
	case "UPDATE_RULES":
		f.syncRules(ctx)
	case "SET_RESPONSE_MODE":
		f.responder.SetMode(respond.ParseMode(command.Argument))
	case "KILL_PROCESS":
		f.remoteKill(command.Argument)
	case "QUARANTINE":
		result := f.responder.RequestNetworkBlock(strings.TrimSpace(command.Argument))
		f.logger.Warn("quarantine command", "target", command.Argument, "result", result)
	default:
		f.logger.Warn("ignoring unknown command from control plane", "kind", command.Kind)
	}
}

func (f *fleetRunner) remoteKill(argument string) {
	pid, err := strconv.ParseUint(strings.TrimSpace(argument), 10, 32)
	if err != nil {
		f.logger.Warn("invalid KILL_PROCESS argument", "argument", argument, "err", err)
		return
	}
	result := f.responder.RequestKill(uint32(pid), "")
	f.logger.Warn("remote kill command", "pid", pid, "result", result)
}

// syncRules pulls the fleet ruleset when it differs from what the agent runs,
// writes the files locally, and swaps in a freshly compiled engine. A pull,
// compile or write failure leaves the running engine untouched.
func (f *fleetRunner) syncRules(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	rules, err := f.conn.client.FetchRules(ctx, f.conn.agentID, f.conn.rulesVersion)
	if err != nil {
		if ctx.Err() == nil { // a cancelled RPC is just clean shutdown, not a failure
			f.logger.Warn("rule sync failed", "err", err)
		}
		return
	}
	if rules.Unchanged {
		return
	}
	if err := writeRuleFiles(f.rulesDir, rules.Files); err != nil {
		f.logger.Error("writing pushed rules failed", "err", err)
		return
	}
	engine, err := loadEngine(f.rulesDir, f.correlator)
	if err != nil {
		f.logger.Error("compiling pushed rules failed, keeping current ruleset", "err", err)
		return
	}
	if f.intel != nil {
		engine.SetIntel(f.intel) // carry threat intel across the rule reload
	}
	f.pipeline.SetEngine(engine)
	f.conn.rulesVersion = rules.Version
	f.logger.Info("applied pushed ruleset", "version", rules.Version, "files", len(rules.Files))
}

// writeRuleFiles persists pushed rule files into dir. It reduces each name to its
// base so a misbehaving control plane cannot write outside the rules directory.
func writeRuleFiles(dir string, files []fleet.RuleFile) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}
	for _, file := range files {
		name := filepath.Base(file.Name)
		if err := os.WriteFile(filepath.Join(dir, name), file.Content, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// kernelRelease reads the running kernel version for enrollment metadata.
func kernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

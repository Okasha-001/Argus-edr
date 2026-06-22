package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/argus-edr/argus/internal/anomaly"
	"github.com/argus-edr/argus/internal/config"
	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/enrich"
	"github.com/argus-edr/argus/internal/intel"
	"github.com/argus-edr/argus/internal/logging"
	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/output"
	"github.com/argus-edr/argus/internal/pipeline"
	"github.com/argus-edr/argus/internal/respond"
	"github.com/argus-edr/argus/internal/version"
	"github.com/argus-edr/argus/internal/yara"
)

func runAgent(args []string) error {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := flags.String("config", "/etc/argus/config.yaml", "config file path")
	if err := flags.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	logger := logging.New(os.Stderr, cfg.Agent.LogLevel, cfg.Agent.LogFormat)

	correlator := buildCorrelator(cfg)
	engine, err := loadEngine(cfg.Detection.RulesDir, correlator)
	if err != nil {
		return err
	}
	matcher, err := buildIntel(cfg, logger)
	if err != nil {
		return err
	}
	if matcher != nil {
		engine.SetIntel(matcher)
	}
	yaraEngine, err := buildYara(cfg, logger)
	if err != nil {
		return err
	}
	responder := respond.New(
		respond.ParseMode(cfg.Response.Mode),
		respond.ParseMode(cfg.Response.MaxMode),
		cfg.Response.AllowlistPaths,
		logger,
	)

	sink, fleet, err := buildSink(cfg, logger)
	if err != nil {
		return err
	}
	defer sink.Close()

	scorer, err := buildScorer(cfg, logger)
	if err != nil {
		return err
	}

	guard := buildSelfProtection(cfg, sink, logger)
	telemetry := buildObservability(cfg, logger)
	source := buildSource(cfg, logger)
	agent := pipeline.New(pipeline.Params{
		Source:    source,
		Enricher:  enrich.New(enrichOptions(cfg, yaraEngine)),
		Scorer:    scorer,
		Engine:    engine,
		Responder: responder,
		Sink:      sink,
		Logger:    logger,
		Heartbeat: guard.heartbeat(),
		Observer:  telemetry.observer(),
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	guard.start(ctx)
	telemetry.start(ctx, source)

	fleetDone := startFleet(ctx, fleet, agent, responder, correlator, matcher, cfg, logger)

	logger.Info("argus starting",
		"version", version.Version, "host", cfg.Agent.Hostname,
		"source", cfg.Input.Source, "response", cfg.Response.Mode, "fleet", cfg.Fleet.Enabled)

	runErr := agent.Run(ctx)
	stop() // the pipeline has stopped (signal or exhausted source); tear the fleet runner down too
	if fleetDone != nil {
		<-fleetDone // let the control-plane runner drain before we exit
	}
	logStats(logger, agent)
	return runErr
}

// buildSink assembles the agent's output sinks, joining the control-plane sink
// when fleet mode is enabled. The returned fleetConn is nil when fleet is off.
func buildSink(cfg config.Config, logger *slog.Logger) (output.Sink, *fleetConn, error) {
	outputs, err := output.Build(cfg.Outputs)
	if err != nil {
		return nil, nil, err
	}
	if !cfg.Fleet.Enabled {
		return outputs, nil, nil
	}
	conn, err := connectFleet(cfg, logger)
	if err != nil {
		_ = outputs.Close()
		return nil, nil, fmt.Errorf("fleet: %w", err)
	}
	return output.NewMultiSink(outputs, conn.sink), conn, nil
}

// startFleet launches the control-plane runner when connected, returning a
// channel closed once it has fully drained (nil when fleet is off).
func startFleet(ctx context.Context, conn *fleetConn, agent *pipeline.Pipeline, responder *respond.Responder,
	correlator *detect.Correlator, matcher *intel.Matcher, cfg config.Config, logger *slog.Logger) <-chan struct{} {
	if conn == nil {
		return nil
	}
	done := make(chan struct{})
	runner := newFleetRunner(conn, agent, responder, correlator, matcher, cfg, logger)
	go func() {
		defer close(done)
		runner.Run(ctx)
	}()
	return done
}

// buildScorer loads the anomaly baseline when anomaly scoring is enabled, or
// returns a nil scorer (scoring off) otherwise.
func buildScorer(cfg config.Config, logger *slog.Logger) (pipeline.Scorer, error) {
	if !cfg.Anomaly.Enabled {
		return nil, nil
	}
	detector, err := anomaly.Load(cfg.Anomaly.BaselineFile)
	if err != nil {
		return nil, fmt.Errorf("anomaly: %w", err)
	}
	logger.Info("anomaly scoring enabled", "baseline", cfg.Anomaly.BaselineFile)
	return detector, nil
}

// buildIntel loads the configured threat-intel feeds, or returns nil when
// intel is disabled.
func buildIntel(cfg config.Config, logger *slog.Logger) (*intel.Matcher, error) {
	if !cfg.Intel.Enabled {
		return nil, nil
	}
	matcher, err := intel.Load(cfg.Intel.Feeds...)
	if err != nil {
		return nil, fmt.Errorf("load threat intel: %w", err)
	}
	logger.Info("threat intel loaded", "indicators", matcher.Size(), "feeds", len(cfg.Intel.Feeds))
	return matcher, nil
}

// buildSource picks the event source: the recorded replay (any platform) or the
// platform's live source. The live source is the one piece that differs per OS —
// eBPF on Linux, a process source on Windows — so it lives in a build-tagged
// newLiveSource. Everything downstream (enrich, detect, respond, output, fleet)
// is platform-neutral and consumes the same model.Event.
func buildSource(cfg config.Config, logger *slog.Logger) pipeline.Source {
	if cfg.Input.Source == config.SourceReplay {
		return pipeline.NewReplaySource(cfg.Input.ReplayFile)
	}
	return newLiveSource(cfg, logger)
}

// selfProtection bundles the userspace tamper checks so the runtime can wire the
// watchdog's kick into the pipeline and start both under one context.
type selfProtection struct {
	integrity *respond.SelfIntegrity
	watchdog  *respond.Watchdog
}

// buildSelfProtection assembles the binary-integrity check and liveness watchdog,
// or returns nil when self-protection is disabled. A finding is written straight
// to the sink (stamped with this host), exactly like a detection alert. An
// unresolvable own-binary disables only the integrity half, never the watchdog.
func buildSelfProtection(cfg config.Config, sink output.Sink, logger *slog.Logger) *selfProtection {
	settings := cfg.Response.SelfProtection
	if !settings.Enabled {
		return nil
	}
	report := func(alert *model.Alert) {
		alert.Event.Host = cfg.Agent.Hostname
		if err := sink.WriteAlert(alert); err != nil {
			logger.Error("write self-protection alert", "err", err)
		}
		logger.Warn("self-protection alert",
			"rule", alert.RuleID, "name", alert.RuleName, "detail", alert.Description)
	}

	guard := &selfProtection{
		watchdog: respond.NewWatchdog(
			time.Duration(settings.WatchdogTimeoutSeconds)*time.Second, report, logger),
	}
	exe, err := os.Executable()
	if err != nil {
		logger.Warn("self-integrity disabled: cannot resolve own binary", "err", err)
		return guard
	}
	integrity, err := respond.NewSelfIntegrity(
		exe, time.Duration(settings.IntegrityIntervalSeconds)*time.Second, report, logger)
	if err != nil {
		logger.Warn("self-integrity disabled", "err", err)
		return guard
	}
	guard.integrity = integrity
	return guard
}

// heartbeat is the pipeline hook that kicks the watchdog; nil (a no-op) when
// self-protection is off, so the pipeline pays nothing for it.
func (s *selfProtection) heartbeat() func() {
	if s == nil {
		return nil
	}
	return s.watchdog.Kick
}

// start launches the check loops, both bound to ctx so they stop with the agent.
func (s *selfProtection) start(ctx context.Context) {
	if s == nil {
		return
	}
	go s.watchdog.Run(ctx)
	if s.integrity != nil {
		go s.integrity.Run(ctx)
	}
}

// buildCorrelator creates the per-process correlator, or nil when correlation is
// disabled. It is built separately from the engine so the same correlator can be
// carried across rule reloads, preserving in-flight incident state.
func buildCorrelator(cfg config.Config) *detect.Correlator {
	if !cfg.Detection.Correlation.Enabled {
		return nil
	}
	return detect.NewCorrelator(
		time.Duration(cfg.Detection.Correlation.WindowSeconds)*time.Second,
		cfg.Detection.Correlation.IncidentThreshold)
}

// loadEngine compiles the rules in rulesDir into an engine bound to correlator.
// It is also called on a control-plane rule push to build the replacement engine.
func loadEngine(rulesDir string, correlator *detect.Correlator) (*detect.Engine, error) {
	rules, err := detect.LoadDir(rulesDir)
	if err != nil {
		return nil, err
	}
	return detect.NewEngine(rules, correlator), nil
}

func enrichOptions(cfg config.Config, yaraEngine *yara.Engine) enrich.Options {
	return enrich.Options{
		ProcessTree:     cfg.Enrichment.ProcessTree,
		ResolveUsers:    cfg.Enrichment.ResolveUsers,
		ContainerAware:  cfg.Enrichment.ContainerAware,
		HashExecutables: cfg.Enrichment.HashExecutables,
		HashMaxBytes:    cfg.Enrichment.HashMaxBytes,
		Yara:            yaraEngine,
		YaraMaxBytes:    cfg.Yara.MaxBytes,
	}
}

// buildYara compiles every *.yar file under the configured directory into a YARA
// engine, or returns nil when scanning is disabled.
func buildYara(cfg config.Config, logger *slog.Logger) (*yara.Engine, error) {
	if !cfg.Yara.Enabled {
		return nil, nil
	}
	paths, err := filepath.Glob(filepath.Join(cfg.Yara.RulesDir, "*.yar"))
	if err != nil {
		return nil, fmt.Errorf("glob yara rules: %w", err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("yara enabled but no .yar files in %s", cfg.Yara.RulesDir)
	}
	var source strings.Builder
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read yara rule %s: %w", path, err)
		}
		source.Write(data)
		source.WriteByte('\n')
	}
	engine, err := yara.Compile(source.String())
	if err != nil {
		return nil, fmt.Errorf("compile yara rules: %w", err)
	}
	logger.Info("yara loaded", "files", len(paths), "dir", cfg.Yara.RulesDir)
	return engine, nil
}

func logStats(logger *slog.Logger, agent *pipeline.Pipeline) {
	stats := agent.Stats()
	logger.Info("argus stopped",
		"events", stats.Events.Load(),
		"alerts", stats.Alerts.Load(),
		"incidents", stats.Incidents.Load())
}

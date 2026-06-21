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
	"github.com/argus-edr/argus/internal/bpfloader"
	"github.com/argus-edr/argus/internal/config"
	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/enrich"
	"github.com/argus-edr/argus/internal/intel"
	"github.com/argus-edr/argus/internal/logging"
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

	agent := pipeline.New(pipeline.Params{
		Source:    buildSource(cfg, logger),
		Enricher:  enrich.New(enrichOptions(cfg, yaraEngine)),
		Scorer:    scorer,
		Engine:    engine,
		Responder: responder,
		Sink:      sink,
		Logger:    logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

func buildSource(cfg config.Config, logger *slog.Logger) pipeline.Source {
	if cfg.Input.Source == config.SourceReplay {
		return pipeline.NewReplaySource(cfg.Input.ReplayFile)
	}
	return bpfloader.NewEBPFSource(bpfloader.Options{
		ObjectPath:    cfg.Input.BPFObject,
		LSMObjectPath: enforcementObject(cfg),
		Hostname:      cfg.Agent.Hostname,
		EnforceMode:   cfg.Response.ModeValue(),
		CredReaders:   cfg.Response.CredReaderAllowlist,
		Logger:        logger,
	})
}

// enforcementObject is the LSM object sitting next to the sensor object, loaded
// only when response enforcement is actually requested.
func enforcementObject(cfg config.Config) string {
	if cfg.Response.Mode == config.ModeOff {
		return ""
	}
	return filepath.Join(filepath.Dir(cfg.Input.BPFObject), "edr_lsm.bpf.o")
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

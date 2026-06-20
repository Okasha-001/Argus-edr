package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/argus-edr/argus/internal/anomaly"
	"github.com/argus-edr/argus/internal/detect"
	"github.com/argus-edr/argus/internal/enrich"
	"github.com/argus-edr/argus/internal/logging"
	"github.com/argus-edr/argus/internal/output"
	"github.com/argus-edr/argus/internal/pipeline"
)

const (
	replayWindow    = 30 * time.Second
	replayThreshold = 75
)

func runReplay(args []string) error {
	flags := flag.NewFlagSet("replay", flag.ExitOnError)
	rulesDir := flags.String("rules", "rules", "rules directory")
	format := flags.String("format", "pretty", "stdout format: pretty|ecs")
	baselineFile := flags.String("baseline", "", "anomaly baseline to score events against (enables anomaly.score)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	eventsFile := flags.Arg(0)
	if eventsFile == "" {
		return fmt.Errorf("usage: argus replay [--rules dir] [--format pretty|ecs] <events.ndjson>")
	}

	rules, err := detect.LoadDir(*rulesDir)
	if err != nil {
		return err
	}
	logger := logging.New(os.Stderr, "info", "text")
	engine := detect.NewEngine(rules, detect.NewCorrelator(replayWindow, replayThreshold))
	sink := output.NewStdout(os.Stdout, *format)

	var scorer pipeline.Scorer
	if *baselineFile != "" {
		detector, err := anomaly.Load(*baselineFile)
		if err != nil {
			return err
		}
		scorer = detector
	}

	agent := pipeline.New(pipeline.Params{
		Source:   pipeline.NewReplaySource(eventsFile),
		Enricher: enrich.New(enrich.Options{ProcessTree: true}),
		Scorer:   scorer,
		Engine:   engine,
		Sink:     sink,
		Logger:   logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := agent.Run(ctx); err != nil {
		return err
	}
	_ = sink.Close()

	stats := agent.Stats()
	logger.Info("replay complete",
		"events", stats.Events.Load(),
		"alerts", stats.Alerts.Load(),
		"incidents", stats.Incidents.Load())
	return nil
}

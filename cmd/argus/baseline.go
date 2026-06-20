package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"

	"github.com/argus-edr/argus/internal/anomaly"
	"github.com/argus-edr/argus/internal/enrich"
	"github.com/argus-edr/argus/internal/model"
	"github.com/argus-edr/argus/internal/pipeline"
)

func runBaseline(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: argus baseline build [--out baseline.json] [--seed N] <events.ndjson>")
	}
	switch args[0] {
	case "build":
		return buildBaseline(args[1:])
	default:
		return fmt.Errorf("unknown baseline subcommand %q (want build)", args[0])
	}
}

// buildBaseline trains an anomaly baseline from a recorded NDJSON stream. It runs
// the same replay source and enrichment the live agent uses, so the model learns
// the same shapes it will later score, then writes the detector to disk.
func buildBaseline(args []string) error {
	flags := flag.NewFlagSet("baseline build", flag.ExitOnError)
	out := flags.String("out", "baseline.json", "output baseline file")
	seed := flags.Int64("seed", 1, "random seed for the isolation forest (reproducible builds)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	eventsFile := flags.Arg(0)
	if eventsFile == "" {
		return fmt.Errorf("usage: argus baseline build [--out file] [--seed N] <events.ndjson>")
	}

	source := pipeline.NewReplaySource(eventsFile)
	enricher := enrich.New(enrich.Options{ProcessTree: true})
	trainer := anomaly.NewTrainer()

	events := make(chan *model.Event, 1024)
	errc := make(chan error, 1)
	go func() {
		err := source.Run(context.Background(), events)
		close(events)
		errc <- err
	}()
	for event := range events {
		enricher.Enrich(event)
		trainer.Observe(event)
	}
	if err := <-errc; err != nil {
		return fmt.Errorf("read events: %w", err)
	}

	detector := trainer.Build(rand.New(rand.NewSource(*seed)))
	if err := detector.Save(*out); err != nil {
		return err
	}
	fmt.Printf("baseline written to %s from %d events\n", *out, trainer.Count())
	return nil
}

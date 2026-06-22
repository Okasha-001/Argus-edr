//go:build windows

package main

import (
	"log/slog"

	"github.com/argus-edr/argus/internal/config"
	"github.com/argus-edr/argus/internal/pipeline"
	"github.com/argus-edr/argus/internal/winsource"
)

// newLiveSource returns the Windows event source. It fills the same model.Event
// the eBPF sensors produce, so the detection, response, output and fleet layers
// run unchanged — only the source differs by platform.
func newLiveSource(cfg config.Config, logger *slog.Logger) pipeline.Source {
	logger.Info("windows process source (experimental); detection/output/fleet run unchanged")
	return winsource.New(cfg.Agent.Hostname, logger)
}

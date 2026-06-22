//go:build !windows

package main

import (
	"log/slog"
	"path/filepath"

	"github.com/argus-edr/argus/internal/bpfloader"
	"github.com/argus-edr/argus/internal/config"
	"github.com/argus-edr/argus/internal/pipeline"
)

// newLiveSource returns the eBPF kernel source on Linux. On other non-Windows
// platforms the bpfloader stub fails at Run with a clear message — the agent
// still builds for tooling and editor support.
func newLiveSource(cfg config.Config, logger *slog.Logger) pipeline.Source {
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

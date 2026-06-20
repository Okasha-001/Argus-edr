package config

import "fmt"

var (
	validLogLevels = map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	validSources   = map[string]bool{SourceEBPF: true, SourceReplay: true}
	validModes     = map[string]bool{ModeOff: true, ModeDryRun: true, ModeEnforce: true}
	validOutputs   = map[string]bool{"stdout": true, "file": true, "loki": true, "sqlite": true}

	// modeRank orders the response postures so config can enforce mode <= max_mode.
	modeRank = map[string]int{ModeOff: 0, ModeDryRun: 1, ModeEnforce: 2}
)

func (c Config) validate() error {
	if !validLogLevels[c.Agent.LogLevel] {
		return fmt.Errorf("agent.log_level %q invalid (want debug|info|warn|error)", c.Agent.LogLevel)
	}
	if !validSources[c.Input.Source] {
		return fmt.Errorf("input.source %q invalid (want ebpf|replay)", c.Input.Source)
	}
	if c.Input.Source == SourceReplay && c.Input.ReplayFile == "" {
		return fmt.Errorf("input.replay_file is required when source=replay")
	}
	if c.Input.RingBufferBytes <= 0 {
		return fmt.Errorf("input.ring_buffer_bytes must be positive")
	}
	if !validModes[c.Response.Mode] {
		return fmt.Errorf("response.mode %q invalid (want off|dry-run|enforce)", c.Response.Mode)
	}
	if !validModes[c.Response.MaxMode] {
		return fmt.Errorf("response.max_mode %q invalid (want off|dry-run|enforce)", c.Response.MaxMode)
	}
	if modeRank[c.Response.Mode] > modeRank[c.Response.MaxMode] {
		return fmt.Errorf("response.mode %q exceeds response.max_mode %q", c.Response.Mode, c.Response.MaxMode)
	}
	if c.Detection.Correlation.Enabled && c.Detection.Correlation.IncidentThreshold <= 0 {
		return fmt.Errorf("detection.correlation.incident_threshold must be positive")
	}
	if len(c.Outputs) == 0 {
		return fmt.Errorf("at least one output is required")
	}
	if err := c.validateOutputs(); err != nil {
		return err
	}
	if err := c.validateFleet(); err != nil {
		return err
	}
	if c.Intel.Enabled && len(c.Intel.Feeds) == 0 {
		return fmt.Errorf("intel.feeds is required when intel.enabled is true")
	}
	if c.Anomaly.Enabled && c.Anomaly.BaselineFile == "" {
		return fmt.Errorf("anomaly.baseline_file is required when anomaly.enabled is true")
	}
	if c.Yara.Enabled && c.Yara.RulesDir == "" {
		return fmt.Errorf("yara.rules_dir is required when yara.enabled is true")
	}
	return nil
}

// validateFleet checks the control-plane connection settings, but only when the
// fleet is enabled: a standalone agent leaves these blank.
func (c Config) validateFleet() error {
	if !c.Fleet.Enabled {
		return nil
	}
	required := []struct {
		name, value string
	}{
		{"fleet.server_address", c.Fleet.ServerAddress},
		{"fleet.server_name", c.Fleet.ServerName},
		{"fleet.ca_file", c.Fleet.CAFile},
		{"fleet.cert_file", c.Fleet.CertFile},
		{"fleet.key_file", c.Fleet.KeyFile},
	}
	for _, field := range required {
		if field.value == "" {
			return fmt.Errorf("%s is required when fleet.enabled is true", field.name)
		}
	}
	if c.Fleet.HeartbeatSeconds <= 0 {
		return fmt.Errorf("fleet.heartbeat_seconds must be positive")
	}
	return nil
}

func (c Config) validateOutputs() error {
	for i, out := range c.Outputs {
		if !validOutputs[out.Type] {
			return fmt.Errorf("outputs[%d].type %q invalid (want stdout|file|loki|sqlite)", i, out.Type)
		}
		if out.Type == "file" && out.Path == "" {
			return fmt.Errorf("outputs[%d] (file) requires a path", i)
		}
		if out.Type == "sqlite" && out.Path == "" {
			return fmt.Errorf("outputs[%d] (sqlite) requires a path", i)
		}
		if out.Type == "loki" && out.Endpoint == "" {
			return fmt.Errorf("outputs[%d] (loki) requires an endpoint", i)
		}
	}
	return nil
}

// ModeValue maps the response mode onto the integer the LSM enforcement map
// expects: 0 off, 1 dry-run, 2 enforce.
func (r Response) ModeValue() uint32 {
	switch r.Mode {
	case ModeDryRun:
		return 1
	case ModeEnforce:
		return 2
	default:
		return 0
	}
}

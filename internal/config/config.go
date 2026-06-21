// Package config loads and validates the agent configuration. Loading starts
// from the built-in defaults and overlays the file, so a config only needs the
// keys it wants to change. Unknown keys are rejected rather than ignored.
package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Response modes, ordered off < dry-run < enforce. The numeric value is what the
// LSM enforcement map expects.
const (
	ModeOff     = "off"
	ModeDryRun  = "dry-run"
	ModeEnforce = "enforce"
)

// Input sources.
const (
	SourceEBPF   = "ebpf"
	SourceReplay = "replay"
)

type Config struct {
	Agent      Agent      `yaml:"agent"`
	Input      Input      `yaml:"input"`
	Enrichment Enrichment `yaml:"enrichment"`
	Detection  Detection  `yaml:"detection"`
	Response   Response   `yaml:"response"`
	Outputs    []Output   `yaml:"outputs"`
	Fleet      Fleet      `yaml:"fleet"`
	Intel      Intel      `yaml:"intel"`
	Anomaly    Anomaly    `yaml:"anomaly"`
	Yara       Yara       `yaml:"yara"`
}

type Agent struct {
	Hostname  string `yaml:"hostname"`
	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`
}

type Input struct {
	Source          string `yaml:"source"`
	BPFObject       string `yaml:"bpf_object"`
	RingBufferBytes int    `yaml:"ring_buffer_bytes"`
	ReplayFile      string `yaml:"replay_file"`
}

type Enrichment struct {
	ProcessTree     bool  `yaml:"process_tree"`
	ResolveUsers    bool  `yaml:"resolve_users"`
	ContainerAware  bool  `yaml:"container_aware"`
	HashExecutables bool  `yaml:"hash_executables"`
	HashMaxBytes    int64 `yaml:"hash_max_bytes"`
}

type Detection struct {
	RulesDir    string      `yaml:"rules_dir"`
	Correlation Correlation `yaml:"correlation"`
}

type Correlation struct {
	Enabled           bool `yaml:"enabled"`
	WindowSeconds     int  `yaml:"window_seconds"`
	IncidentThreshold int  `yaml:"incident_threshold"`
}

type Response struct {
	Mode string `yaml:"mode"`
	// MaxMode is the highest posture the control plane may set on this agent. It
	// defaults to Mode, so out of the box a remote SET_RESPONSE_MODE can only
	// lower the posture, never raise it past what the operator pinned locally.
	// Raising it (e.g. mode: dry-run, max_mode: enforce) is an explicit opt-in.
	MaxMode        string   `yaml:"max_mode"`
	AllowlistPaths []string `yaml:"allowlist_paths"`
	// CredReaderAllowlist names the process comms permitted to read the shadow
	// password files when the file_open enforcement hook is active. The auth stack
	// (sshd, login, su, ...) must stay listed or enforce mode would break local
	// logins. Comms are matched exactly as the kernel reports them (≤15 chars).
	CredReaderAllowlist []string `yaml:"cred_reader_allowlist"`
}

type Output struct {
	Type           string            `yaml:"type"`
	Format         string            `yaml:"format,omitempty"`
	Path           string            `yaml:"path,omitempty"`
	RotateMaxBytes int64             `yaml:"rotate_max_bytes,omitempty"`
	Endpoint       string            `yaml:"endpoint,omitempty"`
	Labels         map[string]string `yaml:"labels,omitempty"`
}

// Fleet connects the agent to an argus-server control plane over mTLS. It is
// off by default: a standalone agent needs no control plane. When enabled, the
// agent enrolls, heartbeats, streams its alerts upstream, and applies pushed
// commands (rule updates, response posture).
type Fleet struct {
	Enabled          bool   `yaml:"enabled"`
	ServerAddress    string `yaml:"server_address"`
	ServerName       string `yaml:"server_name"`
	CAFile           string `yaml:"ca_file"`
	CertFile         string `yaml:"cert_file"`
	KeyFile          string `yaml:"key_file"`
	EnrollmentToken  string `yaml:"enrollment_token"`
	HeartbeatSeconds int    `yaml:"heartbeat_seconds"`
}

// Intel loads threat-intelligence indicator feeds (IOC files). Off by default;
// when enabled, events are matched against the indicators and hits raise alerts.
type Intel struct {
	Enabled bool     `yaml:"enabled"`
	Feeds   []string `yaml:"feeds"`
}

// Anomaly scores events for rarity/outlierness using a baseline trained offline
// by `argus baseline build`. Off by default; when enabled it loads BaselineFile
// and exposes anomaly.score (0–100) to rules. No baseline means no scoring.
type Anomaly struct {
	Enabled      bool   `yaml:"enabled"`
	BaselineFile string `yaml:"baseline_file"`
}

// Yara scans executed files against signature rules and exposes yara.matched to
// the rule engine. Off by default; when enabled it loads every *.yar file under
// RulesDir and scans up to MaxBytes of each executable.
type Yara struct {
	Enabled  bool   `yaml:"enabled"`
	RulesDir string `yaml:"rules_dir"`
	MaxBytes int64  `yaml:"max_bytes"`
}

const (
	defaultRingBufferBytes  = 8 * 1024 * 1024
	defaultHashMaxBytes     = 32 * 1024 * 1024
	defaultYaraMaxBytes     = 16 * 1024 * 1024
	defaultWindowSeconds    = 30
	defaultIncidentScore    = 75
	defaultHeartbeatSeconds = 30
)

// Defaults returns the configuration used when no file overrides a value.
func Defaults() Config {
	return Config{
		Agent: Agent{LogLevel: "info", LogFormat: "json"},
		Input: Input{
			Source:          SourceEBPF,
			BPFObject:       "/usr/lib/argus/edr.bpf.o",
			RingBufferBytes: defaultRingBufferBytes,
		},
		Enrichment: Enrichment{
			ProcessTree:    true,
			ResolveUsers:   true,
			ContainerAware: true,
			HashMaxBytes:   defaultHashMaxBytes,
		},
		Detection: Detection{
			RulesDir: "/etc/argus/rules",
			Correlation: Correlation{
				Enabled:           true,
				WindowSeconds:     defaultWindowSeconds,
				IncidentThreshold: defaultIncidentScore,
			},
		},
		Response: Response{
			Mode:           ModeOff,
			AllowlistPaths: []string{"/usr/lib/systemd/systemd", "/usr/sbin/sshd"},
			// The auth stack that legitimately reads the shadow files. Operators
			// should run dry-run first to discover any reader specific to their
			// host (PAM modules, display managers) before enabling enforce.
			CredReaderAllowlist: []string{
				"sshd", "login", "su", "sudo", "passwd", "chpasswd", "unix_chkpwd",
				"systemd-logind", "agetty", "gdm-session-wor", "polkitd", "useradd",
				"usermod", "gpasswd", "chage",
			},
		},
		Outputs: []Output{{Type: "stdout", Format: "ecs"}},
		Fleet:   Fleet{Enabled: false, HeartbeatSeconds: defaultHeartbeatSeconds},
		Yara:    Yara{Enabled: false, MaxBytes: defaultYaraMaxBytes},
	}
}

// Load reads the file at path over the defaults and validates the result. An
// empty path returns the validated defaults.
func Load(path string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		if err := overlayFile(&cfg, path); err != nil {
			return Config{}, err
		}
	}
	if cfg.Agent.Hostname == "" {
		cfg.Agent.Hostname = detectHostname()
	}
	if cfg.Response.MaxMode == "" {
		cfg.Response.MaxMode = cfg.Response.Mode
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func overlayFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}

func detectHostname() string {
	if name, err := os.Hostname(); err == nil {
		return name
	}
	return "unknown"
}

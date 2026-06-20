// Package store holds the control plane's fleet state: the agent inventory,
// recent alerts, and per-agent command queues. The interface lets the in-memory
// implementation be swapped for a database without touching the API layer.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Agent is one enrolled host as the control plane knows it.
type Agent struct {
	ID       string
	Hostname string
	Version  string
	Kernel   string
	// CertFingerprint is the SHA-256 of the client certificate presented at
	// enrollment. Every later request from this agent must present the same
	// certificate, which stops one valid fleet cert from impersonating another
	// agent. Empty only for agents enrolled without mTLS (in-process tests).
	CertFingerprint string
	FirstSeen       time.Time
	LastSeen        time.Time
	EventsProcessed uint64
	Alerts          uint64
	Incidents       uint64
	RulesVersion    string
}

// Online reports whether the agent's last heartbeat is within ttl of now.
func (a Agent) Online(now time.Time, ttl time.Duration) bool {
	return now.Sub(a.LastSeen) <= ttl
}

// Stats are the counters an agent reports on each heartbeat.
type Stats struct {
	EventsProcessed uint64
	Alerts          uint64
	Incidents       uint64
	RulesVersion    string
}

// AlertRecord is a flattened alert as received from an agent — enough for
// central display and cross-host correlation.
type AlertRecord struct {
	AgentID           string
	Hostname          string
	Time              time.Time
	RuleID            string
	RuleName          string
	Severity          string
	TechniqueID       string
	TechniqueName     string
	PID               uint32
	ProcessName       string
	ProcessExecutable string
	DestinationIP     string
	RiskScore         int
	IsIncident        bool
}

// Command is an instruction queued for an agent, delivered on its next heartbeat.
type Command struct {
	Kind     string
	Argument string
}

// Store is the control plane's state backend.
type Store interface {
	Enroll(hostname, version, kernel, certFingerprint string) Agent
	Heartbeat(agentID string, stats Stats) (Agent, bool)
	Get(agentID string) (Agent, bool)
	List() []Agent
	RecordAlert(record AlertRecord)
	RecentAlerts(limit int) []AlertRecord
	EnqueueCommand(agentID string, cmd Command) bool
	DrainCommands(agentID string) []Command
}

// NewID returns a random 128-bit hex identifier for a freshly enrolled agent.
func NewID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

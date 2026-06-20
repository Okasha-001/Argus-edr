// Package store holds the control plane's fleet state: the agent inventory,
// recent alerts, and per-agent command queues. The interface lets the in-memory
// implementation be swapped for a database without touching the API layer.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Backend names accepted by Open.
const (
	BackendMemory = "memory"
	BackendSQLite = "sqlite"
)

// Open returns a Store of the named kind. "memory" is ephemeral (lost on
// restart); "sqlite" is durable and takes a filesystem path as its dsn.
// Postgres is the documented next backend — it implements the same interface.
func Open(kind, dsn string) (Store, error) {
	switch kind {
	case BackendMemory, "":
		return NewMemory(), nil
	case BackendSQLite:
		if dsn == "" {
			return nil, fmt.Errorf("store %q requires a --dsn (database file path)", kind)
		}
		return openSQLite(dsn)
	default:
		return nil, fmt.Errorf("unknown store %q (want memory|sqlite)", kind)
	}
}

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
	// ID uniquely identifies a stored alert. RecordAlert assigns one when it is
	// empty, so callers may leave it blank and read it back via AlertByID.
	ID                string
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

// AlertFilter narrows a history query. A zero value matches everything; each set
// field is an additional AND constraint. Time bounds are inclusive; the zero
// time means "unbounded" on that side.
type AlertFilter struct {
	Hostname      string
	Severity      string
	TechniqueID   string
	Since         time.Time
	Until         time.Time
	IncidentsOnly bool
	Limit         int // <= 0 means no limit
}

// Store is the control plane's state backend. Implementations must be safe for
// concurrent use. The history methods (QueryAlerts, AlertByID, PruneAlerts) and
// Close exist so a durable backend can outlive a restart and serve the console.
type Store interface {
	Enroll(hostname, version, kernel, certFingerprint string) Agent
	Heartbeat(agentID string, stats Stats) (Agent, bool)
	Get(agentID string) (Agent, bool)
	List() []Agent
	RecordAlert(record AlertRecord)
	RecentAlerts(limit int) []AlertRecord
	QueryAlerts(filter AlertFilter) []AlertRecord
	AlertByID(id string) (AlertRecord, bool)
	PruneAlerts(before time.Time) int
	EnqueueCommand(agentID string, cmd Command) bool
	DrainCommands(agentID string) []Command
	Close() error
}

// matches reports whether record satisfies every set constraint in the filter.
// It is shared by the in-memory backend and any backend that filters in Go.
func (f AlertFilter) matches(record AlertRecord) bool {
	if f.Hostname != "" && record.Hostname != f.Hostname {
		return false
	}
	if f.Severity != "" && record.Severity != f.Severity {
		return false
	}
	if f.TechniqueID != "" && record.TechniqueID != f.TechniqueID {
		return false
	}
	if f.IncidentsOnly && !record.IsIncident {
		return false
	}
	if !f.Since.IsZero() && record.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && record.Time.After(f.Until) {
		return false
	}
	return true
}

// NewID returns a random 128-bit hex identifier for a freshly enrolled agent.
func NewID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

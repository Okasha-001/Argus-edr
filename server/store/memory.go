package store

import (
	"sync"
	"time"
)

const maxRetainedAlerts = 1000

// Memory is an in-memory Store, suitable for a single control-plane instance and
// for tests. Postgres-backed storage implements the same interface later.
type Memory struct {
	mu       sync.RWMutex
	agents   map[string]Agent
	alerts   []AlertRecord
	commands map[string][]Command
	clock    func() time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		agents:   make(map[string]Agent),
		commands: make(map[string][]Command),
		clock:    time.Now,
	}
}

func (m *Memory) Enroll(hostname, version, kernel, certFingerprint string) Agent {
	now := m.clock()
	agent := Agent{
		ID:              NewID(),
		Hostname:        hostname,
		Version:         version,
		Kernel:          kernel,
		CertFingerprint: certFingerprint,
		FirstSeen:       now,
		LastSeen:        now,
	}
	m.mu.Lock()
	m.agents[agent.ID] = agent
	m.mu.Unlock()
	return agent
}

func (m *Memory) Heartbeat(agentID string, stats Stats) (Agent, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	agent, ok := m.agents[agentID]
	if !ok {
		return Agent{}, false
	}
	agent.LastSeen = m.clock()
	agent.EventsProcessed = stats.EventsProcessed
	agent.Alerts = stats.Alerts
	agent.Incidents = stats.Incidents
	agent.RulesVersion = stats.RulesVersion
	m.agents[agentID] = agent
	return agent, true
}

func (m *Memory) Get(agentID string) (Agent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agent, ok := m.agents[agentID]
	return agent, ok
}

func (m *Memory) List() []Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agents := make([]Agent, 0, len(m.agents))
	for _, agent := range m.agents {
		agents = append(agents, agent)
	}
	return agents
}

func (m *Memory) RecordAlert(record AlertRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, record)
	if len(m.alerts) > maxRetainedAlerts {
		m.alerts = m.alerts[len(m.alerts)-maxRetainedAlerts:]
	}
}

// RecentAlerts returns up to limit alerts, most recent first.
func (m *Memory) RecentAlerts(limit int) []AlertRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.alerts) {
		limit = len(m.alerts)
	}
	out := make([]AlertRecord, 0, limit)
	for i := len(m.alerts) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, m.alerts[i])
	}
	return out
}

func (m *Memory) EnqueueCommand(agentID string, cmd Command) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.agents[agentID]; !ok {
		return false
	}
	m.commands[agentID] = append(m.commands[agentID], cmd)
	return true
}

func (m *Memory) DrainCommands(agentID string) []Command {
	m.mu.Lock()
	defer m.mu.Unlock()
	pending := m.commands[agentID]
	delete(m.commands, agentID)
	return pending
}

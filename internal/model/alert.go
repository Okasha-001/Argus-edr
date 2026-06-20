package model

import "time"

// Technique is the MITRE ATT&CK technique a rule maps to.
type Technique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic,omitempty"`
}

// ResponseRecord captures what the responder did about an alert.
type ResponseRecord struct {
	Action string `json:"action"`
	Result string `json:"result"`
}

// Alert is a single rule firing on a single event.
type Alert struct {
	Timestamp   time.Time       `json:"@timestamp"`
	RuleID      string          `json:"rule_id"`
	RuleName    string          `json:"rule_name"`
	Description string          `json:"description,omitempty"`
	Severity    Severity        `json:"severity"`
	Technique   Technique       `json:"technique"`
	RiskScore   int             `json:"risk_score,omitempty"`
	Event       *Event          `json:"event"`
	Response    *ResponseRecord `json:"response,omitempty"`

	// RequestedAction is the response a rule asks for ("kill", "network_block",
	// ...); empty means the responder picks a default from the severity.
	RequestedAction string `json:"-"`
}

// IncidentStatus tracks the lifecycle of a correlated incident.
type IncidentStatus string

const (
	IncidentOpen IncidentStatus = "open"
)

// Incident is a correlated chain of alerts on one process tree whose combined
// risk crossed the configured threshold — the unit a responder acts on.
type Incident struct {
	ID         string         `json:"id"`
	Host       string         `json:"host,omitempty"`
	ProcessKey string         `json:"process_key"`
	RiskScore  int            `json:"risk_score"`
	Techniques []string       `json:"techniques"`
	RuleIDs    []string       `json:"rule_ids"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Status     IncidentStatus `json:"status"`
	Summary    string         `json:"summary"`
}

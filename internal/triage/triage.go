// Package triage turns a structured ARGUS incident into a natural-language triage
// report — "what happened, how bad, what to do". It is a leaf utility (it imports
// nothing from ARGUS) so both the agent and the control plane can use it.
//
// The template summarizer is deterministic and works with no network — it renders
// a factual summary, severity, and concrete containment steps from the incident's
// own fields.
package triage

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Technique is one ATT&CK technique observed in the incident.
type Technique struct {
	ID     string
	Name   string
	Tactic string
}

// Alert is one detection that contributed to the incident.
type Alert struct {
	RuleID    string
	RuleName  string
	Severity  string
	Technique string
}

// Incident is the structured input to triage: the incident plus the context a
// human analyst would want — the process, its risk, the techniques and the alerts.
type Incident struct {
	ID          string
	Hostname    string
	ProcessName string
	PID         uint32
	RiskScore   int
	Techniques  []Technique
	Alerts      []Alert
}

// Report is the triage output.
type Report struct {
	Summary     string   `json:"summary"`
	Severity    string   `json:"severity"`
	Containment []string `json:"containment"`
	RuleDraft   string   `json:"rule_draft"`
	Source      string   `json:"source"`
}

// Summarizer turns a structured incident into a triage report.
type Summarizer interface {
	Summarize(ctx context.Context, incident Incident) (Report, error)
}

// ProviderTemplate is the provider name for the built-in template summarizer.
const ProviderTemplate = "template"

// New returns a Summarizer. The template summarizer is deterministic, works
// offline, and is the default for all environments.
func New() Summarizer {
	return &templateSummarizer{}
}

// templateSummarizer renders a factual report from the incident's own fields with
// no network call. It is deterministic, which is what makes triage testable.
type templateSummarizer struct{}

func (t *templateSummarizer) Summarize(_ context.Context, incident Incident) (Report, error) {
	return Report{
		Summary:     templateSummary(incident),
		Severity:    SeverityForRisk(incident.RiskScore),
		Containment: containmentSteps(incident),
		Source:      ProviderTemplate,
	}, nil
}

func templateSummary(incident Incident) string {
	host := orUnknown(incident.Hostname)
	process := orUnknown(incident.ProcessName)
	techniques := techniqueList(incident.Techniques)
	highSeverity := countSeverity(incident.Alerts, "high") + countSeverity(incident.Alerts, "critical")
	return fmt.Sprintf(
		"Host %s: process %s (pid %d) accumulated risk %d across %d ATT&CK technique(s) — %s. "+
			"%d detection(s) fired, %d high-or-critical. Review the process tree on %s and the "+
			"destinations it contacted before deciding on containment.",
		host, process, incident.PID, incident.RiskScore, len(incident.Techniques), techniques,
		len(incident.Alerts), highSeverity, host)
}

func techniqueList(techniques []Technique) string {
	if len(techniques) == 0 {
		return "no mapped technique"
	}
	parts := make([]string, 0, len(techniques))
	for _, technique := range techniques {
		parts = append(parts, strings.TrimSpace(technique.ID+" "+technique.Name))
	}
	return strings.Join(parts, ", ")
}

func countSeverity(alerts []Alert, severity string) int {
	count := 0
	for _, alert := range alerts {
		if strings.EqualFold(alert.Severity, severity) {
			count++
		}
	}
	return count
}

// Risk thresholds match the response ladder (internal/respond): an incident that
// would trigger network-block/kill should read as high/critical here too.
const (
	riskCritical = 90
	riskHigh     = 75
	riskMedium   = 50
)

// SeverityForRisk maps a risk score to a severity label.
func SeverityForRisk(risk int) string {
	switch {
	case risk >= riskCritical:
		return "critical"
	case risk >= riskHigh:
		return "high"
	case risk >= riskMedium:
		return "medium"
	default:
		return "low"
	}
}

// containmentSteps derives concrete actions from the tactics present, deduped and
// ordered, always ending with the evidence-preservation step.
func containmentSteps(incident Incident) []string {
	host := orUnknown(incident.Hostname)
	steps := make([]string, 0, 4)
	seen := map[string]bool{}
	add := func(step string) {
		if !seen[step] {
			seen[step] = true
			steps = append(steps, step)
		}
	}
	for _, technique := range incident.Techniques {
		if hint := tacticHint(technique.Tactic, host, incident.ProcessName, incident.PID); hint != "" {
			add(hint)
		}
	}
	add(fmt.Sprintf("Snapshot %s and preserve volatile memory before remediation.", host))
	return steps
}

func tacticHint(tactic, host, process string, pid uint32) string {
	switch strings.ToLower(strings.TrimSpace(tactic)) {
	case "execution", "privilege-escalation":
		return fmt.Sprintf("Kill the offending process %s (pid %d) and isolate %s from the network.", orUnknown(process), pid, host)
	case "command-and-control", "exfiltration":
		return fmt.Sprintf("Block egress from %s and capture the destination for threat-intel.", host)
	case "credential-access":
		return fmt.Sprintf("Rotate credentials exposed on %s and review its authentication logs.", host)
	case "persistence":
		return fmt.Sprintf("Audit %s for persistence (cron, systemd units, modified binaries).", host)
	case "defense-evasion":
		return fmt.Sprintf("Preserve forensic state on %s — the actor attempted to evade detection.", host)
	default:
		return ""
	}
}

func orUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

// sortedTactics returns the distinct tactics in the incident, used by the
// template to summarize the kill chain.
func sortedTactics(techniques []Technique) []string {
	seen := map[string]bool{}
	var tactics []string
	for _, technique := range techniques {
		tactic := strings.TrimSpace(technique.Tactic)
		if tactic != "" && !seen[tactic] {
			seen[tactic] = true
			tactics = append(tactics, tactic)
		}
	}
	sort.Strings(tactics)
	return tactics
}

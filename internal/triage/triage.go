// Package triage turns a structured ARGUS incident into a natural-language triage
// report — "what happened, how bad, what to do". It is a leaf utility (it imports
// nothing from ARGUS) so both the agent and the control plane can use it.
//
// Two summarizers implement the same interface. The template summarizer is
// deterministic and works with no network — it is the default and the test path.
// The Claude summarizer (claude.go) calls an LLM for a richer narrative and is
// used only when explicitly enabled with an API key; on any failure it falls back
// to the template, so triage always returns a report and a misconfiguration never
// breaks the caller. No incident data leaves the process unless the operator turns
// the Claude provider on and supplies a key.
package triage

import (
	"context"
	"fmt"
	"log/slog"
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

// Report is the triage output. Source records which summarizer produced it so the
// console can tell an analyst whether they are reading a template or an LLM summary.
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

// Provider names for Config.Provider.
const (
	ProviderTemplate = "template"
	ProviderClaude   = "claude"
)

// Config selects and configures a Summarizer. APIKey is read from the environment
// by the caller, never from a config file, so a secret is never committed.
type Config struct {
	Enabled   bool
	Provider  string
	APIKey    string
	Model     string
	Endpoint  string
	MaxTokens int
}

// New returns the Summarizer the config asks for. It returns the template
// summarizer unless the Claude provider is explicitly enabled with a key, in which
// case it returns a Claude summarizer that falls back to the template on any error.
// This is the single seam that enforces "no data leaves without explicit opt-in".
func New(cfg Config, logger *slog.Logger) Summarizer {
	template := &templateSummarizer{}
	if !cfg.Enabled || cfg.Provider != ProviderClaude || cfg.APIKey == "" {
		return template
	}
	return &fallbackSummarizer{primary: newClaudeSummarizer(cfg), fallback: template, logger: logger}
}

// fallbackSummarizer tries the primary (Claude) summarizer and falls back to the
// template on any error, so a network blip, a refusal or a bad key degrades to a
// deterministic report rather than failing the request.
type fallbackSummarizer struct {
	primary  Summarizer
	fallback Summarizer
	logger   *slog.Logger
}

func (f *fallbackSummarizer) Summarize(ctx context.Context, incident Incident) (Report, error) {
	report, err := f.primary.Summarize(ctx, incident)
	if err != nil {
		if f.logger != nil {
			f.logger.Warn("triage provider failed, using template summary", "err", err)
		}
		return f.fallback.Summarize(ctx, incident)
	}
	return report, nil
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

// SeverityForRisk maps a risk score to a severity label, shared so the template and
// the Claude prompt agree on the same scale.
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

// sortedTactics returns the distinct tactics in the incident, used by the Claude
// prompt to summarize the kill chain.
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

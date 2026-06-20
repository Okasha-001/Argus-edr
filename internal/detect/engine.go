package detect

import (
	"fmt"
	"strings"

	"github.com/argus-edr/argus/internal/model"
)

// Result is the outcome of evaluating one event: the alerts it triggered and,
// when the correlated risk crossed the threshold, the incident that opened.
type Result struct {
	Alerts   []*model.Alert
	Incident *model.Incident
}

// IntelSource supplies threat-intel matches for an event. When attached to the
// engine, each indicator hit becomes an alert that flows through correlation,
// response and output exactly like a rule match.
type IntelSource interface {
	Match(*model.Event) []model.IntelHit
}

// Engine evaluates every event against the rule set and feeds the matches to the
// correlator. It holds no mutable per-event state, so the caller controls
// ordering (the pipeline evaluates events one at a time, in order).
type Engine struct {
	rules      []*Rule
	correlator *Correlator
	intel      IntelSource
}

// NewEngine builds an engine. A nil correlator disables correlation.
func NewEngine(rules []*Rule, correlator *Correlator) *Engine {
	return &Engine{rules: rules, correlator: correlator}
}

// SetIntel attaches (or, with nil, detaches) a threat-intel matcher.
func (e *Engine) SetIntel(source IntelSource) {
	e.intel = source
}

// Rules returns the loaded rules, primarily for the `rules` CLI command.
func (e *Engine) Rules() []*Rule {
	return e.rules
}

// Evaluate runs the rules — and the threat-intel matcher, if set — against one
// event.
func (e *Engine) Evaluate(event *model.Event) Result {
	var alerts []*model.Alert
	for _, rule := range e.rules {
		if rule.Matches(event) {
			alerts = append(alerts, rule.ToAlert(event))
		}
	}
	if e.intel != nil {
		for _, hit := range e.intel.Match(event) {
			alerts = append(alerts, intelAlert(event, hit))
		}
	}

	result := Result{Alerts: alerts}
	if e.correlator != nil {
		result.Incident = e.correlator.Observe(event, alerts)
	}
	return result
}

// intelAlert turns a threat-intel hit into a high-severity alert. Network
// indicators are tagged as C2 (T1071); a malicious-hash hit carries no technique
// because it is identity, not behaviour.
func intelAlert(event *model.Event, hit model.IntelHit) *model.Alert {
	var technique model.Technique
	switch hit.Type {
	case "ip", "domain":
		technique = model.Technique{ID: "T1071", Name: "Application Layer Protocol", Tactic: "command-and-control"}
	}
	return &model.Alert{
		Timestamp:   event.Timestamp,
		RuleID:      "INTEL-" + strings.ToUpper(hit.Type),
		RuleName:    "Threat intel match",
		Description: fmt.Sprintf("%s %q matched an indicator from feed %s", hit.Field, hit.Indicator, hit.Source),
		Severity:    model.SeverityHigh,
		Technique:   technique,
		RiskScore:   60,
		Event:       event,
	}
}

package detect

import "github.com/argus-edr/argus/internal/model"

// Rule is a compiled detection: a condition tree plus the metadata attached to
// any alert it produces.
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    model.Severity
	Technique   model.Technique
	Enabled     bool
	RiskScore   int
	Response    string
	Match       *Condition
}

// Matches reports whether the rule is enabled and its condition fires.
func (r *Rule) Matches(event *model.Event) bool {
	return r.Enabled && r.Match.Eval(event)
}

// ToAlert builds the alert for an event this rule matched.
func (r *Rule) ToAlert(event *model.Event) *model.Alert {
	return &model.Alert{
		Timestamp:       event.Timestamp,
		RuleID:          r.ID,
		RuleName:        r.Name,
		Description:     r.Description,
		Severity:        r.Severity,
		Technique:       r.Technique,
		RiskScore:       r.RiskScore,
		Event:           event,
		RequestedAction: r.Response,
	}
}

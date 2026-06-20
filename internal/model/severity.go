package model

import "fmt"

// Severity is an ordered alert level; higher values are more urgent, which lets
// the responder and routing logic compare them directly.
type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "unknown"
}

// MarshalJSON emits the textual severity so alerts read naturally downstream.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// ParseSeverity converts a rule's textual severity into the ordered type.
func ParseSeverity(text string) (Severity, error) {
	for severity, name := range severityNames {
		if name == text {
			return severity, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want low|medium|high|critical)", text)
}

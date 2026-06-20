// Package sigma converts upstream Sigma detection rules into the native ARGUS
// rule format. It maps Sigma logsource categories to ARGUS event types, Sigma
// fields to ARGUS rule fields, and compiles the Sigma detection block —
// selections plus the condition expression — into an ARGUS condition tree.
//
// The supported subset targets Linux endpoint telemetry: the process_creation,
// network_connection, dns_query and file_* categories, the common value
// modifiers (contains/startswith/endswith/re/cidr/all), and condition
// expressions built from and/or/not, parentheses and all/1/any quantifiers.
// Anything outside that subset is reported as an *UnsupportedError so a bulk
// import can skip a rule cleanly instead of emitting a broken one.
package sigma

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// UnsupportedError marks a Sigma rule that is valid but uses a feature ARGUS
// cannot represent. Callers use IsUnsupported to skip such rules during a bulk
// import while still failing on genuinely malformed input.
type UnsupportedError struct {
	Reason string
}

func (e *UnsupportedError) Error() string {
	return "unsupported sigma feature: " + e.Reason
}

// IsUnsupported reports whether err is (or wraps) an UnsupportedError.
func IsUnsupported(err error) bool {
	var unsupported *UnsupportedError
	return errors.As(err, &unsupported)
}

// sigmaRule is the subset of the Sigma schema the importer reads.
type sigmaRule struct {
	Title       string   `yaml:"title"`
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Level       string   `yaml:"level"`
	Tags        []string `yaml:"tags"`
	Logsource   struct {
		Category string `yaml:"category"`
		Product  string `yaml:"product"`
	} `yaml:"logsource"`
	Detection map[string]yaml.Node `yaml:"detection"`
}

// Convert parses one Sigma rule document and compiles it into an ARGUS rule.
func Convert(data []byte) (*Rule, error) {
	var rule sigmaRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parse sigma rule: %w", err)
	}
	if strings.TrimSpace(rule.Title) == "" {
		return nil, errors.New("sigma rule has no title")
	}
	if product := strings.ToLower(rule.Logsource.Product); product != "" && product != "linux" {
		return nil, &UnsupportedError{Reason: fmt.Sprintf("logsource product %q (ARGUS is Linux-only)", rule.Logsource.Product)}
	}
	action, ok := categoryActions[strings.ToLower(rule.Logsource.Category)]
	if !ok {
		return nil, &UnsupportedError{Reason: fmt.Sprintf("logsource category %q", rule.Logsource.Category)}
	}
	if len(rule.Detection) == 0 {
		return nil, errors.New("sigma rule has no detection block")
	}

	detection, err := compileDetection(rule.Detection)
	if err != nil {
		return nil, err
	}

	severity := severityFor(rule.Level)
	return &Rule{doc: ruleDoc{
		ID:          ruleID(rule),
		Name:        rule.Title,
		Description: strings.TrimSpace(rule.Description),
		Severity:    severity,
		Technique:   techniqueFor(rule.Tags),
		RiskScore:   severityRisks[severity],
		Match:       anchorToAction(action, detection),
	}}, nil
}

// anchorToAction ANDs the event-type guard with the detection condition,
// flattening when the detection is itself an AND group so the tree stays shallow.
func anchorToAction(action string, detection *condDoc) *condDoc {
	guard := leaf("event.action", "eq", action)
	if isAndGroup(detection) {
		return &condDoc{All: append([]*condDoc{guard}, detection.All...)}
	}
	return &condDoc{All: []*condDoc{guard, detection}}
}

func isAndGroup(condition *condDoc) bool {
	return len(condition.All) > 0 && condition.Any == nil && condition.Not == nil && condition.Field == ""
}

// ruleID derives a stable ARGUS id from the Sigma rule's UUID, falling back to a
// hash of the title when the rule carries no id.
func ruleID(rule sigmaRule) string {
	if compact := strings.ReplaceAll(rule.ID, "-", ""); len(compact) >= 8 {
		return "SIGMA-" + strings.ToUpper(compact[:8])
	}
	digest := sha1.Sum([]byte(rule.Title))
	return "SIGMA-" + strings.ToUpper(hex.EncodeToString(digest[:])[:8])
}

package sigma

import (
	"regexp"
	"strings"
)

// categoryActions maps a Sigma logsource category to the ARGUS event action a
// rule of that category must observe. Every converted rule is anchored with an
// `event.action eq <action>` leaf so a process_creation rule never fires on,
// say, a network event. Categories absent here are unsupported.
var categoryActions = map[string]string{
	"process_creation":   "exec",
	"network_connection": "connect",
	"dns_query":          "connect",
	"file_event":         "open",
	"file_change":        "chmod",
	"file_delete":        "unlink",
	"file_rename":        "rename",
}

// sigmaFields maps a Sigma field name (lower-cased, modifier stripped) to the
// ARGUS rule field that backs it. Only fields a sensor actually emits appear
// here; an unmapped field makes the rule unconvertible rather than silently
// never matching.
var sigmaFields = map[string]string{
	"image":               "process.executable",
	"originalfilename":    "process.name",
	"commandline":         "process.command_line",
	"parentimage":         "process.parent.executable",
	"parentprocessname":   "process.parent.name",
	"user":                "user.name",
	"username":            "user.name",
	"processid":           "process.pid",
	"parentprocessid":     "process.ppid",
	"sha256":              "process.hash.sha256",
	"destinationip":       "destination.ip",
	"destinationport":     "destination.port",
	"sourceip":            "source.ip",
	"sourceport":          "source.port",
	"destinationhostname": "dns.question.name",
	"query":               "dns.question.name",
	"queryname":           "dns.question.name",
	"targetfilename":      "file.path",
	"filename":            "file.path",
}

// argusField resolves a Sigma field name to its ARGUS counterpart.
func argusField(name string) (string, bool) {
	field, ok := sigmaFields[strings.ToLower(name)]
	return field, ok
}

// levelSeverities maps a Sigma level to an ARGUS severity, and severityRisks
// gives each severity a default risk score so converted rules contribute
// sensibly to incident correlation.
var levelSeverities = map[string]string{
	"informational": "low",
	"low":           "low",
	"medium":        "medium",
	"high":          "high",
	"critical":      "critical",
}

var severityRisks = map[string]int{
	"low":      25,
	"medium":   50,
	"high":     70,
	"critical": 90,
}

func severityFor(level string) string {
	if severity, ok := levelSeverities[strings.ToLower(level)]; ok {
		return severity
	}
	return "medium"
}

// tacticTags maps a Sigma `attack.<tactic>` tag to the hyphenated tactic name
// ARGUS uses in its ATT&CK mapping.
var tacticTags = map[string]string{
	"initial_access":       "initial-access",
	"execution":            "execution",
	"persistence":          "persistence",
	"privilege_escalation": "privilege-escalation",
	"defense_evasion":      "defense-evasion",
	"credential_access":    "credential-access",
	"discovery":            "discovery",
	"lateral_movement":     "lateral-movement",
	"collection":           "collection",
	"command_and_control":  "command-and-control",
	"exfiltration":         "exfiltration",
	"impact":               "impact",
	"reconnaissance":       "reconnaissance",
	"resource_development": "resource-development",
}

// techniqueTag matches a Sigma ATT&CK technique tag, e.g. attack.t1059.004.
var techniqueTag = regexp.MustCompile(`^attack\.(t\d{4}(?:\.\d{3})?)$`)

// techniqueFor extracts the ATT&CK technique id and tactic from a Sigma rule's
// tags, returning nil when none are present so an untagged rule omits the block.
func techniqueFor(tags []string) *techniqueDoc {
	doc := &techniqueDoc{}
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if match := techniqueTag.FindStringSubmatch(tag); match != nil {
			doc.ID = strings.ToUpper(match[1])
			continue
		}
		if tactic, ok := tacticTags[strings.TrimPrefix(tag, "attack.")]; ok {
			doc.Tactic = tactic
		}
	}
	if doc.ID == "" && doc.Tactic == "" {
		return nil
	}
	return doc
}

package cases

import (
	"fmt"
	"strings"
	"time"

	"github.com/argus-edr/argus/internal/triage"
)

// EvidenceRow is a resolved alert as it appears in a case report — the fields an
// analyst needs to follow the chain, and nothing machine-specific.
type EvidenceRow struct {
	RuleID    string
	RuleName  string
	Severity  string
	Technique string
	Time      time.Time
}

// ReportInput is everything Report needs: the case, the triage narrative
// (reusing internal/triage so the prose matches the console's triage panel), and
// the resolved evidence alerts.
type ReportInput struct {
	Case     Case
	Triage   triage.Report
	Evidence []EvidenceRow
}

// Report renders a case as a self-contained Markdown document for sharing or
// archiving. It contains only case data, alert metadata and the templated
// narrative — never usernames, paths or addresses from a developer's machine —
// so a report is safe to attach to a ticket.
func Report(in ReportInput) string {
	var b strings.Builder
	c := in.Case
	fmt.Fprintf(&b, "# %s — %s\n\n", c.ID, c.Title)
	writeField(&b, "Status", c.Status)
	writeField(&b, "Severity", c.Severity)
	writeField(&b, "Assignee", c.Assignee)
	writeField(&b, "Host", c.Host)
	if len(c.Tags) > 0 {
		writeField(&b, "Tags", strings.Join(c.Tags, ", "))
	}
	writeField(&b, "Opened", c.Created.Format(time.RFC3339))
	writeField(&b, "Updated", c.Updated.Format(time.RFC3339))

	if in.Triage.Summary != "" {
		fmt.Fprintf(&b, "\n## Summary\n\n%s\n", in.Triage.Summary)
	}
	if len(in.Triage.Containment) > 0 {
		b.WriteString("\n## Recommended containment\n\n")
		for _, step := range in.Triage.Containment {
			fmt.Fprintf(&b, "- %s\n", step)
		}
	}
	writeEvidence(&b, in.Evidence)
	writeComments(&b, c.Comments)
	return b.String()
}

func writeEvidence(b *strings.Builder, rows []EvidenceRow) {
	if len(rows) == 0 {
		return
	}
	b.WriteString("\n## Evidence\n\n")
	b.WriteString("| Time | Rule | Severity | Technique |\n|---|---|---|---|\n")
	for _, row := range rows {
		fmt.Fprintf(b, "| %s | %s %s | %s | %s |\n",
			row.Time.Format(time.RFC3339), row.RuleID, row.RuleName, row.Severity, row.Technique)
	}
}

func writeComments(b *strings.Builder, comments []Comment) {
	if len(comments) == 0 {
		return
	}
	b.WriteString("\n## Notes\n\n")
	for _, comment := range comments {
		fmt.Fprintf(b, "- **%s** (%s): %s\n", comment.Author, comment.Time.Format(time.RFC3339), comment.Body)
	}
}

func writeField(b *strings.Builder, label, value string) {
	if value != "" {
		fmt.Fprintf(b, "**%s:** %s  \n", label, value)
	}
}

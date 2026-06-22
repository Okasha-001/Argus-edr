package cases

import (
	"strings"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/triage"
)

func TestCaseLifecycle(t *testing.T) {
	store := NewMemory()

	created, err := store.Create(CreateInput{Title: "Reverse shell on web-01", Severity: "high", Host: "web-01", Evidence: []string{"a1"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" || created.Status != StatusOpen {
		t.Fatalf("new case = %+v", created)
	}

	if _, err := store.Assign(created.ID, "analyst-1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if _, err := store.AddComment(created.ID, Comment{Author: "analyst-1", Body: "Confirmed malicious."}); err != nil {
		t.Fatalf("comment: %v", err)
	}
	if _, err := store.AddEvidence(created.ID, "a1", "a2"); err != nil { // a1 is a dup
		t.Fatalf("evidence: %v", err)
	}
	closed, err := store.SetStatus(created.ID, StatusClosed)
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	if closed.Assignee != "analyst-1" || closed.Status != StatusClosed {
		t.Errorf("final case = %+v", closed)
	}
	if len(closed.Evidence) != 2 {
		t.Errorf("evidence should dedupe to [a1 a2], got %v", closed.Evidence)
	}
	if len(closed.Comments) != 1 || closed.Comments[0].Time.IsZero() {
		t.Errorf("comment not recorded with a timestamp: %+v", closed.Comments)
	}
}

func TestCreateRejectsEmptyTitleAndBadSeverity(t *testing.T) {
	store := NewMemory()
	if _, err := store.Create(CreateInput{Title: "  "}); err == nil {
		t.Error("empty title must be rejected")
	}
	if _, err := store.Create(CreateInput{Title: "x", Severity: "spicy"}); err == nil {
		t.Error("unknown severity must be rejected")
	}
}

func TestMutateUnknownCase(t *testing.T) {
	store := NewMemory()
	if _, err := store.SetStatus("CASE-9999", StatusClosed); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSetStatusValidates(t *testing.T) {
	store := NewMemory()
	c, _ := store.Create(CreateInput{Title: "x"})
	if _, err := store.SetStatus(c.ID, "frozen"); err == nil {
		t.Error("invalid status must be rejected")
	}
}

func TestListFiltersAndOrders(t *testing.T) {
	store := NewMemory()
	first, err := store.Create(CreateInput{Title: "first"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetStatus(first.ID, StatusClosed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(CreateInput{Title: "second"}); err != nil { // stays open
		t.Fatal(err)
	}

	open := store.List(Filter{Status: StatusOpen})
	if len(open) != 1 || open[0].Title != "second" {
		t.Errorf("open filter = %+v", open)
	}
	if all := store.List(Filter{}); len(all) != 2 || all[0].Title != "second" {
		t.Errorf("list should be newest-first, got %+v", all)
	}
}

func TestReportIsSelfContainedMarkdown(t *testing.T) {
	c := Case{
		ID: "CASE-0001", Title: "Reverse shell", Status: StatusClosed, Assignee: "analyst-1",
		Severity: "critical", Host: "web-01", Created: time.Unix(100, 0).UTC(), Updated: time.Unix(200, 0).UTC(),
		Comments: []Comment{{Author: "analyst-1", Body: "Contained.", Time: time.Unix(150, 0).UTC()}},
	}
	report := Report(ReportInput{
		Case:     c,
		Triage:   triage.Report{Summary: "A web service spawned a shell.", Containment: []string{"Isolate web-01."}},
		Evidence: []EvidenceRow{{RuleID: "R-0007", RuleName: "Reverse shell", Severity: "critical", Technique: "T1059", Time: time.Unix(120, 0).UTC()}},
	})
	for _, want := range []string{"# CASE-0001", "## Summary", "A web service spawned a shell.", "## Recommended containment", "Isolate web-01.", "## Evidence", "R-0007", "## Notes", "Contained."} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q\n---\n%s", want, report)
		}
	}
}

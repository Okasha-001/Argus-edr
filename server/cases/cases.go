// Package cases is the investigation case manager: it groups the alerts of an
// incident into a workable unit an analyst can assign, discuss, attach evidence
// to, move through a lifecycle, and export as a report. The Store interface keeps
// the default in-memory backend (single-binary mode) swappable for a durable one,
// the same way server/store and internal/eventstore began.
package cases

import (
	"fmt"
	"strings"
	"time"
)

// Case lifecycle states. A case opens, may move to triage while it is worked,
// and closes when resolved.
const (
	StatusOpen   = "open"
	StatusTriage = "triage"
	StatusClosed = "closed"
)

func validStatus(status string) bool {
	switch status {
	case StatusOpen, StatusTriage, StatusClosed:
		return true
	default:
		return false
	}
}

// Comment is one note on a case's thread.
type Comment struct {
	Author string    `json:"author"`
	Body   string    `json:"body"`
	Time   time.Time `json:"time"`
}

// Case is an investigation: a titled, assignable container for the alerts and
// notes that make up one incident.
type Case struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Status   string    `json:"status"`
	Assignee string    `json:"assignee,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Host     string    `json:"host,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	Evidence []string  `json:"evidence,omitempty"` // alert ids gathered into the case
	Comments []Comment `json:"comments,omitempty"`
	Created  time.Time `json:"created"`
	Updated  time.Time `json:"updated"`
}

// CreateInput is the minimum needed to open a case. Title is required; the rest
// is optional context carried from the incident that prompted it.
type CreateInput struct {
	Title    string
	Severity string
	Host     string
	Tags     []string
	Evidence []string
}

// Filter narrows a List. A zero value returns every case, newest first.
type Filter struct {
	Status   string
	Assignee string
}

// Store persists cases. Implementations must be safe for concurrent use.
type Store interface {
	Create(input CreateInput) (Case, error)
	Get(id string) (Case, bool)
	List(filter Filter) []Case
	Assign(id, assignee string) (Case, error)
	SetStatus(id, status string) (Case, error)
	AddComment(id string, comment Comment) (Case, error)
	AddEvidence(id string, alertIDs ...string) (Case, error)
}

// ErrNotFound is returned by mutating operations on an unknown case id.
var ErrNotFound = fmt.Errorf("case not found")

func validateCreate(input CreateInput) error {
	if strings.TrimSpace(input.Title) == "" {
		return fmt.Errorf("a case needs a title")
	}
	if input.Severity != "" && severityRank(input.Severity) == 0 {
		return fmt.Errorf("unknown severity %q", input.Severity)
	}
	return nil
}

var severityOrder = map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

func severityRank(severity string) int { return severityOrder[strings.ToLower(severity)] }

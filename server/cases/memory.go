package cases

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Memory is the in-process case store: the default backend, with no
// infrastructure. A durable backend (sqlite/postgres) implements the same Store
// interface for fleets that must keep cases across restarts.
type Memory struct {
	mu    sync.Mutex
	seq   int
	byID  map[string]*Case
	clock func() time.Time
}

// NewMemory returns an empty in-memory case store.
func NewMemory() *Memory {
	return &Memory{byID: map[string]*Case{}, clock: time.Now}
}

func (m *Memory) Create(input CreateInput) (Case, error) {
	if err := validateCreate(input); err != nil {
		return Case{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock().UTC()
	m.seq++
	c := &Case{
		ID:       fmt.Sprintf("CASE-%04d", m.seq),
		Title:    input.Title,
		Status:   StatusOpen,
		Severity: input.Severity,
		Host:     input.Host,
		Tags:     append([]string(nil), input.Tags...),
		Evidence: dedupeAppend(nil, input.Evidence...),
		Created:  now,
		Updated:  now,
	}
	m.byID[c.ID] = c
	return *c, nil
}

func (m *Memory) Get(id string) (Case, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[id]
	if !ok {
		return Case{}, false
	}
	return *c, true
}

func (m *Memory) List(filter Filter) []Case {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Case, 0, len(m.byID))
	for _, c := range m.byID {
		if filter.Status != "" && c.Status != filter.Status {
			continue
		}
		if filter.Assignee != "" && c.Assignee != filter.Assignee {
			continue
		}
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// mutate applies fn to a case under the lock and stamps it updated, the single
// guarded path every change goes through so concurrency and the timestamp are
// handled once.
func (m *Memory) mutate(id string, fn func(*Case) error) (Case, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[id]
	if !ok {
		return Case{}, ErrNotFound
	}
	if err := fn(c); err != nil {
		return Case{}, err
	}
	c.Updated = m.clock().UTC()
	return *c, nil
}

func (m *Memory) Assign(id, assignee string) (Case, error) {
	return m.mutate(id, func(c *Case) error { c.Assignee = assignee; return nil })
}

func (m *Memory) SetStatus(id, status string) (Case, error) {
	return m.mutate(id, func(c *Case) error {
		if !validStatus(status) {
			return fmt.Errorf("invalid status %q (want open|triage|closed)", status)
		}
		c.Status = status
		return nil
	})
}

func (m *Memory) AddComment(id string, comment Comment) (Case, error) {
	return m.mutate(id, func(c *Case) error {
		if comment.Time.IsZero() {
			comment.Time = m.clock().UTC()
		}
		c.Comments = append(c.Comments, comment)
		return nil
	})
}

func (m *Memory) AddEvidence(id string, alertIDs ...string) (Case, error) {
	return m.mutate(id, func(c *Case) error {
		c.Evidence = dedupeAppend(c.Evidence, alertIDs...)
		return nil
	})
}

// dedupeAppend adds each id not already present, preserving order, so attaching
// the same alert twice does not list it twice.
func dedupeAppend(existing []string, ids ...string) []string {
	seen := make(map[string]bool, len(existing))
	for _, id := range existing {
		seen[id] = true
	}
	for _, id := range ids {
		if id != "" && !seen[id] {
			existing = append(existing, id)
			seen[id] = true
		}
	}
	return existing
}

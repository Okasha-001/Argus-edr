package soar

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// PlaybookStore holds playbooks in memory — the default backend, swappable for a
// durable one via the same methods. New playbooks default to dry-run so a freshly
// authored playbook can never act before it is reviewed and promoted.
type PlaybookStore struct {
	mu    sync.Mutex
	seq   int
	byID  map[string]*Playbook
	clock func() time.Time
}

// NewPlaybookStore returns an empty store.
func NewPlaybookStore() *PlaybookStore {
	return &PlaybookStore{byID: map[string]*Playbook{}, clock: time.Now}
}

func (s *PlaybookStore) Create(playbook Playbook) (Playbook, error) {
	if playbook.Mode == "" {
		playbook.Mode = ModeDryRun // safe default: never enforce on creation
	}
	if err := playbook.validate(); err != nil {
		return Playbook{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock().UTC()
	s.seq++
	playbook.ID = fmt.Sprintf("PB-%04d", s.seq)
	playbook.Created, playbook.Updated = now, now
	stored := playbook
	s.byID[playbook.ID] = &stored
	return stored, nil
}

func (s *PlaybookStore) Get(id string) (Playbook, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	playbook, ok := s.byID[id]
	if !ok {
		return Playbook{}, false
	}
	return *playbook, true
}

func (s *PlaybookStore) List() []Playbook {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Playbook, 0, len(s.byID))
	for _, playbook := range s.byID {
		out = append(out, *playbook)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Update replaces a playbook's mutable fields (name, mode, trigger, steps),
// re-validating the result. The id and creation time are preserved.
func (s *PlaybookStore) Update(id string, update Playbook) (Playbook, error) {
	if update.Mode == "" {
		update.Mode = ModeDryRun
	}
	if err := update.validate(); err != nil {
		return Playbook{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.byID[id]
	if !ok {
		return Playbook{}, fmt.Errorf("playbook %q not found", id)
	}
	existing.Name, existing.Mode, existing.Trigger, existing.Steps = update.Name, update.Mode, update.Trigger, update.Steps
	existing.Updated = s.clock().UTC()
	return *existing, nil
}

func (s *PlaybookStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return false
	}
	delete(s.byID, id)
	return true
}

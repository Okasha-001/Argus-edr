package eventstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

// Memory is an in-process event lake guarded by a mutex — enough for
// single-binary mode, tests and short investigations, with no persistence
// across restarts.
type Memory struct {
	mu     sync.RWMutex
	events []*model.Event
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{} }

func (m *Memory) Append(ctx context.Context, events ...*model.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, events...)
	return nil
}

func (m *Memory) Query(ctx context.Context, q Query) ([]*model.Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	matched := make([]*model.Event, 0)
	for _, event := range m.events {
		if q.matches(event) {
			matched = append(matched, event)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		if q.Ascending {
			return matched[i].Timestamp.Before(matched[j].Timestamp)
		}
		return matched[i].Timestamp.After(matched[j].Timestamp)
	})
	if len(matched) > q.limit() {
		matched = matched[:q.limit()]
	}
	return matched, nil
}

func (m *Memory) Count(ctx context.Context) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return int64(len(m.events)), nil
}

func (m *Memory) Prune(ctx context.Context, before time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.events[:0]
	var pruned int64
	for _, event := range m.events {
		if event.Timestamp.Before(before) {
			pruned++
			continue
		}
		kept = append(kept, event)
	}
	m.events = kept
	return pruned, nil
}

func (m *Memory) Close() error { return nil }

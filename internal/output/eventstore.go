package output

import (
	"context"

	"github.com/argus-edr/argus/internal/eventstore"
	"github.com/argus-edr/argus/internal/model"
)

// EventStoreSink persists every event into the queryable event lake
// (internal/eventstore) so hunting and investigation can search a host's
// history. Alerts and incidents are deliberately not stored here — they are kept
// by the control-plane store and the other sinks — so the lake stays a pure
// event record. The "memory" backend needs no files; "sqlite" is durable.
type EventStoreSink struct {
	store eventstore.Store
}

// NewEventStore opens the named event-lake backend ("memory" or "sqlite", the
// latter taking a database file path as its dsn).
func NewEventStore(backend, path string) (*EventStoreSink, error) {
	store, err := eventstore.Open(backend, path)
	if err != nil {
		return nil, err
	}
	return &EventStoreSink{store: store}, nil
}

func (s *EventStoreSink) WriteEvent(event *model.Event) error {
	return s.store.Append(context.Background(), event)
}

func (s *EventStoreSink) WriteAlert(*model.Alert) error       { return nil }
func (s *EventStoreSink) WriteIncident(*model.Incident) error { return nil }
func (s *EventStoreSink) Flush() error                        { return nil }
func (s *EventStoreSink) Close() error                        { return s.store.Close() }

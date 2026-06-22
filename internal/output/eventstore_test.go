package output

import (
	"context"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/eventstore"
	"github.com/argus-edr/argus/internal/model"
)

func TestEventStoreSinkPersistsEvents(t *testing.T) {
	sink, err := NewEventStore("memory", "")
	if err != nil {
		t.Fatalf("NewEventStore: %v", err)
	}
	defer sink.Close()

	event := &model.Event{Timestamp: time.Now(), Action: "exec", Host: "web-01"}
	event.Normalize()
	if err := sink.WriteEvent(event); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}

	// Alerts and incidents are not stored by the lake sink.
	if err := sink.WriteAlert(&model.Alert{}); err != nil {
		t.Fatalf("WriteAlert: %v", err)
	}

	got, err := sink.store.Query(context.Background(), eventstore.Query{Action: "exec"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 || got[0].Host != "web-01" {
		t.Fatalf("stored events = %#v", got)
	}
}

func TestEventStoreSinkRejectsUnknownBackend(t *testing.T) {
	if _, err := NewEventStore("redis", ""); err == nil {
		t.Fatal("expected an error for an unknown backend")
	}
}

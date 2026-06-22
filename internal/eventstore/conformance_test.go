package eventstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

// base is the reference time the sample events are anchored to.
var base = time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

// sampleEvents returns three events spanning two hosts and three actions, used
// by every conformance subtest.
func sampleEvents() []*model.Event {
	mk := func(action, host string, pid uint32, offset time.Duration, name string) *model.Event {
		event := &model.Event{
			Timestamp: base.Add(offset),
			Host:      host,
			Action:    action,
			Process:   model.Process{PID: pid, Name: name},
		}
		event.Normalize()
		return event
	}
	connect := mk("connect", "db-01", 300, 2*time.Minute, "curl")
	connect.Network = model.Network{DstIP: "203.0.113.5", Domain: "evil.example"}
	return []*model.Event{
		mk("exec", "web-01", 100, 0, "nginx"),
		mk("exec", "web-01", 200, time.Minute, "bash"),
		connect,
	}
}

// TestMemoryConformance and TestSQLiteConformance run the identical suite so the
// two backends are provably interchangeable behind the Store interface.
func TestMemoryConformance(t *testing.T) {
	runConformance(t, func(t *testing.T) Store { return NewMemory() })
}

func TestSQLiteConformance(t *testing.T) {
	runConformance(t, func(t *testing.T) Store {
		store, err := openSQLite(filepath.Join(t.TempDir(), "events.db"))
		if err != nil {
			t.Fatalf("openSQLite: %v", err)
		}
		return store
	})
}

func runConformance(t *testing.T, open func(*testing.T) Store) {
	ctx := context.Background()
	seed := func(t *testing.T) Store {
		store := open(t)
		t.Cleanup(func() { _ = store.Close() })
		if err := store.Append(ctx, sampleEvents()...); err != nil {
			t.Fatalf("append: %v", err)
		}
		return store
	}
	query := func(t *testing.T, store Store, q Query) []*model.Event {
		got, err := store.Query(ctx, q)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		return got
	}

	t.Run("count", func(t *testing.T) {
		store := seed(t)
		got, err := store.Count(ctx)
		if err != nil || got != 3 {
			t.Fatalf("count = %d, err = %v, want 3", got, err)
		}
	})

	t.Run("filter by action", func(t *testing.T) {
		got := query(t, seed(t), Query{Action: "exec"})
		if len(got) != 2 {
			t.Fatalf("got %d exec events, want 2", len(got))
		}
	})

	t.Run("filter by host", func(t *testing.T) {
		got := query(t, seed(t), Query{Host: "db-01"})
		if len(got) != 1 || got[0].Host != "db-01" {
			t.Fatalf("host filter = %#v", got)
		}
	})

	t.Run("filter by pid", func(t *testing.T) {
		got := query(t, seed(t), Query{PID: 200})
		if len(got) != 1 || got[0].Process.PID != 200 {
			t.Fatalf("pid filter = %#v", got)
		}
	})

	t.Run("time range", func(t *testing.T) {
		got := query(t, seed(t), Query{Since: base.Add(30 * time.Second), Until: base.Add(90 * time.Second)})
		if len(got) != 1 || got[0].Process.PID != 200 {
			t.Fatalf("time range = %#v", got)
		}
	})

	t.Run("contains", func(t *testing.T) {
		got := query(t, seed(t), Query{Contains: "EVIL"}) // case-insensitive
		if len(got) != 1 || got[0].Action != "connect" {
			t.Fatalf("contains = %#v", got)
		}
	})

	t.Run("limit", func(t *testing.T) {
		got := query(t, seed(t), Query{Limit: 1})
		if len(got) != 1 {
			t.Fatalf("limit = %d, want 1", len(got))
		}
	})

	t.Run("newest first by default", func(t *testing.T) {
		got := query(t, seed(t), Query{})
		if len(got) != 3 || !got[0].Timestamp.After(got[2].Timestamp) {
			t.Fatalf("ordering = %#v", got)
		}
	})

	t.Run("ascending", func(t *testing.T) {
		got := query(t, seed(t), Query{Ascending: true})
		if len(got) != 3 || got[0].Timestamp.After(got[2].Timestamp) {
			t.Fatalf("ascending ordering = %#v", got)
		}
	})

	t.Run("prune", func(t *testing.T) {
		store := seed(t)
		pruned, err := store.Prune(ctx, base.Add(90*time.Second))
		if err != nil || pruned != 2 {
			t.Fatalf("pruned = %d, err = %v, want 2", pruned, err)
		}
		remaining, _ := store.Count(ctx)
		if remaining != 1 {
			t.Fatalf("remaining = %d, want 1", remaining)
		}
	})
}

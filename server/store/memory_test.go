package store

import (
	"testing"
	"time"
)

func TestMemoryConformance(t *testing.T) {
	runStoreConformance(t, func(t *testing.T) Store { return NewMemory() })
}

func TestEnrollAndGet(t *testing.T) {
	store := NewMemory()
	agent := store.Enroll("web-01", "1.0", "6.8.0", "fp-web-01")
	if agent.ID == "" {
		t.Fatal("enroll returned an empty id")
	}
	got, ok := store.Get(agent.ID)
	if !ok || got.Hostname != "web-01" {
		t.Fatalf("Get = %+v, %v; want web-01", got, ok)
	}
	if len(store.List()) != 1 {
		t.Errorf("List should hold one agent")
	}
}

func TestHeartbeatUpdatesStats(t *testing.T) {
	store := NewMemory()
	agent := store.Enroll("web-01", "1.0", "6.8.0", "fp-web-01")

	updated, ok := store.Heartbeat(agent.ID, Stats{EventsProcessed: 42, Alerts: 3, RulesVersion: "abc"})
	if !ok {
		t.Fatal("heartbeat for a known agent should succeed")
	}
	if updated.EventsProcessed != 42 || updated.Alerts != 3 || updated.RulesVersion != "abc" {
		t.Errorf("stats not applied: %+v", updated)
	}
	if _, ok := store.Heartbeat("unknown", Stats{}); ok {
		t.Error("heartbeat for an unknown agent should fail")
	}
}

func TestOnline(t *testing.T) {
	base := time.Unix(1000, 0)
	agent := Agent{LastSeen: base}
	if !agent.Online(base.Add(30*time.Second), time.Minute) {
		t.Error("agent within ttl should be online")
	}
	if agent.Online(base.Add(2*time.Minute), time.Minute) {
		t.Error("agent past ttl should be offline")
	}
}

func TestCommandQueue(t *testing.T) {
	store := NewMemory()
	agent := store.Enroll("web-01", "1.0", "6.8.0", "fp-web-01")

	if store.EnqueueCommand("unknown", Command{Kind: "UPDATE_RULES"}) {
		t.Error("queueing for an unknown agent should fail")
	}
	if !store.EnqueueCommand(agent.ID, Command{Kind: "SET_RESPONSE_MODE", Argument: "dry-run"}) {
		t.Fatal("queueing for a known agent should succeed")
	}
	drained := store.DrainCommands(agent.ID)
	if len(drained) != 1 || drained[0].Kind != "SET_RESPONSE_MODE" {
		t.Fatalf("drained = %+v, want one SET_RESPONSE_MODE", drained)
	}
	if len(store.DrainCommands(agent.ID)) != 0 {
		t.Error("draining should clear the queue")
	}
}

func TestRecentAlertsOrderAndCap(t *testing.T) {
	store := NewMemory()
	for i := 0; i < maxRetainedAlerts+50; i++ {
		store.RecordAlert(AlertRecord{RuleID: "R", PID: uint32(i)})
	}
	if len(store.RecentAlerts(0)) != maxRetainedAlerts {
		t.Errorf("retained %d alerts, want the cap of %d", len(store.RecentAlerts(0)), maxRetainedAlerts)
	}
	recent := store.RecentAlerts(3)
	if len(recent) != 3 {
		t.Fatalf("limit not honoured: got %d", len(recent))
	}
	// Most recent first: the last recorded PID is the highest.
	if recent[0].PID < recent[1].PID {
		t.Error("recent alerts should be newest first")
	}
}

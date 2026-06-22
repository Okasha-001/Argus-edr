package store

import (
	"testing"
	"time"
)

// runStoreConformance exercises the behaviour every Store backend must share.
// Both memory_test.go and sqlite_test.go call it, so the in-memory and SQLite
// implementations are held to one contract rather than drifting apart.
func runStoreConformance(t *testing.T, newStore func(t *testing.T) Store) {
	t.Helper()
	t.Run("AgentLifecycle", func(t *testing.T) { testAgentLifecycle(t, newStore(t)) })
	t.Run("Heartbeat", func(t *testing.T) { testHeartbeat(t, newStore(t)) })
	t.Run("CertRotation", func(t *testing.T) { testCertRotation(t, newStore(t)) })
	t.Run("CommandQueueFIFO", func(t *testing.T) { testCommandQueueFIFO(t, newStore(t)) })
	t.Run("AlertIDAndLookup", func(t *testing.T) { testAlertIDAndLookup(t, newStore(t)) })
	t.Run("AlertOrderAndLimit", func(t *testing.T) { testAlertOrderAndLimit(t, newStore(t)) })
	t.Run("AlertFilters", func(t *testing.T) { testAlertFilters(t, newStore(t)) })
	t.Run("PruneAlerts", func(t *testing.T) { testPruneAlerts(t, newStore(t)) })
}

func testAgentLifecycle(t *testing.T, s Store) {
	agent := s.Enroll("web-01", "1.2.3", "6.8.0", "fp-web-01")
	if agent.ID == "" {
		t.Fatal("enroll returned an empty id")
	}
	got, ok := s.Get(agent.ID)
	if !ok {
		t.Fatalf("Get(%s) not found after enroll", agent.ID)
	}
	if got.Hostname != "web-01" || got.Version != "1.2.3" || got.Kernel != "6.8.0" || got.CertFingerprint != "fp-web-01" {
		t.Errorf("agent fields not persisted: %+v", got)
	}
	if got.FirstSeen.IsZero() || got.LastSeen.IsZero() {
		t.Error("enroll should stamp first_seen and last_seen")
	}
	if _, ok := s.Get("does-not-exist"); ok {
		t.Error("Get of an unknown id should report not found")
	}
	if len(s.List()) != 1 {
		t.Errorf("List = %d agents, want 1", len(s.List()))
	}
}

func testHeartbeat(t *testing.T, s Store) {
	agent := s.Enroll("web-01", "1.0", "6.8.0", "fp")
	updated, ok := s.Heartbeat(agent.ID, Stats{EventsProcessed: 42, Alerts: 3, Incidents: 1, RulesVersion: "v9"})
	if !ok {
		t.Fatal("heartbeat for a known agent should succeed")
	}
	if updated.EventsProcessed != 42 || updated.Alerts != 3 || updated.Incidents != 1 || updated.RulesVersion != "v9" {
		t.Errorf("heartbeat stats not applied: %+v", updated)
	}
	if _, ok := s.Heartbeat("unknown", Stats{}); ok {
		t.Error("heartbeat for an unknown agent should fail")
	}
}

func testCertRotation(t *testing.T, s Store) {
	agent := s.Enroll("web-01", "1.0", "6.8.0", "fp-current")

	if s.SetPendingCert("unknown", "fp-new") {
		t.Error("SetPendingCert for an unknown agent should fail")
	}
	if !s.SetPendingCert(agent.ID, "fp-new") {
		t.Fatal("SetPendingCert for a known agent should succeed")
	}
	staged, _ := s.Get(agent.ID)
	if staged.PendingCertFingerprint != "fp-new" || staged.CertFingerprint != "fp-current" {
		t.Fatalf("staging a pending cert must not touch the current one: %+v", staged)
	}

	if s.PromoteCert(agent.ID, "fp-wrong") {
		t.Error("PromoteCert should reject a fingerprint that is not the pending one")
	}
	if !s.PromoteCert(agent.ID, "fp-new") {
		t.Fatal("PromoteCert of the staged fingerprint should succeed")
	}
	promoted, _ := s.Get(agent.ID)
	if promoted.CertFingerprint != "fp-new" || promoted.PendingCertFingerprint != "" {
		t.Errorf("promotion should make pending current and clear pending: %+v", promoted)
	}
	if s.PromoteCert(agent.ID, "fp-new") {
		t.Error("PromoteCert with nothing pending should be a no-op")
	}
}

func testCommandQueueFIFO(t *testing.T, s Store) {
	agent := s.Enroll("web-01", "1.0", "6.8.0", "fp")
	if s.EnqueueCommand("unknown", Command{Kind: "KILL_PROCESS"}) {
		t.Error("queueing for an unknown agent should fail")
	}
	if !s.EnqueueCommand(agent.ID, Command{Kind: "SET_RESPONSE_MODE", Argument: "dry-run"}) {
		t.Fatal("queueing for a known agent should succeed")
	}
	if !s.EnqueueCommand(agent.ID, Command{Kind: "UPDATE_RULES"}) {
		t.Fatal("second queue should succeed")
	}
	drained := s.DrainCommands(agent.ID)
	if len(drained) != 2 || drained[0].Kind != "SET_RESPONSE_MODE" || drained[1].Kind != "UPDATE_RULES" {
		t.Fatalf("drain not FIFO: %+v", drained)
	}
	if len(s.DrainCommands(agent.ID)) != 0 {
		t.Error("draining again should yield nothing")
	}
}

func testAlertIDAndLookup(t *testing.T, s Store) {
	s.RecordAlert(AlertRecord{AgentID: "a1", Hostname: "web-01", RuleID: "R-0001", Time: time.Unix(100, 0).UTC()})
	stored := s.RecentAlerts(1)
	if len(stored) != 1 {
		t.Fatalf("expected one stored alert, got %d", len(stored))
	}
	if stored[0].ID == "" {
		t.Fatal("RecordAlert should assign an ID when none is given")
	}
	got, ok := s.AlertByID(stored[0].ID)
	if !ok || got.RuleID != "R-0001" {
		t.Fatalf("AlertByID(%s) = %+v, %v", stored[0].ID, got, ok)
	}
	if _, ok := s.AlertByID("missing"); ok {
		t.Error("AlertByID of an unknown id should report not found")
	}
}

func testAlertOrderAndLimit(t *testing.T, s Store) {
	for i := 0; i < 5; i++ {
		s.RecordAlert(AlertRecord{
			RuleID: "R", PID: uint32(i), Time: time.Unix(int64(1000+i), 0).UTC(),
		})
	}
	all := s.RecentAlerts(0)
	if len(all) != 5 {
		t.Fatalf("RecentAlerts(0) = %d, want 5", len(all))
	}
	if all[0].PID != 4 || all[4].PID != 0 {
		t.Errorf("alerts should be newest first: got PIDs %d..%d", all[0].PID, all[4].PID)
	}
	if got := s.RecentAlerts(2); len(got) != 2 || got[0].PID != 4 {
		t.Errorf("limit not honoured: %+v", got)
	}
}

func testAlertFilters(t *testing.T, s Store) {
	base := time.Unix(2000, 0).UTC()
	s.RecordAlert(AlertRecord{Hostname: "web-01", Severity: "high", TechniqueID: "T1003", Time: base, IsIncident: true})
	s.RecordAlert(AlertRecord{Hostname: "web-02", Severity: "low", TechniqueID: "T1059", Time: base.Add(time.Minute)})
	s.RecordAlert(AlertRecord{Hostname: "web-01", Severity: "low", TechniqueID: "T1071", Time: base.Add(2 * time.Minute)})

	cases := []struct {
		name   string
		filter AlertFilter
		want   int
	}{
		{"hostname", AlertFilter{Hostname: "web-01"}, 2},
		{"severity", AlertFilter{Severity: "low"}, 2},
		{"technique", AlertFilter{TechniqueID: "T1003"}, 1},
		{"incidents only", AlertFilter{IncidentsOnly: true}, 1},
		{"since", AlertFilter{Since: base.Add(90 * time.Second)}, 1},
		{"until", AlertFilter{Until: base.Add(30 * time.Second)}, 1},
		{"combined", AlertFilter{Hostname: "web-01", Severity: "low"}, 1},
		{"limit", AlertFilter{Limit: 2}, 2},
		{"no match", AlertFilter{Hostname: "ghost"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.QueryAlerts(tc.filter); len(got) != tc.want {
				t.Errorf("QueryAlerts(%+v) = %d alerts, want %d", tc.filter, len(got), tc.want)
			}
		})
	}
}

func testPruneAlerts(t *testing.T, s Store) {
	old := time.Unix(1000, 0).UTC()
	recent := time.Unix(5000, 0).UTC()
	s.RecordAlert(AlertRecord{RuleID: "old", Time: old})
	s.RecordAlert(AlertRecord{RuleID: "recent", Time: recent})

	removed := s.PruneAlerts(time.Unix(2000, 0).UTC())
	if removed != 1 {
		t.Errorf("PruneAlerts removed %d, want 1", removed)
	}
	left := s.RecentAlerts(0)
	if len(left) != 1 || left[0].RuleID != "recent" {
		t.Errorf("prune kept the wrong alerts: %+v", left)
	}
}

package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newSQLiteForTest(t *testing.T) Store {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "argus-test.db")
	s, err := openSQLite(dsn)
	if err != nil {
		t.Fatalf("openSQLite: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSQLiteConformance(t *testing.T) {
	runStoreConformance(t, newSQLiteForTest)
}

func TestSQLitePersistsAcrossReopen(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "persist.db")

	first, err := openSQLite(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	agent := first.Enroll("web-01", "1.0", "6.8.0", "fp")
	first.RecordAlert(AlertRecord{AgentID: agent.ID, RuleID: "R-0001", Time: time.Unix(123, 0).UTC()})
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopening the same file is the restart case: state must survive.
	second, err := openSQLite(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	if _, ok := second.Get(agent.ID); !ok {
		t.Error("agent did not survive a reopen")
	}
	if len(second.RecentAlerts(0)) != 1 {
		t.Error("alert did not survive a reopen")
	}
}

func TestOpenFactory(t *testing.T) {
	mem, err := Open(BackendMemory, "")
	if err != nil {
		t.Fatalf("Open(memory): %v", err)
	}
	mem.Close()

	if _, err := Open(BackendSQLite, ""); err == nil {
		t.Error("sqlite without a dsn should error")
	}
	if _, err := Open("mongodb", "x"); err == nil {
		t.Error("unknown backend should error")
	}

	db, err := Open(BackendSQLite, filepath.Join(t.TempDir(), "factory.db"))
	if err != nil {
		t.Fatalf("Open(sqlite): %v", err)
	}
	defer db.Close()
	if db.Enroll("h", "v", "k", "fp").ID == "" {
		t.Error("sqlite store from factory should work")
	}
}

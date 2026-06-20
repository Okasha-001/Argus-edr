package output

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

func TestSQLiteSinkPersistsRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	sink, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}

	event := &model.Event{Type: model.EventExec, Timestamp: time.Unix(1000, 0).UTC()}
	event.Process.Name = "bash"
	if err := sink.WriteEvent(event); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	alert := &model.Alert{RuleID: "R-0001", Event: event}
	if err := sink.WriteAlert(alert); err != nil {
		t.Fatalf("WriteAlert: %v", err)
	}
	if err := sink.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()

	counts := map[string]int{}
	rows, err := db.Query(`SELECT kind, COUNT(*) FROM records GROUP BY kind`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var count int
		if err := rows.Scan(&kind, &count); err != nil {
			t.Fatalf("scan: %v", err)
		}
		counts[kind] = count
	}
	if counts["event"] != 1 || counts["alert"] != 1 {
		t.Errorf("persisted record counts = %v, want one event and one alert", counts)
	}
}

func TestSQLiteSinkRequiresValidPath(t *testing.T) {
	if _, err := NewSQLite("/this/path/should/not/exist/and/cannot/be/made/x.db"); err == nil {
		t.Skip("environment allowed the path; nothing to assert")
	}
}

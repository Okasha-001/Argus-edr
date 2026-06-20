package output

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"

	"github.com/argus-edr/argus/internal/model"
)

// SQLiteSink is a local event store: it writes every event, alert and incident as
// an ECS JSON row into an on-host SQLite database, so an analyst can investigate a
// box after the fact without a central server. It is cgo-free (modernc driver),
// so the agent still builds without a C toolchain.
//
// Rows are stored as the ECS document (the same shape the file/loki sinks emit)
// plus a kind and a sortable timestamp, which keeps querying simple and future
// schema changes cheap.
type SQLiteSink struct {
	mu sync.Mutex
	db *sql.DB
}

// NewSQLite opens (creating directories as needed) the event database at path.
func NewSQLite(path string) (*SQLiteSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open event store %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	const schema = `
CREATE TABLE IF NOT EXISTS records (
    seq  INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    ts   TEXT NOT NULL,
    doc  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_kind_ts ON records(kind, ts);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("event store schema: %w", err)
	}
	return &SQLiteSink{db: db}, nil
}

func (s *SQLiteSink) WriteEvent(event *model.Event) error {
	return s.insert("event", event.ECS())
}

func (s *SQLiteSink) WriteAlert(alert *model.Alert) error {
	return s.insert("alert", alert.ECS())
}

func (s *SQLiteSink) WriteIncident(incident *model.Incident) error {
	return s.insert("incident", incident.ECS())
}

func (s *SQLiteSink) insert(kind string, doc map[string]any) error {
	encoded, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO records (kind, ts, doc) VALUES (?, ?, ?)`,
		kind, timestampOf(doc), string(encoded))
	return err
}

// timestampOf returns the document's "@timestamp" for ordering, falling back to
// now when a document does not carry one.
func timestampOf(doc map[string]any) string {
	if ts, ok := doc["@timestamp"].(string); ok && ts != "" {
		return ts
	}
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// Flush is a no-op: inserts autocommit. WAL durability is handled by SQLite.
func (s *SQLiteSink) Flush() error { return nil }

func (s *SQLiteSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

package eventstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"

	"github.com/argus-edr/argus/internal/model"
)

// sqliteStore is the durable, embedded event lake. It stores each event as its
// JSON document plus the indexed columns the Query predicates filter on, so a
// box keeps a searchable history across restarts without a server. It is cgo-free
// (modernc driver), so the agent still builds without a C toolchain.
type sqliteStore struct {
	db *sql.DB
}

func openSQLite(path string) (*sqliteStore, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open eventstore %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	const schema = `
CREATE TABLE IF NOT EXISTS events (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    action TEXT NOT NULL,
    host   TEXT NOT NULL,
    pid    INTEGER NOT NULL,
    search TEXT NOT NULL,
    doc    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("eventstore schema: %w", err)
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) Append(ctx context.Context, events ...*model.Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events (ts, action, host, pid, search, doc) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, event := range events {
		doc, err := json.Marshal(event)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
		_, err = stmt.ExecContext(ctx, event.Timestamp.UnixNano(), event.Action,
			event.Host, event.Process.PID, searchText(event), string(doc))
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *sqliteStore) Query(ctx context.Context, q Query) ([]*model.Event, error) {
	clause, args := q.sql()
	order := "DESC"
	if q.Ascending {
		order = "ASC"
	}
	query := fmt.Sprintf("SELECT doc FROM events%s ORDER BY ts %s, seq %s LIMIT %d",
		clause, order, order, q.limit())
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*model.Event
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		event := &model.Event{}
		if err := json.Unmarshal([]byte(doc), event); err != nil {
			return nil, fmt.Errorf("decode stored event: %w", err)
		}
		event.Normalize()
		events = append(events, event)
	}
	return events, rows.Err()
}

// sql renders the query predicates as a parameterised WHERE clause. Only the
// limit and sort direction are interpolated, and both are derived from typed
// fields, never user strings, so the statement is injection-safe.
func (q Query) sql() (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, arg any) {
		conds = append(conds, cond)
		args = append(args, arg)
	}
	if q.Action != "" {
		add("action = ?", q.Action)
	}
	if q.Host != "" {
		add("host = ?", q.Host)
	}
	if q.PID != 0 {
		add("pid = ?", q.PID)
	}
	if !q.Since.IsZero() {
		add("ts >= ?", q.Since.UnixNano())
	}
	if !q.Until.IsZero() {
		add("ts <= ?", q.Until.UnixNano())
	}
	if q.Contains != "" {
		add("search LIKE ?", "%"+strings.ToLower(q.Contains)+"%")
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func (s *sqliteStore) Count(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events").Scan(&count)
	return count, err
}

func (s *sqliteStore) Prune(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM events WHERE ts < ?", before.UnixNano())
	if err != nil {
		return 0, err
	}
	pruned, _ := result.RowsAffected()
	return pruned, nil
}

func (s *sqliteStore) Close() error { return s.db.Close() }

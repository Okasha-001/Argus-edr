package store

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

// SQLite is a durable Store backed by a single SQLite database. Unlike Memory it
// survives a control-plane restart, which is what lets the console show history.
//
// The driver is modernc.org/sqlite — a cgo-free, pure-Go translation of SQLite —
// so the server still builds without a C toolchain. Access is serialized with a
// single connection (SetMaxOpenConns(1)); a control plane's write volume is low
// (a heartbeat per agent every tens of seconds) and serialization removes every
// "database is locked" race at a negligible cost.
//
// The Store interface deliberately does not return errors on its hot methods, to
// mirror Memory. SQLite operational errors are therefore logged, not propagated.
type SQLite struct {
	db     *sql.DB
	logger *slog.Logger
	clock  func() time.Time
}

// openSQLite opens the database at dsn (a filesystem path or ":memory:"),
// attaches durability/concurrency pragmas, and creates the schema.
func openSQLite(dsn string) (*SQLite, error) {
	db, err := sql.Open("sqlite", withPragmas(dsn))
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", dsn, err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite %q: %w", dsn, err)
	}
	store := &SQLite{db: db, logger: slog.Default(), clock: time.Now}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// withPragmas appends the pragmas the store relies on to the DSN. WAL lets reads
// proceed alongside the single writer; busy_timeout absorbs brief contention.
func withPragmas(dsn string) string {
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	pragmas := "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	return dsn + separator + pragmas
}

func (s *SQLite) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS agents (
    id               TEXT PRIMARY KEY,
    hostname         TEXT NOT NULL,
    version          TEXT NOT NULL,
    kernel           TEXT NOT NULL,
    cert_fingerprint TEXT NOT NULL,
    first_seen       INTEGER NOT NULL,
    last_seen        INTEGER NOT NULL,
    events_processed INTEGER NOT NULL DEFAULT 0,
    alerts           INTEGER NOT NULL DEFAULT 0,
    incidents        INTEGER NOT NULL DEFAULT 0,
    rules_version    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS alerts (
    id                 TEXT PRIMARY KEY,
    agent_id           TEXT NOT NULL,
    hostname           TEXT NOT NULL,
    ts                 INTEGER NOT NULL,
    rule_id            TEXT NOT NULL,
    rule_name          TEXT NOT NULL,
    severity           TEXT NOT NULL,
    technique_id       TEXT NOT NULL,
    technique_name     TEXT NOT NULL,
    pid                INTEGER NOT NULL,
    process_name       TEXT NOT NULL,
    process_executable TEXT NOT NULL,
    destination_ip     TEXT NOT NULL,
    risk_score         INTEGER NOT NULL,
    is_incident        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);
CREATE TABLE IF NOT EXISTS commands (
    seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    kind     TEXT NOT NULL,
    argument TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_commands_agent ON commands(agent_id, seq);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

func (s *SQLite) Enroll(hostname, version, kernel, certFingerprint string) Agent {
	now := s.clock()
	agent := Agent{
		ID:              NewID(),
		Hostname:        hostname,
		Version:         version,
		Kernel:          kernel,
		CertFingerprint: certFingerprint,
		FirstSeen:       now,
		LastSeen:        now,
	}
	_, err := s.db.Exec(
		`INSERT INTO agents (id, hostname, version, kernel, cert_fingerprint, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		agent.ID, hostname, version, kernel, certFingerprint, now.UnixNano(), now.UnixNano())
	if err != nil {
		s.logger.Error("store: enroll agent", "err", err)
	}
	return agent
}

func (s *SQLite) Heartbeat(agentID string, stats Stats) (Agent, bool) {
	now := s.clock()
	result, err := s.db.Exec(
		`UPDATE agents SET last_seen = ?, events_processed = ?, alerts = ?, incidents = ?, rules_version = ?
		 WHERE id = ?`,
		now.UnixNano(), stats.EventsProcessed, stats.Alerts, stats.Incidents, stats.RulesVersion, agentID)
	if err != nil {
		s.logger.Error("store: heartbeat", "err", err)
		return Agent{}, false
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return Agent{}, false
	}
	return s.Get(agentID)
}

func (s *SQLite) Get(agentID string) (Agent, bool) {
	row := s.db.QueryRow(
		`SELECT id, hostname, version, kernel, cert_fingerprint, first_seen, last_seen,
		        events_processed, alerts, incidents, rules_version
		 FROM agents WHERE id = ?`, agentID)
	agent, err := scanAgent(row)
	if err == sql.ErrNoRows {
		return Agent{}, false
	}
	if err != nil {
		s.logger.Error("store: get agent", "err", err)
		return Agent{}, false
	}
	return agent, true
}

func (s *SQLite) List() []Agent {
	rows, err := s.db.Query(
		`SELECT id, hostname, version, kernel, cert_fingerprint, first_seen, last_seen,
		        events_processed, alerts, incidents, rules_version
		 FROM agents ORDER BY hostname`)
	if err != nil {
		s.logger.Error("store: list agents", "err", err)
		return nil
	}
	defer rows.Close()

	agents := make([]Agent, 0)
	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			s.logger.Error("store: scan agent", "err", err)
			return agents
		}
		agents = append(agents, agent)
	}
	return agents
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanAgent(row rowScanner) (Agent, error) {
	var agent Agent
	var firstSeen, lastSeen int64
	err := row.Scan(&agent.ID, &agent.Hostname, &agent.Version, &agent.Kernel,
		&agent.CertFingerprint, &firstSeen, &lastSeen,
		&agent.EventsProcessed, &agent.Alerts, &agent.Incidents, &agent.RulesVersion)
	if err != nil {
		return Agent{}, err
	}
	agent.FirstSeen = time.Unix(0, firstSeen).UTC()
	agent.LastSeen = time.Unix(0, lastSeen).UTC()
	return agent, nil
}

func (s *SQLite) RecordAlert(record AlertRecord) {
	if record.ID == "" {
		record.ID = NewID()
	}
	_, err := s.db.Exec(
		`INSERT INTO alerts (id, agent_id, hostname, ts, rule_id, rule_name, severity,
		        technique_id, technique_name, pid, process_name, process_executable,
		        destination_ip, risk_score, is_incident)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID, record.AgentID, record.Hostname, record.Time.UnixNano(),
		record.RuleID, record.RuleName, record.Severity, record.TechniqueID,
		record.TechniqueName, record.PID, record.ProcessName, record.ProcessExecutable,
		record.DestinationIP, record.RiskScore, boolToInt(record.IsIncident))
	if err != nil {
		s.logger.Error("store: record alert", "err", err)
	}
}

func (s *SQLite) RecentAlerts(limit int) []AlertRecord {
	return s.QueryAlerts(AlertFilter{Limit: limit})
}

// QueryAlerts builds a parameterized WHERE from the filter so the database does
// the matching, ordering (newest first) and limiting.
func (s *SQLite) QueryAlerts(filter AlertFilter) []AlertRecord {
	query, args := buildAlertQuery(filter)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		s.logger.Error("store: query alerts", "err", err)
		return nil
	}
	defer rows.Close()
	return s.scanAlerts(rows)
}

func buildAlertQuery(filter AlertFilter) (string, []any) {
	var clauses []string
	var args []any
	add := func(clause string, value any) {
		clauses = append(clauses, clause)
		args = append(args, value)
	}
	if filter.Hostname != "" {
		add("hostname = ?", filter.Hostname)
	}
	if filter.Severity != "" {
		add("severity = ?", filter.Severity)
	}
	if filter.TechniqueID != "" {
		add("technique_id = ?", filter.TechniqueID)
	}
	if filter.IncidentsOnly {
		add("is_incident = ?", 1)
	}
	if !filter.Since.IsZero() {
		add("ts >= ?", filter.Since.UnixNano())
	}
	if !filter.Until.IsZero() {
		add("ts <= ?", filter.Until.UnixNano())
	}

	query := `SELECT id, agent_id, hostname, ts, rule_id, rule_name, severity,
	        technique_id, technique_name, pid, process_name, process_executable,
	        destination_ip, risk_score, is_incident FROM alerts`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY ts DESC, rowid DESC"
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	return query, args
}

func (s *SQLite) scanAlerts(rows *sql.Rows) []AlertRecord {
	records := make([]AlertRecord, 0)
	for rows.Next() {
		record, err := scanAlert(rows)
		if err != nil {
			s.logger.Error("store: scan alert", "err", err)
			return records
		}
		records = append(records, record)
	}
	return records
}

func (s *SQLite) AlertByID(id string) (AlertRecord, bool) {
	row := s.db.QueryRow(
		`SELECT id, agent_id, hostname, ts, rule_id, rule_name, severity,
		        technique_id, technique_name, pid, process_name, process_executable,
		        destination_ip, risk_score, is_incident FROM alerts WHERE id = ?`, id)
	record, err := scanAlert(row)
	if err == sql.ErrNoRows {
		return AlertRecord{}, false
	}
	if err != nil {
		s.logger.Error("store: alert by id", "err", err)
		return AlertRecord{}, false
	}
	return record, true
}

func scanAlert(row rowScanner) (AlertRecord, error) {
	var record AlertRecord
	var ts int64
	var isIncident int
	err := row.Scan(&record.ID, &record.AgentID, &record.Hostname, &ts,
		&record.RuleID, &record.RuleName, &record.Severity, &record.TechniqueID,
		&record.TechniqueName, &record.PID, &record.ProcessName, &record.ProcessExecutable,
		&record.DestinationIP, &record.RiskScore, &isIncident)
	if err != nil {
		return AlertRecord{}, err
	}
	record.Time = time.Unix(0, ts).UTC()
	record.IsIncident = isIncident != 0
	return record, nil
}

func (s *SQLite) PruneAlerts(before time.Time) int {
	result, err := s.db.Exec(`DELETE FROM alerts WHERE ts < ?`, before.UnixNano())
	if err != nil {
		s.logger.Error("store: prune alerts", "err", err)
		return 0
	}
	removed, _ := result.RowsAffected()
	return int(removed)
}

func (s *SQLite) EnqueueCommand(agentID string, cmd Command) bool {
	if _, ok := s.Get(agentID); !ok {
		return false
	}
	_, err := s.db.Exec(
		`INSERT INTO commands (agent_id, kind, argument) VALUES (?, ?, ?)`,
		agentID, cmd.Kind, cmd.Argument)
	if err != nil {
		s.logger.Error("store: enqueue command", "err", err)
		return false
	}
	return true
}

// DrainCommands returns the agent's queued commands in FIFO order and deletes
// them. Reading and deleting run in one transaction so a command cannot be
// delivered twice or lost to a concurrent drain.
func (s *SQLite) DrainCommands(agentID string) []Command {
	tx, err := s.db.Begin()
	if err != nil {
		s.logger.Error("store: drain begin", "err", err)
		return nil
	}
	defer tx.Rollback() //nolint:errcheck // committed on the happy path; rollback is a no-op then

	rows, err := tx.Query(`SELECT kind, argument FROM commands WHERE agent_id = ? ORDER BY seq`, agentID)
	if err != nil {
		s.logger.Error("store: drain query", "err", err)
		return nil
	}
	var commands []Command
	for rows.Next() {
		var cmd Command
		if err := rows.Scan(&cmd.Kind, &cmd.Argument); err != nil {
			rows.Close()
			s.logger.Error("store: drain scan", "err", err)
			return nil
		}
		commands = append(commands, cmd)
	}
	rows.Close()

	if _, err := tx.Exec(`DELETE FROM commands WHERE agent_id = ?`, agentID); err != nil {
		s.logger.Error("store: drain delete", "err", err)
		return nil
	}
	if err := tx.Commit(); err != nil {
		s.logger.Error("store: drain commit", "err", err)
		return nil
	}
	return commands
}

func (s *SQLite) Close() error {
	return s.db.Close()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

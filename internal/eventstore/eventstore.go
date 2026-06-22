// Package eventstore is the queryable event lake behind ARGUS hunting and
// investigation. It keeps single-binary mode infrastructure-free: the default
// backends are an in-memory buffer (memory) and an embedded, cgo-free SQLite
// file (sqlite). A columnar backend (ClickHouse/DuckDB) implements the same
// Store interface for fleet-scale deployments — see docs/DATA_LAKE.md.
package eventstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

// Backend names accepted by Open.
const (
	BackendMemory = "memory"
	BackendSQLite = "sqlite"
)

// DefaultLimit caps a Query that does not set its own, so an open-ended hunt
// cannot load an entire lake into memory by accident.
const DefaultLimit = 1000

// Store is the queryable event lake. Implementations must be safe for
// concurrent use.
type Store interface {
	Append(ctx context.Context, events ...*model.Event) error
	Query(ctx context.Context, q Query) ([]*model.Event, error)
	Count(ctx context.Context) (int64, error)
	Prune(ctx context.Context, before time.Time) (int64, error)
	Close() error
}

// Query selects and orders stored events. A zero value matches everything and
// returns the newest DefaultLimit events.
type Query struct {
	Action    string    // event action verb ("exec", "connect", ...); "" = any
	Host      string    // exact host match; "" = any
	PID       uint32    // exact process id; 0 = any
	Since     time.Time // inclusive lower time bound; zero = unbounded
	Until     time.Time // inclusive upper time bound; zero = unbounded
	Contains  string    // case-insensitive substring across the searchable fields
	Limit     int       // <= 0 means DefaultLimit
	Ascending bool      // default false = newest first
}

func (q Query) limit() int {
	if q.Limit <= 0 {
		return DefaultLimit
	}
	return q.Limit
}

// Open returns a Store of the named kind. "memory" is ephemeral (lost on
// restart); "sqlite" is durable and takes a filesystem path as its dsn.
func Open(kind, dsn string) (Store, error) {
	switch kind {
	case BackendMemory, "":
		return NewMemory(), nil
	case BackendSQLite:
		if dsn == "" {
			return nil, fmt.Errorf("eventstore %q requires a dsn (database file path)", kind)
		}
		return openSQLite(dsn)
	default:
		return nil, fmt.Errorf("unknown eventstore %q (want memory|sqlite; clickhouse is the documented scale-out backend)", kind)
	}
}

// matches reports whether event satisfies every set field of the query. It is
// shared by the in-memory backend and the conformance tests; the SQLite backend
// pushes the same predicates into SQL and must agree with it.
func (q Query) matches(event *model.Event) bool {
	if q.Action != "" && event.Action != q.Action {
		return false
	}
	if q.Host != "" && event.Host != q.Host {
		return false
	}
	if q.PID != 0 && event.Process.PID != q.PID {
		return false
	}
	if !q.Since.IsZero() && event.Timestamp.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && event.Timestamp.After(q.Until) {
		return false
	}
	if q.Contains != "" && !strings.Contains(searchText(event), strings.ToLower(q.Contains)) {
		return false
	}
	return true
}

// searchText is the lowercased haystack a Contains query matches against. The
// SQLite backend stores the identical string in an indexed column so both
// backends agree on what "contains" means.
func searchText(event *model.Event) string {
	parts := []string{
		event.Process.Name, event.Process.Executable, event.Process.CommandLine,
		event.File.Path, event.File.Target, event.Network.DstIP, event.Network.Domain,
		event.Host,
	}
	return strings.ToLower(strings.Join(parts, " "))
}

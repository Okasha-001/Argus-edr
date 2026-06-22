package hunt

import (
	"context"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/eventstore"
	"github.com/argus-edr/argus/internal/model"
)

var t0 = time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

func lake(t *testing.T) eventstore.Store {
	t.Helper()
	mk := func(action, host string, offset time.Duration, fn func(*model.Event)) *model.Event {
		e := &model.Event{Timestamp: t0.Add(offset), Host: host, Action: action}
		fn(e)
		e.Normalize()
		return e
	}
	store := eventstore.NewMemory()
	events := []*model.Event{
		mk("exec", "web-01", 0, func(e *model.Event) { e.Process = model.Process{PID: 100, Name: "nginx"} }),
		mk("exec", "web-01", time.Minute, func(e *model.Event) { e.Process = model.Process{PID: 200, Name: "bash", ParentName: "nginx"} }),
		mk("connect", "web-01", 2*time.Minute, func(e *model.Event) { e.Network = model.Network{DstIP: "203.0.113.9", DstPort: 4444} }),
		mk("exec", "db-01", 0, func(e *model.Event) { e.Process = model.Process{PID: 300, Name: "curl"} }),
		mk("connect", "db-01", time.Minute, func(e *model.Event) { e.Network = model.Network{DstIP: "198.51.100.7", DstPort: 4444} }),
	}
	if err := store.Append(context.Background(), events...); err != nil {
		t.Fatalf("append: %v", err)
	}
	return store
}

func run(t *testing.T, store eventstore.Store, src string) Result {
	t.Helper()
	q, err := Compile(src)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	res, err := q.Run(context.Background(), store)
	if err != nil {
		t.Fatalf("run %q: %v", src, err)
	}
	return res
}

func TestSimpleQueries(t *testing.T) {
	store := lake(t)
	tests := []struct {
		src  string
		want int
	}{
		{`exec where process.name == "bash"`, 1},
		{`exec where process.name in ("bash", "curl")`, 2},
		{`exec where process.parent.name == "nginx"`, 1},
		{`connect where destination.port == 4444`, 2},
		{`connect where destination.port > 4000 | limit 1`, 1},
		{`event where host.name == "web-01"`, 3},
		{`any where not (host.name == "web-01")`, 2},
		{`exec where process.name startswith "ng"`, 1},
		{`connect where destination.ip =~ "^203\\."`, 1},
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			if got := run(t, store, tc.src).Count(); got != tc.want {
				t.Fatalf("count = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSequence(t *testing.T) {
	store := lake(t)
	// curl then a 4444 connect, on the same host, within 5m: only db-01 chains
	// (web-01 has the connect but no curl exec).
	src := `sequence by host.name within 5m:
		exec where process.name == "curl";
		connect where destination.port == 4444`
	res := run(t, store, src)
	if res.Count() != 1 {
		t.Fatalf("sequences = %d, want 1", res.Count())
	}
	chain := res.Sequences[0]
	if len(chain) != 2 || chain[0].Process.Name != "curl" || chain[1].Network.DstPort != 4444 {
		t.Fatalf("unexpected chain: %#v", chain)
	}
}

func TestSequenceWindowExcludes(t *testing.T) {
	store := lake(t)
	// The db-01 curl→connect gap is 1m; a 30s window must exclude it.
	src := `sequence by host.name within 30s:
		exec where process.name == "curl";
		connect where destination.port == 4444`
	if got := run(t, store, src).Count(); got != 0 {
		t.Fatalf("sequences = %d, want 0 (outside window)", got)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []string{
		`exec where bogus.field == "x"`,       // unknown field
		`exec where process.name =~ "("`,      // invalid regex
		`exec where process.name`,             // missing operator
		`sequence by host.name: exec where x`, // single stage + bad field
		`| limit 5`,                           // missing class
	}
	for _, src := range tests {
		t.Run(src, func(t *testing.T) {
			if _, err := Compile(src); err == nil {
				t.Fatalf("expected a compile error for %q", src)
			}
		})
	}
}

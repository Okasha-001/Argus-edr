package hunt

import (
	"context"
	"testing"

	"github.com/argus-edr/argus/internal/eventstore"
)

// FuzzCompile asserts the parser never panics on arbitrary input and that any
// query it accepts also runs without panicking against an empty lake.
func FuzzCompile(f *testing.F) {
	seeds := []string{
		`exec where process.name == "bash"`,
		`connect where destination.port == 4444 | limit 5`,
		`event where not (process.name contains "x" or user.id > 0)`,
		`sequence by host.name within 5m: exec where process.name == "curl"; connect where destination.port == 4444`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		query, err := Compile(src)
		if err != nil {
			return
		}
		if _, err := query.Run(context.Background(), eventstore.NewMemory()); err != nil {
			t.Fatalf("a compiled query failed to run: %v", err)
		}
	})
}

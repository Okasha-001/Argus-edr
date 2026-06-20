// Package pipeline wires a source of events through enrichment, detection,
// response and output. Events are processed one at a time, in order, because the
// process tree and correlator depend on observation order.
package pipeline

import (
	"context"

	"github.com/argus-edr/argus/internal/model"
)

// Source produces decoded events on out until ctx is cancelled (live sources) or
// the input is exhausted (replay). It must honour ctx promptly.
type Source interface {
	Run(ctx context.Context, out chan<- *model.Event) error
	Close() error
}

// Package bus is the event-streaming seam between ingestion and the consumers
// that fan out from it: the live console feed (SSE), the hunting engine and the
// event lake. The default in-process implementation needs no infrastructure, so
// single-binary mode stays dependency-free; a NATS JetStream implementation of
// the same interface is the documented scale-out path (see docs/DATA_LAKE.md).
package bus

import (
	"context"
	"errors"

	"github.com/argus-edr/argus/internal/model"
)

// ErrClosed is returned by Publish once the bus has been closed.
var ErrClosed = errors.New("event bus closed")

// EventBus fans every published event out to all active subscribers.
type EventBus interface {
	Publish(ctx context.Context, event *model.Event) error
	Subscribe(buffer int) Subscription
	Close() error
}

// Subscription is one consumer's view of the stream. A caller reads Events until
// the channel is closed and must Unsubscribe when done to free the slot.
type Subscription interface {
	Events() <-chan *model.Event
	Unsubscribe()
}

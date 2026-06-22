package bus

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/argus-edr/argus/internal/model"
)

// DefaultBuffer is the per-subscriber channel depth used when Subscribe is
// called with a non-positive buffer.
const DefaultBuffer = 1024

var _ EventBus = (*InProc)(nil)

// InProc is an in-process EventBus. Publish never blocks ingestion: an event is
// dropped (and counted) for any subscriber whose buffer is full, so one slow
// consumer cannot stall the pipeline.
type InProc struct {
	mu      sync.RWMutex
	subs    map[*subscription]struct{}
	closed  bool
	dropped atomic.Uint64
}

// NewInProc returns an empty in-process bus.
func NewInProc() *InProc {
	return &InProc{subs: make(map[*subscription]struct{})}
}

func (b *InProc) Publish(ctx context.Context, event *model.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrClosed
	}
	for sub := range b.subs {
		select {
		case sub.ch <- event:
		default:
			b.dropped.Add(1) // full buffer: drop rather than stall ingestion
		}
	}
	return nil
}

func (b *InProc) Subscribe(buffer int) Subscription {
	if buffer <= 0 {
		buffer = DefaultBuffer
	}
	sub := &subscription{bus: b, ch: make(chan *model.Event, buffer)}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs[sub] = struct{}{}
	return sub
}

// Dropped reports how many events were dropped to full subscriber buffers since
// the bus was created; the caller exposes it as a metric.
func (b *InProc) Dropped() uint64 { return b.dropped.Load() }

func (b *InProc) remove(sub *subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.subs[sub]; ok {
		delete(b.subs, sub)
		close(sub.ch)
	}
}

func (b *InProc) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	for sub := range b.subs {
		delete(b.subs, sub)
		close(sub.ch)
	}
	return nil
}

type subscription struct {
	bus  *InProc
	ch   chan *model.Event
	once sync.Once
}

func (s *subscription) Events() <-chan *model.Event { return s.ch }

func (s *subscription) Unsubscribe() {
	s.once.Do(func() { s.bus.remove(s) })
}

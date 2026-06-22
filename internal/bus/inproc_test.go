package bus

import (
	"context"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

func TestInProcFanOut(t *testing.T) {
	b := NewInProc()
	defer b.Close()
	first := b.Subscribe(4)
	second := b.Subscribe(4)

	event := &model.Event{Action: "exec"}
	if err := b.Publish(context.Background(), event); err != nil {
		t.Fatalf("publish: %v", err)
	}

	for _, sub := range []Subscription{first, second} {
		select {
		case got := <-sub.Events():
			if got != event {
				t.Fatalf("got %v, want %v", got, event)
			}
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive the event")
		}
	}
}

func TestInProcUnsubscribeClosesChannel(t *testing.T) {
	b := NewInProc()
	defer b.Close()
	sub := b.Subscribe(1)
	sub.Unsubscribe()

	if _, open := <-sub.Events(); open {
		t.Fatal("channel should be closed after Unsubscribe")
	}
	sub.Unsubscribe() // idempotent: must not panic or double-close
	if err := b.Publish(context.Background(), &model.Event{}); err != nil {
		t.Fatalf("publish after unsubscribe: %v", err)
	}
}

func TestInProcDropsWhenBufferFull(t *testing.T) {
	b := NewInProc()
	defer b.Close()
	b.Subscribe(1) // never drained

	for range 5 {
		if err := b.Publish(context.Background(), &model.Event{}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	if b.Dropped() == 0 {
		t.Fatal("expected drops to a full subscriber buffer")
	}
}

func TestInProcPublishAfterClose(t *testing.T) {
	b := NewInProc()
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := b.Publish(context.Background(), &model.Event{}); err != ErrClosed {
		t.Fatalf("got %v, want ErrClosed", err)
	}
}

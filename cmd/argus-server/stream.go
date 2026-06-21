package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/argus-edr/argus/server/store"
)

// streamBuffer is how many undelivered alerts a slow SSE subscriber may queue
// before new ones are dropped for that subscriber (the console is a live view,
// not a durable channel — history is always available via /api/alerts).
const streamBuffer = 32

// keepaliveInterval keeps idle SSE connections (and intermediaries) from timing
// out by sending a comment line periodically.
const keepaliveInterval = 25 * time.Second

// broadcaster fans recorded alerts out to every connected SSE subscriber. It is
// safe for concurrent use: the gRPC service publishes; HTTP handlers subscribe.
type broadcaster struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func newBroadcaster() *broadcaster {
	return &broadcaster{subs: make(map[chan []byte]struct{})}
}

func (b *broadcaster) subscribe() chan []byte {
	ch := make(chan []byte, streamBuffer)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *broadcaster) unsubscribe(ch chan []byte) {
	b.mu.Lock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
	b.mu.Unlock()
}

// publish sends payload to every subscriber, dropping it for any whose buffer is
// full rather than blocking the caller (the alert-reporting hot path).
func (b *broadcaster) publish(payload []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- payload:
		default:
		}
	}
}

// recordAlert is the api.OnAlert hook: it serializes a stored alert and pushes it
// to the live console feed. Marshalling failures are dropped silently — a single
// unrenderable alert must not disturb the stream.
func (a *adminAPI) recordAlert(record store.AlertRecord) {
	a.metrics.alerts.Inc()
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	a.stream.publish(payload)
}

// handleStream serves the live alert feed as Server-Sent Events.
func (a *adminAPI) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := a.stream.subscribe()
	defer a.stream.unsubscribe(ch)

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case payload, open := <-ch:
			if !open {
				return
			}
			fmt.Fprintf(w, "event: alert\ndata: %s\n\n", payload)
			flusher.Flush()
		}
	}
}

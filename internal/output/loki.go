package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

const (
	lokiBatchSize     = 256
	lokiFlushInterval = 2 * time.Second
	lokiTimeout       = 5 * time.Second
)

// LokiSink pushes ECS documents to a Grafana Loki endpoint. Entries are batched
// and flushed by size or on a timer; the JSON document is the log line and the
// configured labels form the stream.
type LokiSink struct {
	endpoint string
	labels   map[string]string
	client   *http.Client

	mu     sync.Mutex
	values [][2]string

	stop chan struct{}
	done chan struct{}
}

// NewLoki builds a Loki sink and starts its background flusher.
func NewLoki(endpoint string, labels map[string]string) *LokiSink {
	merged := map[string]string{"job": "argus"}
	for k, v := range labels {
		merged[k] = v
	}
	sink := &LokiSink{
		endpoint: endpoint,
		labels:   merged,
		client:   &http.Client{Timeout: lokiTimeout},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go sink.flushLoop()
	return sink
}

func (s *LokiSink) WriteEvent(event *model.Event) error {
	return s.enqueue(event.Timestamp, event.ECS())
}

func (s *LokiSink) WriteAlert(alert *model.Alert) error {
	return s.enqueue(alert.Timestamp, alert.ECS())
}

func (s *LokiSink) WriteIncident(incident *model.Incident) error {
	return s.enqueue(incident.LastSeen, incident.ECS())
}

func (s *LokiSink) enqueue(ts time.Time, doc map[string]any) error {
	line, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if ts.IsZero() {
		ts = time.Now()
	}

	s.mu.Lock()
	s.values = append(s.values, [2]string{strconv.FormatInt(ts.UnixNano(), 10), string(line)})
	full := len(s.values) >= lokiBatchSize
	s.mu.Unlock()

	if full {
		return s.Flush()
	}
	return nil
}

func (s *LokiSink) flushLoop() {
	defer close(s.done)
	ticker := time.NewTicker(lokiFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = s.Flush()
		case <-s.stop:
			_ = s.Flush()
			return
		}
	}
}

// Flush sends any buffered entries in a single push.
func (s *LokiSink) Flush() error {
	s.mu.Lock()
	if len(s.values) == 0 {
		s.mu.Unlock()
		return nil
	}
	batch := s.values
	s.values = nil
	s.mu.Unlock()
	return s.push(batch)
}

func (s *LokiSink) push(values [][2]string) error {
	payload := lokiPush{Streams: []lokiStream{{Stream: s.labels, Values: values}}}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), lokiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("loki push returned status %d", resp.StatusCode)
	}
	return nil
}

// Close stops the flusher after a final flush.
func (s *LokiSink) Close() error {
	close(s.stop)
	<-s.done
	return nil
}

type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

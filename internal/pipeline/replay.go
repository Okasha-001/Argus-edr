package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/argus-edr/argus/internal/model"
)

const maxReplayLine = 1 << 20 // 1 MiB; argv-heavy events can be long

// ReplaySource feeds a recorded NDJSON event stream through the pipeline. It
// needs no kernel and no privileges, which makes it the basis for tests and
// reproducible demos.
type ReplaySource struct {
	path string
}

// NewReplaySource reads events from the NDJSON file at path.
func NewReplaySource(path string) *ReplaySource {
	return &ReplaySource{path: path}
}

func (r *ReplaySource) Run(ctx context.Context, out chan<- *model.Event) error {
	file, err := os.Open(r.path)
	if err != nil {
		return fmt.Errorf("open replay file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxReplayLine)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		var event model.Event
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			return fmt.Errorf("replay line %d: %w", lineNo, err)
		}
		event.Normalize()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- &event:
		}
	}
	return scanner.Err()
}

func (r *ReplaySource) Close() error {
	return nil
}

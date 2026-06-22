//go:build !windows

package winsource

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

// On a non-Windows build the source must refuse to run rather than silently
// produce nothing — the same contract the bpfloader stub honours off Linux.
func TestStubSourceRefusesOffWindows(t *testing.T) {
	src := New("web-01", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := src.Run(context.Background(), make(chan *model.Event)); err == nil {
		t.Fatal("expected the windows source to error on a non-windows build")
	}
	if err := src.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

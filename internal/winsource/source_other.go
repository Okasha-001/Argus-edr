//go:build !windows

// Package winsource is the Windows event source; this stub keeps the package
// buildable on other platforms (so `go build ./...` and editor tooling work)
// while the real implementation lives in the windows build.
package winsource

import (
	"context"
	"errors"
	"log/slog"

	"github.com/argus-edr/argus/internal/model"
)

// Source is unavailable off Windows.
type Source struct{}

// New returns a non-functional source on non-Windows platforms.
func New(string, *slog.Logger) *Source { return &Source{} }

// Run always fails: this source requires Windows.
func (s *Source) Run(context.Context, chan<- *model.Event) error {
	return errors.New("the windows source is only supported on windows")
}

// Close is a no-op.
func (s *Source) Close() error { return nil }

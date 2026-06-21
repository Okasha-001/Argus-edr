//go:build !linux

// Package bpfloader loads the eBPF objects and exposes the live kernel event
// source. Everything real lives in the linux build; this stub keeps the rest of
// the agent buildable on other platforms for tooling and editor support.
package bpfloader

import (
	"context"
	"errors"
	"log/slog"

	"github.com/argus-edr/argus/internal/model"
)

// Options configures the eBPF source.
type Options struct {
	ObjectPath    string
	LSMObjectPath string
	Hostname      string
	EnforceMode   uint32
	CredReaders   []string
	Logger        *slog.Logger
}

// EBPFSource is unavailable off Linux.
type EBPFSource struct{}

// NewEBPFSource returns a non-functional source on non-Linux platforms.
func NewEBPFSource(Options) *EBPFSource { return &EBPFSource{} }

// Run always fails: eBPF requires Linux.
func (s *EBPFSource) Run(context.Context, chan<- *model.Event) error {
	return errors.New("the eBPF source is only supported on Linux")
}

// Close is a no-op.
func (s *EBPFSource) Close() error { return nil }

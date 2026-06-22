//go:build windows

// Package winsource is the Windows event source. It fills the same model.Event the
// Linux eBPF sensors produce, so the whole pipeline above the source — enrichment,
// detection, response, output and the fleet transport — runs unchanged across
// platforms. The platform-neutral seam is pipeline.Source.
//
// This first sensor reports process creation. It polls the process table through
// the Toolhelp snapshot API: a dependency-free start that proves the cross-platform
// architecture end to end. The production upgrade is an ETW push subscription
// (kernel-process provider) behind this same interface — the events it produces,
// and everything downstream, do not change.
package winsource

import (
	"context"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/argus-edr/argus/internal/model"
)

const pollInterval = time.Second

// Source emits a model.Event for each newly-observed process.
type Source struct {
	hostname string
	interval time.Duration
	logger   *slog.Logger
}

// New builds the Windows process source. hostname stamps each event (empty =
// resolved by the OS elsewhere, as on Linux).
func New(hostname string, logger *slog.Logger) *Source {
	return &Source{hostname: hostname, interval: pollInterval, logger: logger}
}

// Run polls the process table and emits an exec event for every PID that appears,
// until ctx is cancelled. The first snapshot seeds the known set without emitting,
// so startup does not flood the pipeline with every already-running process.
func (s *Source) Run(ctx context.Context, out chan<- *model.Event) error {
	known := map[uint32]string{}
	if procs, err := snapshot(); err == nil {
		for _, proc := range procs {
			known[proc.pid] = proc.name
		}
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			procs, err := snapshot()
			if err != nil {
				s.logger.Warn("windows process snapshot failed", "err", err)
				continue
			}
			seen := make(map[uint32]string, len(procs))
			for _, proc := range procs {
				seen[proc.pid] = proc.name
				// A reused PID with a different image name is a new process too.
				if prev, ok := known[proc.pid]; ok && prev == proc.name {
					continue
				}
				if err := s.emit(ctx, out, proc); err != nil {
					return err
				}
			}
			known = seen
		}
	}
}

func (s *Source) emit(ctx context.Context, out chan<- *model.Event, proc procInfo) error {
	event := &model.Event{
		Timestamp: time.Now().UTC(),
		Host:      s.hostname,
		Type:      model.EventExec,
		Process: model.Process{
			PID:        proc.pid,
			PPID:       proc.ppid,
			Name:       proc.name,
			Executable: proc.executable,
		},
	}
	event.Normalize() // fills schema version + the "exec" action the rules match on
	select {
	case out <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close releases nothing today (the poller owns no handles between ticks).
func (s *Source) Close() error { return nil }

type procInfo struct {
	pid, ppid  uint32
	name       string
	executable string
}

// snapshot enumerates the current process table via the Toolhelp API.
func snapshot() ([]procInfo, error) {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(handle, &entry); err != nil {
		return nil, err
	}
	var procs []procInfo
	for {
		pid := entry.ProcessID
		procs = append(procs, procInfo{
			pid:        pid,
			ppid:       entry.ParentProcessID,
			name:       windows.UTF16ToString(entry.ExeFile[:]),
			executable: imagePath(pid),
		})
		if err := windows.Process32Next(handle, &entry); err != nil {
			break // ERROR_NO_MORE_FILES ends the walk
		}
	}
	return procs, nil
}

// imagePath best-effort resolves a PID's full executable path. Many system PIDs
// deny the query; an empty string simply means the image name is all we have.
func imagePath(pid uint32) string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

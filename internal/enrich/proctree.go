// Package enrich augments raw events with the context that makes detection
// possible: the process tree, user names, container identity and binary hashes.
package enrich

import (
	"sync"

	"github.com/argus-edr/argus/internal/model"
)

const defaultAncestryDepth = 16

type procInfo struct {
	ppid    uint32
	name    string
	exe     string
	startNs uint64
}

// ProcessTree tracks live processes so any event can be annotated with its
// parent and full ancestor chain (e.g. payload <- bash <- nginx <- systemd).
type ProcessTree struct {
	mu       sync.Mutex
	procs    map[uint32]*procInfo
	maxDepth int
}

// NewProcessTree returns an empty process tree.
func NewProcessTree() *ProcessTree {
	return &ProcessTree{procs: make(map[uint32]*procInfo), maxDepth: defaultAncestryDepth}
}

// Enrich updates the tree from lifecycle events and annotates every event with
// its parent and ancestry.
func (t *ProcessTree) Enrich(event *model.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch event.Type {
	case model.EventExec, model.EventExecBlocked:
		t.procs[event.Process.PID] = &procInfo{
			ppid:    event.Process.PPID,
			name:    event.Process.Name,
			exe:     event.Process.Executable,
			startNs: startOf(event),
		}
	case model.EventFork:
		t.procs[event.Process.PID] = &procInfo{
			ppid:    event.Process.PPID,
			name:    event.Process.Name,
			startNs: startOf(event),
		}
	case model.EventExit:
		delete(t.procs, event.Process.PID)
	}

	if parent, ok := t.procs[event.Process.PPID]; ok {
		event.Process.ParentName = parent.name
		event.Process.ParentExecutable = parent.exe
	}
	// Stamp a stable start time on every event of a known process so its
	// ProcessKey is consistent across event types, which correlation relies on.
	if self, ok := t.procs[event.Process.PID]; ok && event.Process.StartTimeNs == 0 {
		event.Process.StartTimeNs = self.startNs
	}
	event.Process.Ancestors = t.ancestry(event.Process.PID, event.Process.PPID)
}

func startOf(event *model.Event) uint64 {
	if event.Process.StartTimeNs != 0 {
		return event.Process.StartTimeNs
	}
	return event.MonotonicNs
}

func (t *ProcessTree) ancestry(pid, ppid uint32) []string {
	var chain []string
	current := ppid
	for depth := 0; depth < t.maxDepth && current != 0 && current != pid; depth++ {
		info, ok := t.procs[current]
		if !ok {
			break
		}
		chain = append(chain, info.name)
		current = info.ppid
	}
	if len(chain) == 0 {
		return nil
	}
	return chain
}

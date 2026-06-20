package enrich

import (
	"testing"

	"github.com/argus-edr/argus/internal/model"
)

func TestProcessTreeResolvesParentAndAncestry(t *testing.T) {
	tree := NewProcessTree()
	tree.Enrich(execEvent(4001, 1, "nginx", 1000))
	tree.Enrich(execEvent(4123, 4001, "bash", 2000))

	open := &model.Event{
		Type:    model.EventOpen,
		Process: model.Process{PID: 4123, PPID: 4001, Name: "bash"},
		File:    model.File{Path: "/etc/shadow"},
	}
	tree.Enrich(open)

	if open.Process.ParentName != "nginx" {
		t.Errorf("parent name = %q, want nginx", open.Process.ParentName)
	}
	if open.Process.StartTimeNs != 2000 {
		t.Errorf("start time not stamped from tree: got %d, want 2000", open.Process.StartTimeNs)
	}
	if len(open.Process.Ancestors) == 0 || open.Process.Ancestors[0] != "nginx" {
		t.Errorf("ancestors = %v, want first element nginx", open.Process.Ancestors)
	}
}

func TestProcessTreeForgetsExitedProcess(t *testing.T) {
	tree := NewProcessTree()
	tree.Enrich(execEvent(5000, 1, "victim", 10))
	tree.Enrich(&model.Event{Type: model.EventExit, Process: model.Process{PID: 5000}})

	child := &model.Event{Type: model.EventOpen, Process: model.Process{PID: 6000, PPID: 5000, Name: "child"}}
	tree.Enrich(child)
	if child.Process.ParentName != "" {
		t.Errorf("exited parent should be forgotten, got %q", child.Process.ParentName)
	}
}

func execEvent(pid, ppid uint32, name string, startNs uint64) *model.Event {
	return &model.Event{
		Type: model.EventExec,
		Process: model.Process{
			PID: pid, PPID: ppid, Name: name,
			Executable: "/usr/bin/" + name, StartTimeNs: startNs,
		},
	}
}

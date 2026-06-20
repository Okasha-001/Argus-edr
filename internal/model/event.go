// Package model holds the unified event and alert types that flow through the
// agent. Every sensor decodes into an Event; every detection produces an Alert.
package model

import "time"

// SchemaVersion is bumped whenever the wire/JSON layout changes so the agent
// and control plane can negotiate compatibility at enrollment.
const SchemaVersion = "1.0"

// EventType mirrors enum event_type in bpf/common.h.
type EventType uint32

const (
	EventExec        EventType = 1
	EventFork        EventType = 2
	EventExit        EventType = 3
	EventOpen        EventType = 4
	EventUnlink      EventType = 5
	EventRename      EventType = 6
	EventChmod       EventType = 7
	EventConnect     EventType = 8
	EventAccept      EventType = 9
	EventExecBlocked EventType = 10
	EventPtrace      EventType = 11
	EventKmod        EventType = 12
	EventBPF         EventType = 13
	EventMemfd       EventType = 14
	EventMmapExec    EventType = 15
	EventPrivChange  EventType = 16
)

var eventActions = map[EventType]string{
	EventExec:        "exec",
	EventFork:        "fork",
	EventExit:        "exit",
	EventOpen:        "open",
	EventUnlink:      "unlink",
	EventRename:      "rename",
	EventChmod:       "chmod",
	EventConnect:     "connect",
	EventAccept:      "accept",
	EventExecBlocked: "exec_blocked",
	EventPtrace:      "ptrace",
	EventKmod:        "module_load",
	EventBPF:         "bpf",
	EventMemfd:       "memfd_create",
	EventMmapExec:    "mmap_exec",
	EventPrivChange:  "setuid",
}

var actionTypes = func() map[string]EventType {
	reverse := make(map[string]EventType, len(eventActions))
	for eventType, action := range eventActions {
		reverse[action] = eventType
	}
	return reverse
}()

// Action returns the lowercase verb used in rules and JSON ("exec", "open", ...).
func (t EventType) Action() string {
	if action, ok := eventActions[t]; ok {
		return action
	}
	return "unknown"
}

// ParseAction maps a verb back to its EventType, used when replaying recorded
// events from JSON. The zero EventType signals an unknown action.
func ParseAction(action string) EventType {
	return actionTypes[action]
}

// Process carries the actor of an event plus everything enrichment adds later.
type Process struct {
	PID         uint32   `json:"pid"`
	TID         uint32   `json:"tid,omitempty"`
	PPID        uint32   `json:"ppid"`
	Name        string   `json:"name"`
	Executable  string   `json:"executable,omitempty"`
	CommandLine string   `json:"command_line,omitempty"`
	Args        []string `json:"args,omitempty"`
	ExitCode    int32    `json:"exit_code,omitempty"`
	StartTimeNs uint64   `json:"start_time_ns,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	StdioSocket bool     `json:"stdio_socket,omitempty"`

	ParentName       string   `json:"parent_name,omitempty"`
	ParentExecutable string   `json:"parent_executable,omitempty"`
	Ancestors        []string `json:"ancestors,omitempty"`
}

// File describes a filesystem operation (open/unlink/rename/chmod).
type File struct {
	Path   string `json:"path,omitempty"`
	Target string `json:"target,omitempty"`
	Flags  uint16 `json:"flags,omitempty"`
	Mode   uint16 `json:"mode,omitempty"`
}

// Network describes a connection or DNS lookup.
type Network struct {
	Family     uint16 `json:"family,omitempty"`
	SrcIP      string `json:"src_ip,omitempty"`
	SrcPort    uint16 `json:"src_port,omitempty"`
	DstIP      string `json:"dst_ip,omitempty"`
	DstPort    uint16 `json:"dst_port,omitempty"`
	Domain     string `json:"domain,omitempty"`
	GeoCountry string `json:"geo_country,omitempty"`
}

// User is the owning uid plus its resolved name.
type User struct {
	ID   uint32 `json:"id"`
	Name string `json:"name,omitempty"`
}

// Syscall carries details specific to the syscall sensors (ptrace, bpf, memfd,
// mmap, privilege changes). It is populated per event type and lives only in
// userspace — the kernel forwards the raw numbers in reused wire fields.
type Syscall struct {
	Request   int64  `json:"request,omitempty"`    // ptrace request / bpf cmd / mmap prot
	TargetPID uint32 `json:"target_pid,omitempty"` // ptrace target process
	NewUID    uint32 `json:"new_uid,omitempty"`    // setuid/setgid requested id
}

// Container identifies the cgroup/container an event came from, if any.
type Container struct {
	ID      string `json:"id,omitempty"`
	Runtime string `json:"runtime,omitempty"`
}

// Event is the unified record produced by every sensor and consumed by the
// detection engine. Enrichment mutates it in place as it flows down the
// pipeline, which is why fields like Container start empty.
type Event struct {
	SchemaVersion string    `json:"schema_version"`
	Timestamp     time.Time `json:"@timestamp"`
	MonotonicNs   uint64    `json:"-"`
	Host          string    `json:"host,omitempty"`
	Type          EventType `json:"-"`
	Action        string    `json:"action"`
	CgroupID      uint64    `json:"cgroup_id,omitempty"`
	Ret           int32     `json:"ret,omitempty"`

	Process   Process   `json:"process"`
	User      User      `json:"user"`
	File      File      `json:"file"`
	Network   Network   `json:"network"`
	Container Container `json:"container"`
	Syscall   Syscall   `json:"syscall"`

	// AnomalyScore is a 0–1 rarity/outlier score the anomaly stage assigns in
	// userspace (0 when scoring is disabled). It is not part of the kernel ABI.
	// Rules see it as anomaly.score on a 0–100 scale (see fields.go).
	AnomalyScore float64 `json:"anomaly_score,omitempty"`
}

// ProcessKey identifies a process across PID reuse by pairing the PID with its
// start time, as recommended in the design notes.
func (e *Event) ProcessKey() string {
	return processKey(e.Process.PID, e.Process.StartTimeNs)
}

// Normalize fills the derived fields after an Event is built from JSON, where
// only the textual action is present.
func (e *Event) Normalize() {
	if e.SchemaVersion == "" {
		e.SchemaVersion = SchemaVersion
	}
	if e.Type == 0 && e.Action != "" {
		e.Type = ParseAction(e.Action)
	}
	if e.Action == "" {
		e.Action = e.Type.Action()
	}
}

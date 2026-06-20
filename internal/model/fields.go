package model

import "strconv"

// fieldAccessor returns a rule-addressable value and whether it is present.
// Numeric fields are normalized to int64 so the comparison operators have a
// single numeric type to reason about.
type fieldAccessor func(*Event) (any, bool)

// fieldAccessors maps the ECS-style dotted paths used in rules to the Event
// fields that back them. Adding a rule-visible field is a one-line change here.
var fieldAccessors = map[string]fieldAccessor{
	"event.type":   func(e *Event) (any, bool) { return e.Action, e.Action != "" },
	"event.action": func(e *Event) (any, bool) { return e.Action, e.Action != "" },
	"host.name":    func(e *Event) (any, bool) { return e.Host, e.Host != "" },

	"process.pid":               func(e *Event) (any, bool) { return int64(e.Process.PID), true },
	"process.ppid":              func(e *Event) (any, bool) { return int64(e.Process.PPID), true },
	"process.name":              func(e *Event) (any, bool) { return e.Process.Name, e.Process.Name != "" },
	"process.executable":        func(e *Event) (any, bool) { return e.Process.Executable, e.Process.Executable != "" },
	"process.command_line":      func(e *Event) (any, bool) { return e.Process.CommandLine, e.Process.CommandLine != "" },
	"process.stdio_socket":      func(e *Event) (any, bool) { return e.Process.StdioSocket, true },
	"process.hash.sha256":       func(e *Event) (any, bool) { return e.Process.SHA256, e.Process.SHA256 != "" },
	"process.parent.name":       func(e *Event) (any, bool) { return e.Process.ParentName, e.Process.ParentName != "" },
	"process.parent.executable": func(e *Event) (any, bool) { return e.Process.ParentExecutable, e.Process.ParentExecutable != "" },

	"user.id":   func(e *Event) (any, bool) { return int64(e.User.ID), true },
	"user.name": func(e *Event) (any, bool) { return e.User.Name, e.User.Name != "" },

	"file.path":   func(e *Event) (any, bool) { return e.File.Path, e.File.Path != "" },
	"file.target": func(e *Event) (any, bool) { return e.File.Target, e.File.Target != "" },
	"file.flags":  func(e *Event) (any, bool) { return int64(e.File.Flags), true },
	"file.mode":   func(e *Event) (any, bool) { return int64(e.File.Mode), true },

	"source.ip":         func(e *Event) (any, bool) { return e.Network.SrcIP, e.Network.SrcIP != "" },
	"source.port":       func(e *Event) (any, bool) { return int64(e.Network.SrcPort), e.Network.SrcPort != 0 },
	"destination.ip":    func(e *Event) (any, bool) { return e.Network.DstIP, e.Network.DstIP != "" },
	"destination.port":  func(e *Event) (any, bool) { return int64(e.Network.DstPort), e.Network.DstPort != 0 },
	"dns.question.name": func(e *Event) (any, bool) { return e.Network.Domain, e.Network.Domain != "" },

	"container.id":      func(e *Event) (any, bool) { return e.Container.ID, e.Container.ID != "" },
	"container.runtime": func(e *Event) (any, bool) { return e.Container.Runtime, e.Container.Runtime != "" },

	// anomaly.score is the userspace anomaly stage's 0–1 score exposed to rules on
	// a 0–100 integer scale, so a rule reads `anomaly.score: {op: ge, value: 90}`.
	"anomaly.score": func(e *Event) (any, bool) { return int64(e.AnomalyScore*100 + 0.5), true },
}

// Field resolves a dotted rule path against the event.
func (e *Event) Field(path string) (any, bool) {
	if accessor, ok := fieldAccessors[path]; ok {
		return accessor(e)
	}
	return nil, false
}

// KnownField reports whether path is addressable, used to validate rules at load
// time rather than silently never matching at runtime.
func KnownField(path string) bool {
	_, ok := fieldAccessors[path]
	return ok
}

func processKey(pid uint32, startTimeNs uint64) string {
	return strconv.FormatUint(uint64(pid), 10) + ":" + strconv.FormatUint(startTimeNs, 10)
}

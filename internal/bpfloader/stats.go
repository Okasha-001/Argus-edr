package bpfloader

import "time"

// ProgramStat is one attached eBPF program's cumulative cost, exposed as the
// per-program runtime/run-count metric. It is platform-neutral so the agent's
// metrics wiring compiles everywhere; only the Linux source actually fills it.
type ProgramStat struct {
	Name     string
	Runtime  time.Duration
	RunCount uint64
}

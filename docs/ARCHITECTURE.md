# Architecture

ARGUS has two halves joined by a ring buffer: small eBPF programs in the kernel
that collect telemetry, and a Go agent in userspace that decodes, enriches,
detects, responds and ships it.

```
         kernel space                                userspace (Go agent)
  ┌────────────────────────┐              ┌──────────────────────────────────────┐
  │ tracepoints / kprobes  │              │ bpfloader: load + attach + read        │
  │ edr.bpf.c  ──ringbuf──▶ │──────────────▶│                                        │
  │ edr_lsm.bpf.c (LSM)    │  events,     │ pipeline (one ordered consumer):       │
  │                        │  enforce     │   decode → enrich → detect → respond   │
  └────────────────────────┘  events     │              → output                  │
                                          └───────────────┬────────────────────────┘
                                                          │  ECS JSON
                                          stdout · file · Loki → Grafana
```

## Data flow

1. A kernel event fires (e.g. `execve`). The eBPF program captures the relevant
   fields into a fixed `struct event` and writes it to the ring buffer.
2. `bpfloader` reads the raw record; `decode` turns the bytes into a `model.Event`.
3. `enrich` adds context: parent and ancestry from the process tree, the user
   name, the container, a binary hash, and the reverse-shell stdio heuristic.
4. `detect` evaluates the event against every rule and feeds matches to the
   correlator, which accumulates per-process risk and opens incidents.
5. `respond` (only when enabled) kills, blocks or quarantines, honouring the
   allowlist and dry-run mode.
6. `output` writes the event, any alerts, and any incident to every configured
   sink as ECS JSON.

## Key decisions

- **Go userspace, C/eBPF sensors.** `cilium/ebpf` gives a clean, CGO-free loader
  and Go's goroutines/channels fit the pipeline. The sensors stay tiny.
- **Runtime object loading, not bundled bindings.** The agent loads the compiled
  `.o` with `ebpf.LoadCollectionSpec` at startup. So the Go build never needs
  clang, CI's Go stages are simple, and the eBPF object can be swapped without
  rebuilding the agent. `make bpf` (clang) and `make build` (go) are independent.
- **Ring buffer (5.8+), not perf buffer.** Lower overhead, ordered, less memory.
- **CO-RE + BTF.** One object runs across kernel versions; `BPF_CORE_READ`
  relocates struct offsets at load time. No on-host compiler.
- **One ordered consumer.** The source runs in its own goroutine and feeds a
  buffered channel; a single consumer runs the stages in order. Event order is
  preserved, so the process tree and correlator need no cross-event locking, and
  there is exactly one place per-event work happens.
- **Sensors collect, the agent decides.** No policy in the kernel keeps the
  programs simple, easy to pass the verifier, and cheap.
- **Replay as a first-class source.** The same pipeline runs over recorded
  NDJSON with no kernel, which is how detection logic is developed and tested.

## The ABI

`bpf/common.h` and `internal/decode/wire.go` describe the same 848-byte record.
Field order avoids padding; `MAX_ARGS_LEN` is a power of two so the argv loop can
mask its write offset for the verifier. The two files must change together, and
`internal/decode/wire_test.go` locks the expected layout.

## Packages

| Package | Responsibility |
|---------|----------------|
| `internal/model` | Event/Alert/Incident types, ECS projection, rule-field resolver (dependency-free leaf) |
| `internal/decode` | ring-buffer bytes → `model.Event` |
| `internal/bpfloader` | load/attach eBPF, read ring buffers (the live `Source`) |
| `internal/enrich` | process tree, users, containers, hashing, stdio heuristic |
| `internal/detect` | rule engine (condition tree + operators), correlation |
| `internal/respond` | kill/block/quarantine, modes, allowlist |
| `internal/output` | `Sink` interface + stdout/file/loki |
| `internal/pipeline` | wiring + the ordered consumer + replay source |
| `internal/config` | load + strict validation |
| `cmd/argus` | agent CLI |
| `cmd/argus-server` | control-plane scaffold |

# Cross-platform agent

ARGUS is built so that **only the event source is platform-specific.** Everything
above it — enrichment, the detection engine, correlation, response policy, the
output sinks, and the fleet transport — consumes one neutral type, `model.Event`,
and runs unchanged on any OS. Porting ARGUS to a new platform is therefore a
matter of writing one new source, not a second EDR.

## The seam

```
            ┌─────────────── platform-specific ───────────────┐
 Linux  →   eBPF sensors ──┐
 Windows →  process source ┤──►  pipeline.Source  ──►  model.Event
 (replay)   NDJSON file ────┘                              │
            └──────────────────────────────────────────────┼─ platform-neutral ─┐
                                                            ▼                     │
                              enrich → detect → correlate → respond → output → fleet
```

`pipeline.Source` is the whole contract:

```go
type Source interface {
    Run(ctx context.Context, out chan<- *model.Event) error
    Close() error
}
```

`cmd/argus` selects the live source in a build-tagged `newLiveSource`
(`livesource_linux.go` ... well, `livesource_default.go` for `!windows`, and
`livesource_windows.go`), so the agent compiles for every target and links only
that platform's source.

## Linux (the reference platform)

The eBPF sensors (`bpf/*.c`) stream kernel events into `internal/bpfloader`,
which decodes them to `model.Event`. This is the full-featured path: ten sensors,
BPF-LSM enforcement, the lot. See `docs/ARCHITECTURE.md`.

## Windows (experimental, one sensor end-to-end)

`internal/winsource` is the Windows source. The first sensor reports **process
creation** and fills the same `model.Event` (`EventExec`, with the process name,
PID, parent PID, and best-effort image path), so a process-based detection rule
fires and an alert reaches the same console as on Linux.

It polls the process table through the Toolhelp snapshot API
(`golang.org/x/sys/windows`) — a dependency-free start that proves the
architecture end to end. The production upgrade is an **ETW** push subscription to
the kernel-process provider behind the same `Source` interface; the events it
produces, and everything downstream, do not change.

Build it:

```bash
GOOS=windows GOARCH=amd64 go build ./cmd/argus
```

What carries over **unchanged** on Windows: `internal/detect` (rules + engine),
`internal/output` (stdout/file/Loki sinks), `internal/fleet` (mTLS enrolment,
heartbeat, alert reporting, rule/policy pull). What is **Linux-only today**:
eBPF sensing and BPF-LSM enforcement, and process kill/freeze in
`internal/respond` (the signalling rungs return a clear "linux only" error on
other platforms; observation and alerting are unaffected, and enforcement ships
off by default).

## Scope

This is the deliberately-small first step of an ambitious area. A real Windows
EDR needs the ETW providers for network, file and registry activity, a signed
driver or kernel callbacks for enforcement, and Windows-native enrichment. The
value proven here is the **architecture**: a new platform is one `Source`
implementation, and the entire detection/response/fleet stack comes for free.

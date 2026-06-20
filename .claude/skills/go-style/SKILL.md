---
name: go-style
description: Go conventions for the ARGUS agent. Use when writing or reviewing Go — error wrapping, concurrency, interfaces, constructors, and table-driven tests.
---

# Go style (ARGUS)

Builds on `clean-code`. Idiomatic Go, the way this codebase already does it.

## Errors

- Wrap with `%w` and a phrase naming the operation: `fmt.Errorf("open ring buffer: %w", err)`.
- Sentinel checks use `errors.Is`; type checks use `errors.As` (see how the
  loader unwraps `*ebpf.VerifierError`).
- Return errors; don't log-and-continue unless the loop must survive one bad item
  (the ring-buffer reader does this deliberately, and logs).

## Concurrency

- The pipeline has exactly one consumer goroutine so event order is preserved;
  shared detection state (process tree, correlator) is therefore never raced.
  Don't add parallelism to that path without a redesign.
- Sources run in their own goroutine and **must honour `ctx`** promptly.
- Guard shared maps with a `sync.Mutex` (see `enrich.UserResolver`,
  `detect.Correlator`). Counters that cross goroutines use `sync/atomic`.
- `go test -race ./...` must stay clean.

## Interfaces and construction

- Define interfaces where they're consumed (`pipeline.Source`, `output.Sink`),
  not where they're implemented.
- Constructors are `New...` and return a ready-to-use value. Injectable
  dependencies (a clock, a `kill` func, a lookup) are fields set to a real
  default in the constructor and overridden in tests — that's how `respond` and
  `enrich` stay testable without touching the real system.

## Tests

- Table-driven where it reduces repetition (see `detect.TestLeafOperators`).
- One concept per test; the name says the behaviour
  (`TestLoadRejectsUnknownKey`).
- Cover boundaries: short buffer, empty input, threshold edge, exited process.
- Fast and hermetic — no real network, no sleeping. Use `t.TempDir()` for files.

## Layout

- `internal/` for everything not meant to be imported externally.
- One responsibility per package; `model` is the dependency-free leaf.
- Keep files focused; split by responsibility (`responder.go` vs `policy.go`)
  rather than growing one large file.

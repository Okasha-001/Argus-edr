# Data Lake, Event Bus & OCSF (Platform v2 — Phase 12)

ARGUS v2 scales from a single host to a fleet **without changing the binary**.
Every heavy component sits behind a Go interface with a light default, so the
agent and control plane run with zero infrastructure out of the box and grow
into a columnar lake when you need billions of searchable events.

This is Phase 12 of `docs/PLATFORM_V2_MASTER_PLAN.md`. It honours the platform
principles: FOSS-first, zero phone-home, and a working single-binary mode.

## OCSF projection

Events and alerts already project to [ECS](https://www.elastic.co/guide/en/ecs)
(`internal/model/ecs.go`). v2 adds a projection to
[OCSF](https://schema.ocsf.io) 1.3.0 (`internal/model/ocsf.go`), the open
industry schema, so ARGUS is interoperable with any OCSF-aware data lake or SIEM
out of the box.

| Event | OCSF class | `class_uid` |
|-------|------------|-------------|
| exec/fork/exit, ptrace, bpf, memfd, mmap, setuid, tamper | Process Activity | 1007 |
| open/unlink/rename/chmod | File System Activity | 1001 |
| connect/accept | Network Activity | 4001 |
| dns | DNS Activity | 4003 |
| **alert** | **Detection Finding** | **2004** |

Each record carries the mandatory identity tuple (`category_uid`, `class_uid`,
`activity_id`, `type_uid = class_uid*100 + activity_id`), a `metadata` block
naming the producer, and — for alerts — an `attacks` array with the MITRE
ATT&CK technique. `Event.OCSF()` and `Alert.OCSF()` return the document; the
unit tests assert the required fields and `type_uid` derivation. Full validation
against the published schema runs in CI.

## Event bus (`internal/bus`)

The bus is the streaming seam between ingestion and everything that fans out
from it — the live console feed (SSE), the hunting engine, the lake.

- **`InProc`** (default): in-process pub/sub. Publish never blocks ingestion; an
  event is dropped (and counted via `Dropped()`) for any subscriber whose buffer
  is full, so one slow consumer can't stall the pipeline. No infrastructure.
- **NATS JetStream** (scale-out): the documented production implementation of the
  same `EventBus` interface, for fanning events across many control-plane
  replicas. It is optional and self-hosted — never required, never a paid
  dependency.

## Event lake (`internal/eventstore`)

The lake is the queryable history hunting and investigation search.

- **`memory`** (default): in-process, ephemeral. Good for single-binary mode,
  tests and short investigations.
- **`sqlite`**: durable, embedded, cgo-free (`modernc.org/sqlite`). A box keeps a
  searchable history across restarts with no server.
- **ClickHouse / DuckDB** (scale-out): the documented columnar backends that
  implement the same `Store` interface for billions of rows. Optional and
  self-hosted.

All backends satisfy one `Store` interface and pass a shared conformance test
(`conformance_test.go`), so they are provably interchangeable. The `Query` type
filters by action, host, pid, time range and a case-insensitive substring, newest
first by default, capped at `DefaultLimit`.

### Enabling the local lake

The lake is wired as an output sink, off unless configured:

```yaml
outputs:
  - type: eventstore
    format: sqlite              # memory (default) | sqlite
    path: /var/lib/argus/lake.db   # required when format=sqlite
```

`format` selects the backend; `memory` needs no path. The sink stores events
only — alerts and incidents are persisted by the control-plane store and the
other sinks, keeping the lake a pure event record.

## Scale-out, same code

```
single binary (default)          fleet (scale-out)
  InProc bus                       NATS JetStream
  memory / sqlite lake             ClickHouse / DuckDB
  no infrastructure                self-hosted, FOSS, zero phone-home
```

Selecting a scale-out backend is configuration, not a different build. The
production backends (NATS, ClickHouse) require their respective servers and are
verified in integration/CI, not in a rootless build environment.

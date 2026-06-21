# Performance

Real, reproducible micro-benchmarks of the agent's hot path. Run them yourself
with `make bench`; the numbers below are from one run on a 2-vCPU x86-64 Linux
box (`GOMAXPROCS=2`, hence the `-2` suffix) and are indicative, not a spec.

## Hot-path latency and throughput

| Benchmark | ns/op | B/op | allocs/op | ≈ events/sec (1 core) |
|-----------|------:|-----:|----------:|----------------------:|
| `DecodeExec` — ring-buffer bytes → `model.Event` (with argv) | 683 | 568 | 6 | ~1,460,000 |
| `EngineEvaluate` — one event vs. the full shipped ruleset | 2,305 | 440 | 18 | ~434,000 |
| `PipelineThroughput` — end-to-end (evaluate + sink), no match | 2,293 | 240 | 15 | ~436,000 |

The pipeline is a single ordered consumer (event order matters for the process
tree and correlator), so these are per-core figures. Decoding is ~3× cheaper than
detection, so detection dominates cost — which is where added rules show up.

## What this means

- A single agent core sustains **~430k events/sec** through decode → detect →
  output before back-pressure. Typical hosts emit orders of magnitude fewer
  exec/network events than that, so the agent has wide headroom.
- Memory per event is small and bounded (sub-kilobyte, single-digit allocations);
  there is no per-event heap growth.
- Detection cost scales with rule count. At 11 rules it is ~2.3 µs/event; the
  rule engine short-circuits condition trees, so cheap leading clauses keep most
  rules from fully evaluating.

## Methodology and honesty

- These measure **CPU latency per stage** and **steady-state throughput** on
  synthetic events. They isolate the userspace agent; they do **not** include
  kernel-side eBPF probe overhead.
- **End-to-end host overhead %** (agent CPU under a real workload, and the
  sensor's added syscall latency) requires a live, rooted deployment with the
  eBPF objects loaded. That benchmark is tracked in `docs/ROADMAP.md` and is not
  reported here rather than estimated — no invented numbers.
- Reproduce: `make bench`. The figures will vary with CPU, kernel and rule set.

## Live metrics (Prometheus)

Both binaries expose a Prometheus endpoint so the hot path can be watched in
production, not just measured in a benchmark.

- **Agent** (`metrics.enabled: true`, default `127.0.0.1:9464`): `GET /metrics`
  serves `argus_events_total`, `argus_alerts_total`, `argus_incidents_total`, the
  per-stage latency histogram `argus_pipeline_stage_seconds{stage=…}`
  (enrich/score/detect/respond/output), per-program eBPF cost
  `argus_program_runtime_ns_total{program=…}` / `argus_program_runs_total`, and —
  closing the long-open event-loss gap — `argus_ring_drops_total`, the kernel's
  count of events dropped when the ring buffer was full.
- **Control plane**: `GET /metrics` on the admin API serves
  `argus_server_alerts_total`, `argus_server_signals_total`, and the
  `argus_server_agents` gauge.

The exposition is hand-rolled (`internal/metrics`) — no client library, in
keeping with the project's minimal-dependency stance. `deploy/` ships a
Prometheus scrape config, a Grafana datasource, and an *ARGUS — Metrics*
dashboard (events/sec, alert rate, stage p95 latency, per-program cost, ring
drops, fleet size); bring them up with
`docker compose -f deploy/docker-compose.yaml up -d`.

Per-program cost needs `CAP_SYS_ADMIN` (the agent enables BPF run-time stats at
load); without it the cost series simply read zero. `argus_ring_drops_total`
rising under load is the signal to raise `input.ring_buffer_bytes`.

## Robustness (fuzzing)

The parsers that consume untrusted input are fuzzed with Go's native fuzzer
(`make fuzz`):

- `FuzzDecode` (`internal/decode`) — arbitrary ring-buffer/replay bytes must
  never panic or read out of bounds; short buffers must be rejected.
- `FuzzRuleCompile` (`internal/detect`) — arbitrary YAML rule files (including
  fleet-pushed ones) must fail closed with an error, never a panic, and any rule
  that compiles must evaluate safely.

Both run clean (no crashers). Example: `make fuzz FUZZ=FuzzDecode PKG=./internal/decode SECS=30`.

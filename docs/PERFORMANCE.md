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

## Robustness (fuzzing)

The parsers that consume untrusted input are fuzzed with Go's native fuzzer
(`make fuzz`):

- `FuzzDecode` (`internal/decode`) — arbitrary ring-buffer/replay bytes must
  never panic or read out of bounds; short buffers must be rejected.
- `FuzzRuleCompile` (`internal/detect`) — arbitrary YAML rule files (including
  fleet-pushed ones) must fail closed with an error, never a panic, and any rule
  that compiles must evaluate safely.

Both run clean (no crashers). Example: `make fuzz FUZZ=FuzzDecode PKG=./internal/decode SECS=30`.

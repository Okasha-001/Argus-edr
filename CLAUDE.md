# CLAUDE.md — working agreement for ARGUS

This file is the operating manual for any AI or human contributor working in this
repository. Read it before writing code. It encodes how ARGUS is built and the
standards every change is held to.

ARGUS is a runtime EDR for Linux: eBPF sensors in the kernel, a Go agent in
userspace, behavioural detection mapped to MITRE ATT&CK, and BPF-LSM
enforcement. See `README.md` for the product view and `docs/ARCHITECTURE.md` for
the deep dive.

---

## Golden rules (non-negotiable)

1. **No machine-specific or personal data in committed files.** No usernames,
   home directories, emails, hostnames, internal IPs, or absolute paths from a
   developer's machine. Use neutral examples: `web-01`, `/opt/argus`,
   `203.0.113.0/24` (TEST-NET), `github.com/argus-edr/argus`.
2. **The ABI is sacred.** `bpf/common.h` (`struct event`) and
   `internal/decode/wire.go` are one contract in two languages. Change one and
   you must change the other in the same commit, keep `WireSize` and the field
   offsets correct, and update `internal/decode/wire_test.go`.
3. **Enforcement is off by default.** Anything that can kill a process or deny a
   syscall ships behind `response.mode` and is `off` until explicitly enabled.
   Never change that default. See `docs/SAFETY.md`.
4. **Sensors are dumb; the agent is smart.** eBPF programs only collect and
   forward. All interpretation, enrichment and policy live in Go, where they are
   testable and can't crash the kernel.
5. **Every change leaves the tree green:** `make fmt vet lint test` all pass.

---

## Architecture map

```
bpf/edr.bpf.c          sensors  → ring buffer ─┐
bpf/edr_lsm.bpf.c      LSM enforcement ────────┤
                                               ▼
internal/bpfloader     load + attach + read ring buffers  (Source, live)
internal/pipeline      Source → enrich → detect → respond → output (one ordered consumer)
internal/decode        raw bytes → model.Event   (mirror of bpf/common.h)
internal/model         Event, Alert, Incident, ECS projection, rule-field resolver
internal/enrich        process tree, users, containers, hashes, reverse-shell heuristic
internal/detect        rule engine (condition tree + operators), correlation/risk scoring
internal/respond       kill / block / quarantine, dry-run vs enforce, allowlist
internal/output        Sink interface + stdout / file / loki
internal/config        config load + strict validation
internal/fleet         agent↔control-plane transport: mTLS, dev certs, gRPC client, reporter
internal/fleet/fleetpb generated FleetService gRPC/protobuf (committed; no protoc at build)
cmd/argus              agent CLI: run | replay | rules | version
rules/                 detection rules (YAML), one file per ATT&CK area

server/api             FleetService gRPC server (enroll/heartbeat/report/getrules)
server/store           fleet state: agents, alerts, command queues (Store interface)
server/correlate       cross-host correlation: lateral movement, C2 fan-in
server/ruleset         versioned rule provider (validated with internal/detect)
cmd/argus-server       control plane: serve (gRPC/mTLS + admin HTTP) | gen-certs
```

Data flows one direction. A package never imports a package "above" it in that
list; `model` is the shared leaf and imports nothing internal. The `server/*`
packages and the agent are independent: they meet only at `internal/fleet/fleetpb`
(the wire contract). The fleet transport, like enforcement, is **off by default**
(`fleet.enabled: false`); see `docs/FLEET.md`.

---

## Build & test

The Makefile assumes `go` (1.24+), `clang`/`llvm`, and `bpftool` are on `PATH`.

```bash
make vmlinux   # regenerate bpf/vmlinux.h from the running kernel's BTF (gitignored)
make bpf       # compile the eBPF objects (needs clang + BTF)
make build     # build the Go binaries (does NOT need clang)
make all       # bpf + build
make test      # go test ./...
make lint      # golangci-lint
make replay    # run the kill-chain demo with no root and no kernel
```

The Go build never depends on clang: the agent loads the compiled `.o` at
runtime (`internal/bpfloader`), so `make build`, tests and CI's Go stages work on
any machine. Only `make bpf` needs the eBPF toolchain.

**Fastest feedback loop:** `argus replay` runs the entire pipeline (enrich →
detect → correlate → output) over `test/integration/testdata/*.ndjson` with no
privileges. Use it to develop and test rules and detection logic.

---

## Clean code standards

These are enforced in review and codified in `.claude/skills/`. They are adapted
from Robert C. Martin's *Clean Code*. The short version:

- **Functions do one thing**, ideally < 20 lines. If you can extract a
  well-named function, do it.
- **Names reveal intent.** No `data`, `tmp`, `mgr`, `x`. Booleans read as
  `is/has/can`. Length matches scope.
- **Comments explain WHY, not WHAT.** No commented-out code, no metadata (git
  has that), no restating the code. A comment earns its place by explaining a
  non-obvious decision or a kernel/verifier subtlety.
- **Handle errors deliberately.** Wrap with context (`fmt.Errorf("...: %w", err)`).
  Never swallow. The only ignored errors are best-effort cleanup (`defer
  x.Close()`), which the linter is configured to allow.
- **DRY**, no magic numbers (name the constant), guard clauses over deep nesting.
- **Boy-scout rule:** leave each file a little cleaner than you found it, but keep
  cleanups proportional to the change.

Skills, by area:

| Skill | Use when |
|-------|----------|
| `.claude/skills/clean-code` | writing or reviewing any code (the master reference) |
| `.claude/skills/go-style` | writing Go — errors, concurrency, table tests, naming |
| `.claude/skills/ebpf-sensors` | touching `bpf/*.c` or the ABI — verifier, stack, CO-RE |
| `.claude/skills/detection-rules` | adding or editing `rules/*.yaml` |

---

## How to extend

### Add a sensor (new event type)
1. Add the enum value to `bpf/common.h` **and** `internal/model/event.go`
   (`EventType`, `eventActions`). Keep them numerically identical.
2. Write the program in `bpf/edr.bpf.c` using `new_event()` + `emit()`. Respect
   the verifier: bounded loops, per-CPU scratch for anything over ~256 bytes,
   masked offsets. See the `ebpf-sensors` skill.
3. Register it in `sensorAttachments` in `internal/bpfloader/source_linux.go`.
4. Populate the new fields in `internal/decode/wire.go` (and adjust offsets/
   `WireSize` only if the struct layout changed) and add a decode test.
5. Expose any new rule-visible field in `internal/model/fields.go`.

### Add a detection rule
1. Pick the right `rules/NN-area.yaml`. Give it the next `R-00NN` id.
2. Map it to a real ATT&CK technique (id + name + tactic).
3. Only reference fields that exist in `fields.go` and event types a sensor
   actually emits — `make replay` against a fixture that should trigger it.
4. Document it in `docs/DETECTIONS.md` and the coverage matrix.

### Add an output sink
Implement `output.Sink` in a new file under `internal/output`, then wire it into
`buildOne` in `registry.go` and add its config keys + validation in
`internal/config`.

---

## Testing expectations

- Unit tests live beside the code; integration fixtures in `test/`.
- Tests are fast (< 100ms), independent, and assert behaviour, not internals.
- Cover boundaries: short buffers, empty inputs, threshold edges, PID reuse.
- The detection logic has an end-to-end test (`internal/pipeline/pipeline_test.go`)
  that replays a recorded kill chain and asserts the alert and incident counts —
  keep it passing and extend it when you add detections.

---

## Safety

Enforcement (`response.mode: dry-run|enforce` and the BPF-LSM object) can lock
you out of a host. The rules: test on a snapshotted VM, start in `dry-run`, keep
the critical-path allowlist, know the kill switch. The full model is in
`docs/SAFETY.md` and is required reading before touching `internal/respond` or
`bpf/edr_lsm.bpf.c`.

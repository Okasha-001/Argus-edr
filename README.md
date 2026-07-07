# ARGUS

**Runtime endpoint detection & response for Linux, built on eBPF.**

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Kernel](https://img.shields.io/badge/kernel-5.8%2B%20(CO--RE)-orange)](docs/ARCHITECTURE.md)

ARGUS watches the Linux kernel directly through eBPF, turns raw process / file /
network activity into a unified event stream, evaluates it against behavioural
rules mapped to [MITRE ATT&CK](https://attack.mitre.org/), and can **stop** an
attack in the kernel via BPF LSM — not just alert on it. Same architecture the
production tools (Falco, Tetragon, Tracee) are built on, every line readable and
free / open source.

> Named after Argus Panoptes, the hundred-eyed giant who never slept while
> standing guard.

---

## Why behaviour, not signatures

A classic antivirus looks for *files* it already knows. Modern intrusions show up
as *behaviour*: a web server spawning a shell, a binary executing from `/tmp`,
a process reading `/etc/shadow`, a payload that never touches disk. ARGUS sees the
behaviour as it happens and reasons about the *sequence* — `nginx → bash →
outbound:4444 → read /etc/shadow → write crontab` is one **incident**, not four
disconnected log lines.

## Features

- **Broad sensor coverage** — process lifecycle (exec/fork/exit + full argv),
  file ops (open/unlink/rename/chmod), network (connect/accept/DNS), and
  security-relevant kernel events (module load, ptrace, bpf, capabilities).
- **CO-RE portability** — compile once, run on any 5.8+ kernel with BTF; no
  on-host compiler, no per-kernel rebuild.
- **Behavioural detection engine** — declarative YAML rules with a structured
  condition tree (`all` / `any` / `not`, 14 operators), every rule carrying its
  ATT&CK technique and severity. Import community [Sigma](https://github.com/SigmaHQ/sigma)
  rules with `argus sigma` (see [docs/SIGMA.md](docs/SIGMA.md)).
- **Threat intelligence** — optional IOC feeds (malicious IPs/CIDRs, domains,
  hashes) matched against every event, raising C2-tagged alerts that drive
  correlation and response (see [docs/INTEL.md](docs/INTEL.md)).
- **Correlation** — per-process-tree risk scoring and time-windowed sequence
  detection that promotes a kill chain to a single incident.
- **Enforcement** — kill / network-block / quarantine, and true *prevention*
  through BPF LSM, gated behind a deliberate `off → dry-run → enforce` safety
  model with an allowlist and a kill switch.
- **Pluggable outputs** — stdout (ECS JSON), rotating file, Loki, OpenSearch,
  Wazuh, syslog/CEF — behind one `Sink` interface.
- **Replay mode** — run the entire pipeline over a recorded event stream with no
  root and no kernel, for development, CI, and reproducible demos.

## Architecture

```
         kernel (eBPF/C)                      userspace agent (Go)
  ┌───────────────────────────┐     ┌────────────────────────────────────────┐
  │ tracepoints / kprobes /   │     │ ringbuf → decode → enrich → detect →     │
  │ fentry / LSM   ──ringbuf──▶│────▶│           respond → output sinks         │
  │ process · file · network  │     │ (proc tree · users · containers · hashes)│
  └───────────────────────────┘     └────────────────────────────────────────┘
                                                       │
                                          Loki / OpenSearch / Wazuh → Grafana
```

Full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quickstart

### Prerequisites

- Linux kernel **5.8+** with BTF (`/sys/kernel/btf/vmlinux` exists)
- `clang`/`llvm` + `bpftool` to build the eBPF objects, `go` 1.25+ for the agent
- `CAP_BPF` + `CAP_SYS_ADMIN` (+ `CAP_PERFMON`) or root to load programs

```bash
# 1. Generate the CO-RE type header and compile everything
make all                 # = make vmlinux bpf build

# 2. Run live (needs privileges; observe-only by default)
sudo ./build/bin/argus run --config configs/argus.yaml

# 3. Or run the whole pipeline offline — no root, no kernel
./build/bin/argus replay --rules rules test/integration/testdata/killchain.ndjson
```

The replay command is the fastest way to see detection working: it feeds a
recorded reverse-shell kill chain through the real enrichment, detection and
correlation code and prints the alerts and the correlated incident.

## Safety

Enforcement can lock you out of a host. ARGUS is **observe-only out of the box**
(`response.mode: off`). Before enabling prevention, read
[docs/SAFETY.md](docs/SAFETY.md): always test on a snapshotted VM, start in
`dry-run`, keep the critical-path allowlist, and know the kill switch.

## Repository layout

| Path | Contents |
|------|----------|
| `bpf/` | eBPF sensors (C), shared ABI (`common.h`), vendored headers |
| `cmd/` | `argus` agent and `argus-server` control plane entrypoints |
| `internal/` | agent packages: model, decode, bpfloader, enrich, detect, respond, output, pipeline, config |
| `rules/` | detection rules (YAML) mapped to ATT&CK |
| `deploy/` | systemd unit, Dockerfile, Grafana dashboards, Loki config |
| `docs/` | architecture, safety model, detection catalogue, roadmap |
| `test/` | integration fixtures, attack mappings, kernel matrix |

## Roadmap

The roadmap tracks live-kernel validation, deeper platform coverage, and
production hardening. See [docs/ROADMAP.md](docs/ROADMAP.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

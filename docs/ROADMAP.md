# Roadmap

ARGUS grows in shippable phases — each one a working, demonstrable version. A
security platform is great because of breadth, depth and engineering quality, not
line count; the phases add real capability, not padding.

## Done

- **Foundation & telemetry.** CO-RE eBPF sensors for process (exec with argv,
  fork, exit), file (open/unlink/rename/chmod), and network (tcp connect,
  accept); ring-buffer transport; the shared ABI.
- **Agent core.** Loader, decoder, enrichment (process tree, users, containers,
  hashing, reverse-shell heuristic), the ordered pipeline, replay source.
- **Detection.** YAML rule engine (condition tree, 14 operators), 11 rules mapped
  to ATT&CK, per-process correlation that opens incidents.
- **Sigma import.** `argus sigma` converts upstream Sigma rules (process, network,
  dns and file categories) into native ARGUS rules, translating fields, value
  modifiers and condition expressions and skipping anything outside the supported
  subset. See `docs/SIGMA.md`.
- **Threat intelligence.** Optional IOC feeds (malicious IPs/CIDRs, domains,
  hashes) matched against every event; a hit raises a high-severity, C2-tagged
  alert that flows through correlation and response. Off by default. See
  `docs/INTEL.md`.
- **Response.** kill/dry-run/enforce posture, allowlist, PID-reuse-guarded kill,
  nftables egress block / quarantine of a destination IP (rule-driven and via the
  fleet `QUARANTINE` command), and a BPF-LSM enforcement object
  (`bprm_check_security`) for `/tmp` execs.
- **Outputs.** stdout (ECS/pretty), rotating file, Loki, behind one `Sink`.
- **Fleet / control plane.** `argus-server` over gRPC/mTLS: enrollment (token +
  client-cert identity), heartbeats with a command queue, alert streaming,
  versioned rule distribution with agent-side hot-reload, cross-host correlation
  (lateral movement, C2 fan-in), and a localhost JSON admin API. See
  `docs/FLEET.md`.
- **Quality & packaging.** Unit + end-to-end tests (including an over-the-wire
  mTLS fleet test), race-clean, golangci-lint, CI (lint/test/bpf/build), systemd
  unit, Dockerfile, Grafana + Loki compose.
- **Performance & robustness.** Hot-path benchmarks (`make bench`, see
  `docs/PERFORMANCE.md`) and native fuzzing of the decoder and rule parser
  (`make fuzz`).

## Next

- **Sensors:** done — ptrace (T1055), module/bpf load (T1547.006), memfd exec
  (T1620), RWX mmap (T1055), setuid (T1548), DNS query names (T1071.004), IPv6
  endpoints, and a `security_file_open` read sensor that closes the R-0002 live
  gap. The kernel-level *deny* on file_open is now done (Phase 6). Remaining:
  container escape (T1611).
- **Detection:** done — 56 rules across the full ATT&CK kill chain plus a pure-Go
  YARA engine (`yara.matched` / R-0073); see `docs/ATTACK_COVERAGE.md`. Next:
  deeper cross-event correlation.
- **Observability:** done — a dependency-free Prometheus `/metrics` on the agent
  and control plane (events/alerts, per-stage latency, per-program eBPF cost,
  ring-buffer loss, fleet size), with a Grafana dashboard in `deploy/`. See
  `docs/PERFORMANCE.md`.
- **Response:** graduated response (alert→throttle→block→kill) and egress
  block/quarantine already done; tc-based traffic shaping next.
- **Hardening:** a kernel-version CI matrix (5.8/5.15/6.1/6.8) with a
  load/verifier smoke test is done (`.github/workflows/kernel-matrix.yml`,
  `scripts/verifier-smoke.sh`, `docs/PACKAGING.md`). Remaining: a documented
  end-to-end host-overhead % under a live, rooted workload (per-stage benchmarks +
  parser fuzzing already done — see `docs/PERFORMANCE.md`).
- **Advanced:** anomaly baselining (rarity/Isolation Forest) and a pure-Go YARA
  engine are done; next, anti-rootkit and eBPF-on-eBPF detection.
- **Self-protection:** done — LSM `task_kill` and `ptrace` deny guard the agent
  (tamper alerts → R-0074), and a userspace binary-integrity check and liveness
  watchdog (R-SELF-*). Remaining: a kernel watchdog that survives a frozen agent.
- **Fleet:** done — a SQLite-backed durable store (interface ready for Postgres),
  RBAC (viewer/operator/admin) and a tamper-evident signed audit log on the admin
  API, per-agent certificate rotation without re-enrolment, and full policy (not
  just rule) distribution in the bundle. See `docs/FLEET.md` and
  `docs/CONTROL_PLANE.md`. Remaining: cert revocation (CRL/OCSP), HA control plane.
- **UI:** done — an embedded, dependency-free web console for fleet, live alerts
  (SSE) and incident timelines, built on the admin API (`docs/CONTROL_PLANE.md`).
- **LLM-assisted triage:** done — `internal/triage` turns an incident into a
  summary + severity + containment + optional rule draft, offline by default with
  an opt-in Claude provider, surfaced on the incident timeline. See `docs/TRIAGE.md`.
- **Supply chain:** done — deb/rpm packaging (nfpm), SBOM (syft), cosign-signed
  releases, and a Helm chart. See `docs/PACKAGING.md`.
- **Cross-platform:** the event source is now the only platform-specific layer; an
  experimental Windows process source (`internal/winsource`) fills the same
  `model.Event` and reuses the whole detection/response/fleet stack. See
  `docs/CROSS_PLATFORM.md`. Next: ETW providers for network/file/registry and
  Windows enforcement.

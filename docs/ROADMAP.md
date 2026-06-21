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
  deeper cross-event correlation and ring-buffer-loss / per-program runtime
  metrics (the latter is Phase 7 observability).
- **Response:** graduated response (alert→throttle→block→kill) and egress
  block/quarantine already done; tc-based traffic shaping next.
- **Hardening:** documented end-to-end host-overhead % under a live, rooted
  workload (per-stage benchmarks + parser fuzzing already done — see
  `docs/PERFORMANCE.md`); a kernel-version CI matrix (5.8/5.15/6.1/6.8) with a
  load/verifier smoke test.
- **Advanced:** anomaly baselining (rarity/Isolation Forest), optional YARA,
  anti-rootkit and eBPF-on-eBPF detection.
- **Self-protection:** done — LSM `task_kill` and `ptrace` deny guard the agent
  (tamper alerts → R-0074), and a userspace binary-integrity check and liveness
  watchdog (R-SELF-*). Remaining: a kernel watchdog that survives a frozen agent.
- **Fleet, next:** a database-backed store (the interface is ready), RBAC and a
  signed audit log on the admin API, per-agent certificate issuance/rotation, and
  policy (not just rule) distribution.
- **UI:** a web console for fleet, live alerts and investigation timelines, built
  on the admin API.
- **Supply chain:** deb/rpm packaging, SBOM, signed releases, Helm chart.

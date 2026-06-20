# Known limitations

Stated plainly, because a security tool that hides its gaps is dangerous.

## Sensing

- **argv TOCTOU.** argv is captured at `execve` entry; a process could in
  principle rewrite it between capture and use. Captured as close to exec as
  possible; documented, not eliminated.
- **argv truncation.** Command lines longer than `MAX_ARGS_LEN` (512 bytes) are
  truncated.
- **openat is write-only.** Read-only opens are dropped in-kernel to spare the
  ring buffer, so read-based detections (e.g. `/etc/shadow` read) rely on the
  LSM `file_open` hook or replay rather than the openat firehose.
- **No in-kernel DNS parsing.** Port-53 connections are visible; query names are
  not yet extracted, so domain rules are not shipped.
- **IPv4 only in the wire struct.** The network fields carry IPv4; IPv6 endpoints
  are not yet represented in `struct event`.

## Correlation and process identity

- **PID reuse.** Mitigated with a composite process key (pid + start time)
  stamped onto every event by the process tree, and a comm re-check before kill —
  reduced, not impossible.
- **Ring-buffer loss.** Under extreme load the kernel drops new events when the
  buffer is full; the size is tunable and loss should be surfaced as a metric
  (counter wiring is on the roadmap).

## Enforcement

- **BPF LSM must be enabled at boot** (`lsm=...,bpf`), which not all kernels do
  by default; without it, enforcement degrades to observation.
- **Network block / quarantine are not implemented yet.** The responder records
  these actions as `unsupported` rather than silently doing nothing; the tc/
  nftables path is a later phase.
- **A full-root attacker** can ultimately disable any host agent. Self-protection
  (LSM `task_kill`, tamper alerts) raises the bar; it does not make this
  impossible.

## Scope

- Linux only (eBPF). The control plane, web UI, fleet management, anomaly/ML
  detection, threat-intel feeds and Sigma import are scaffolded or planned, not
  complete — see `ROADMAP.md`.

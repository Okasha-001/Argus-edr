# Known limitations

Stated plainly, because a security tool that hides its gaps is dangerous.

## Sensing

- **argv TOCTOU.** argv is captured at `execve` entry; a process could in
  principle rewrite it between capture and use. Captured as close to exec as
  possible; documented, not eliminated.
- **argv truncation.** Command lines longer than `MAX_ARGS_LEN` (512 bytes) are
  truncated.
- **openat is write-only.** Read-only opens are dropped in-kernel to spare the
  ring buffer. Reads of the credential files are instead caught at the open
  chokepoint by the `security_file_open` sensor (`/etc/shadow`, `/etc/gshadow`);
  any other read-only open is seen only via replay. That sensor is detection
  only; enforcement for those credential-file reads lives in the LSM
  `file_open` hook.
- **DNS capture is UDP `sendto` only.** Query names are extracted (the sensor
  forwards the raw query bytes from a port-53 `sendto`; the agent parses
  `dns.question.name`), but `sendmsg`-based, TCP and IPv6 resolvers are not yet
  covered, so a resolver using those paths is not seen.
- **IPv6 for TCP connect/accept only.** `struct event` now carries 16-byte
  addresses, so `tcp_connect` and `inet_csk_accept` report IPv6 endpoints. The DNS
  sensor still matches IPv4 port-53 `sendto` only (see the DNS note above).
- **Syscall sensors are offline-verified, live-load pending.** The ptrace, kernel-
  module, bpf(), memfd_create, RWX-mmap and setuid sensors compile, parse through
  the `cilium/ebpf` loader spec, and round-trip in `wire_test.go`/`make replay`,
  but loading them through the **kernel verifier** needs a root host with BTF and
  has not been exercised here (no privileged host in the build environment). Run
  `make all && sudo ./build/bin/argus run` on a snapshotted VM to confirm live.

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

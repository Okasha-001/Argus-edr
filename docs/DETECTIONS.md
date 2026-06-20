# Detection catalogue

Every shipped rule, its ATT&CK mapping, and what it keys on. Rules live in
`rules/*.yaml`; list them at any time with `argus rules --dir rules`.

| ID | Severity | Technique | Detects |
|----|----------|-----------|---------|
| R-0001 | high | T1036 Masquerading | execution from `/tmp`, `/var/tmp`, `/dev/shm` |
| R-0002 | critical | T1003 OS Credential Dumping | open of `/etc/shadow` / `/etc/gshadow` |
| R-0003 | high | T1053.003 Cron | write/rename under `/etc/cron*`, `/var/spool/cron` |
| R-0004 | high | T1543.002 systemd Service | write/rename of a systemd unit file |
| R-0005 | high | T1098.004 SSH Authorized Keys | write/rename of an `authorized_keys` file |
| R-0006 | critical | T1574.006 Dynamic Linker Hijacking | write/chmod of `/etc/ld.so.preload` |
| R-0007 | critical | T1059 Command & Scripting | shell with socket stdio spawned by a service (reverse shell) |
| R-0008 | high | T1571 Non-Standard Port | outbound connect to a common C2 port |
| R-0014 | high | T1070 Indicator Removal | unlink/rename under `/var/log` |
| R-0015 | high | T1548.001 Setuid/Setgid | chmod setting the setuid bit |
| R-0016 | medium | T1070.003 Clear Command History | unlink/rename of `.bash_history` |

R-0007 is the only rule that defaults to a `kill` response (and only when
enforcement is enabled). All others are alert-only by default.

## Telemetry caveats (be honest about live coverage)

- **openat forwards writes/creates only.** To keep the ring buffer quiet, the
  `sys_enter_openat` sensor drops read-only opens. So R-0002 (a *read* of
  `/etc/shadow`) fires from replayed streams and from the BPF-LSM `file_open`
  hook, but **not** from the openat firehose. Wiring `file_open` for targeted
  read detection is tracked in the roadmap.
- **No DNS-name capture yet.** Connections to port 53 are seen, but the query
  name is not parsed in-kernel, so domain-based rules are not shipped.
- **argv may be truncated** at `MAX_ARGS_LEN` and is captured at execve entry
  (see KNOWN_LIMITATIONS for the TOCTOU note).

## Correlation

Each alert contributes its `risk_score` (or a severity default) to its process's
running total within a 30s window. Crossing the threshold (75) opens an
**incident** that groups the alerts, techniques and rule ids — turning a kill
chain into one finding instead of many. The replay fixture demonstrates both an
immediate critical incident (reverse shell) and one that opens by accumulation
(`/tmp` exec + C2 connect by the same process).

## Adding a detection

See the `detection-rules` skill (`.claude/skills/detection-rules`). In short:
map to a real technique, reference only fields that exist and event types a
sensor emits, prove it with a replay fixture, and update this file.

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
| R-0060 | high | T1055 Process Injection | `ptrace` attach/poke into another process |
| R-0061 | high | T1547.006 Kernel Modules | kernel module load (`init_module`) |
| R-0062 | medium | T1059 Command & Scripting | `bpf()` syscall from an unexpected process |
| R-0063 | high | T1620 Reflective Code Loading | fileless staging via `memfd_create` |
| R-0064 | medium | T1055 Process Injection | writable+executable (RWX) memory mapping |
| R-0065 | high | T1548 Abuse Elevation Control | `setuid(0)` privilege escalation |
| R-0066 | high | T1071.004 Application Layer Protocol: DNS | DNS query with an overlong (tunneling) label |

R-0007 and R-0044 default to a `kill` response (and only when enforcement is
enabled). All others are alert-only by default.

The table highlights the originals; the full set is 56 rules — list them all,
validated, with `argus rules --dir rules`. The Phase-5 expansion added:

- **Discovery** (R-0017–0024): user/system/file/account/network/process
  enumeration, SUID search and service scanning. Low severity by design — the
  signal is a *burst* that correlates into an incident, not a single command.
- **Lateral movement** (R-0025–0028): outbound SSH/SCP pivots and remote-service
  connections.
- **Collection / credential access** (R-0029–0032, R-0070–0072): archive
  staging, private-key and secret harvesting, /tmp staging, shadow reads via
  command, brute-force tools and process-memory dumping.
- **Exfiltration** (R-0033–0035): raw-socket, public file-drop and HTTP upload.
- **Impact** (R-0036–0042): ransomware renames, recovery inhibition, service
  stop, data destruction, cryptomining, shutdown and disk wipe.
- **More C2 and evasion** (R-0043–0046, R-0067–0069): pipe-to-shell droppers,
  scripting reverse shells, tunnels/proxies, disabling security tooling, log
  clearing and base64-decode-to-shell.

## Signature scanning (YARA)

With `yara.enabled`, the enrich stage scans each executed file (bounded by
`yara.max_bytes`) against the bundled `rules/yara/*.yar` signatures using a small
pure-Go engine (no libyara/cgo). A hit is recorded in `yara.matched` and rule
**R-0073** alerts on it. Because the agent scans the binary that is exec'd, the
shipped signatures target malicious *binaries* (miners, reverse-shell tools, the
EICAR test file); interpreted scripts are out of scope for this path. See
`docs/YARA.md`.

## Telemetry caveats (be honest about live coverage)

- **openat forwards writes/creates only.** To keep the ring buffer quiet, the
  `sys_enter_openat` sensor drops read-only opens. Live reads of the credential
  files are instead caught by the `security_file_open` sensor, which matches
  `/etc/shadow` and `/etc/gshadow` at the kernel open chokepoint and feeds R-0002
  — whose process allowlist suppresses the routine PAM/account-tool reads so only
  unexpected readers alert. Any other read-only open is still seen only via replay.
- **DNS names are captured from UDP `sendto` to port 53.** The sensor forwards
  the raw query bytes and the agent parses the name into `dns.question.name`
  (keeping the kernel side dumb). `sendmsg`-based, TCP and IPv6 resolvers are not
  yet covered (see KNOWN_LIMITATIONS).
- **argv may be truncated** at `MAX_ARGS_LEN` and is captured at execve entry
  (see KNOWN_LIMITATIONS for the TOCTOU note).

## Correlation

Each alert contributes its `risk_score` (or a severity default) to its process's
running total within a 30s window. Crossing the threshold (75) opens an
**incident** that groups the alerts, techniques and rule ids — turning a kill
chain into one finding instead of many. The replay fixture demonstrates both an
immediate critical incident (reverse shell) and one that opens by accumulation
(`/tmp` exec + C2 connect by the same process).

## Anomaly scoring (detecting the unknown)

Rules catch what they name. The anomaly stage (`internal/anomaly`) adds a
probabilistic layer that flags what no rule describes. It runs in userspace
between enrichment and detection, and is **off by default** — it scores nothing
unless a trained baseline is loaded.

Two layers produce one score in 0–1, exposed to rules as `anomaly.score` on a
**0–100** scale:

- **Rarity baselining** — frequency maps over `process.executable`, parent→child,
  `destination.port`, and user→process. A value rarely seen during training is
  suspicious; the rarest dimension drives the score (never-seen → ~1.0).
- **Isolation Forest** — a small ensemble (100 trees × 256-point subsamples) over
  a per-event numeric vector (name/command lengths, argv count, hour, dest port,
  uid, path depth, name entropy). Few-and-different points isolate in fewer splits.

Train and use it:

```bash
argus baseline build --out baseline.json events.ndjson   # learn normal
argus replay --rules rules --baseline baseline.json suspect.ndjson  # score + detect
# live: set anomaly.enabled + anomaly.baseline_file in the agent config
```

A rule then keys on the score (see `rules/50-anomaly.yaml`, R-0050):

```yaml
match:
  all:
    - { field: event.type, op: eq, value: exec }
    - { field: anomaly.score, op: ge, value: 90 }
```

With no baseline the score is 0, so anomaly rules stay silent and the hot path
pays nothing — the safe default.

## Adding a detection

See the `detection-rules` skill (`.claude/skills/detection-rules`). In short:
map to a real technique, reference only fields that exist and event types a
sensor emits, prove it with a replay fixture, and update this file.

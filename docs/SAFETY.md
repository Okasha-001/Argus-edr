# Safety model

Enforcement can take down a host: a bad rule in enforce mode can kill a critical
service or deny a syscall everything depends on. ARGUS is built so that the
dangerous parts are off by default and reversible. Read this before enabling any
response or touching `internal/respond` or `bpf/edr_lsm.bpf.c`.

## Three modes, off by default

`response.mode` and the LSM `enforce_config` map share one scale:

| Mode | Userspace responder | LSM program | Use |
|------|--------------------|-------------|-----|
| `off` (default) | does nothing | inert (loaded but allows all) | observe only |
| `dry-run` | records the action it *would* take | records "would block", allows | validate rules safely |
| `enforce` | kills/blocks for real | returns `-EPERM` | active prevention |

Always run a new rule in `dry-run` first and confirm it only fires on real
threats before promoting it to `enforce`.

### The `max_mode` ceiling

When the agent is fleet-managed, the control plane can change the posture at
runtime (`SET_RESPONSE_MODE`). `response.max_mode` is a **local, immutable
ceiling** on that: a remote command may *lower* the posture but never raise it
past `max_mode`. It defaults to `response.mode`, so by default the fleet cannot
turn enforcement on against a host you pinned to `off` or `dry-run`. Allowing
remote escalation is an explicit opt-in (`mode: dry-run`, `max_mode: enforce`).
This keeps the off-by-default guarantee true at runtime, not just at startup —
even a compromised server cannot escalate a host past its ceiling.

## Guardrails

- **Critical-path allowlist.** `response.allowlist_paths` lists executables that
  must never be killed or blocked (systemd, sshd by default). The responder
  checks it before acting, so a misfire can't take out the host's plumbing.
- **PID-reuse guard.** Before killing, the responder re-reads `/proc/<pid>/comm`
  and refuses if it no longer matches what the alert observed — a freed PID
  reassigned to another process is not killed.
- **Kill switch.** Set `response.mode: off` (or `enforce_config = 0`) and reload
  to stop all enforcement immediately. Stopping the agent detaches the LSM
  program entirely.
- **The LSM hook is narrow.** It only acts on what policy explicitly targets and
  respects any earlier denial (`if ret != 0 return ret`).

## Graduated response

A rule may name an explicit response, which always wins. Otherwise the responder
picks one off a ladder by the alert's risk score (or, for a rule with no score,
its severity):

| Rung | Score | Action |
|------|-------|--------|
| throttle | ≥ 50 | **suspend** the process with `SIGSTOP` — a *reversible* freeze (`SIGCONT` resumes it) that halts the threat in place for review without the finality of a kill |
| network-block | ≥ 75 | drop the process's egress (falls back to throttle when the alert has no network destination) |
| kill | ≥ 90 | `SIGKILL` |

The ladder only chooses *what* to do; *whether* it happens is still gated by the
mode above — `off` does nothing, `dry-run` only records, `enforce` acts — and by
the allowlist and PID-reuse guard. Lower-risk alerts stay alert-only.

## Self-protection

Three LSM hooks defend the agent itself. Like all enforcement they are gated by
`response.mode`: inert at `off`, recording-only at `dry-run`, denying at
`enforce`. Each only ever targets the agent's own pid (written into the
`protected_pid` map at load), and a signal/trace the agent aims at itself always
passes.

| Hook | Protects against | On a hit |
|------|------------------|----------|
| `task_kill` | `kill -9` / `SIGSTOP` of the agent from another process | denies the signal, emits a `tamper` event (→ `R-0074`, T1562.001) |
| `ptrace_access_check` | a debugger reading the agent's memory or injecting into it | denies the attach, emits `tamper` |
| `file_open` | reads of `/etc/shadow`/`/etc/gshadow` by a process not on `response.cred_reader_allowlist` | denies the open, emits a blocked `open` event (→ `R-0002`, T1003) |

> **Stopping a self-protected agent.** Because `task_kill` refuses `SIGKILL`,
> `SIGTERM` and `SIGSTOP` in `enforce`, `systemctl stop argus` and `kill` will
> *fail* while enforcement is on — this is the point of tamper protection. To
> stop it deliberately, **lower the mode first**, then stop: set
> `response.mode: off` (a fleet `SET_RESPONSE_MODE off`, or as root
> `bpftool map update name enforce_config key 0 0 0 0 value 0 0 0 0`), which makes
> the hooks inert, then stop the service. Detaching the LSM link (process exit
> *forced* by the kernel, or `bpftool link detach`) also clears it.

> **`file_open` allowlist.** The kernel deny is matched by process *comm*, which
> is a coarse, spoofable key — a v1 heuristic, not a guarantee. The auth stack
> (`sshd`, `login`, `su`, …) ships on the allowlist; **run `dry-run` first** and
> read the blocked-open records to discover any reader specific to your host
> (PAM modules, a display manager) before enabling `enforce`, or local logins
> can break.

### Userspace tamper checks

Independent of the kernel hooks and *not* gated by `response.mode` (they only
raise alerts, never block), `response.self_protection` runs two checks, on by
default:

- **Binary integrity** — a SHA-256 of the agent's own executable, re-hashed every
  `integrity_interval_seconds`; a change underneath the running process raises
  `R-SELF-INTEGRITY`.
- **Liveness watchdog** — the pipeline kicks it per event; if the hot path makes
  no progress for `watchdog_timeout_seconds` it raises `R-SELF-WATCHDOG`. It
  cannot detect a fully frozen process, so keep the timeout above the host's
  normal quiet periods to avoid false stalls.

## Operating rules

1. **Test enforcement on a snapshotted VM**, never first on a host you care
   about. Take the snapshot *before* the experiment.
2. **Start in `dry-run`**, read the "would block" records, then enforce.
3. **Keep the allowlist current** for your environment's management tooling.
4. **Know how to recover:** serial/console access, and the snapshot, in case an
   enforce rule locks you out.

## BPF LSM prerequisites

Enforcement needs `CONFIG_BPF_LSM` and `bpf` in the kernel's `lsm=` boot list,
which most distros don't enable by default. `scripts/enable-bpf-lsm.sh` adds it
(root + reboot). If `bpf` is absent from `/sys/kernel/security/lsm`, the LSM
program won't attach and the agent logs a warning and continues observing.

## Fail-open vs fail-closed

If the agent dies, attached LSM programs are detached and the system fails
**open** (permissive) — the safe default for availability. A fail-closed posture
(deny on agent death) is possible by pinning programs but is intentionally not
the default; choose it deliberately, per host.

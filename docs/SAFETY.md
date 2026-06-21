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

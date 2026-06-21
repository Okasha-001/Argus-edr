// SPDX-License-Identifier: GPL-2.0
//
// ARGUS enforcement via BPF LSM. Unlike the sensors, these programs can return a
// non-zero value to *deny* an operation in the kernel before it happens.
//
// Every hook is gated by a userspace-controlled mode so the dangerous part is
// never on by default:
//   0 = off      programs loaded but inert
//   1 = dry-run  records what it *would* have blocked, but allows it
//   2 = enforce  actually returns -EPERM
//
// Hooks:
//   bprm_check_security  deny exec from /tmp                     (E1)
//   task_kill            deny fatal signals to the agent itself  (E2, self-protection)
//   ptrace_access_check  deny ptrace/inject against the agent    (E2, self-protection)
//
// Requires CONFIG_BPF_LSM and "bpf" present in the kernel's lsm= boot list.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

// Fatal/stop signals the agent guards itself against. SIGKILL and SIGSTOP can be
// neither caught nor ignored in userspace, so this kernel hook is the only place
// ARGUS can survive a `kill -9`. Values are the x86-64/arm64 UAPI numbers.
#define SIGKILL 9
#define SIGTERM 15
#define SIGSTOP 19

enum enforce_mode {
    MODE_OFF     = 0,
    MODE_DRY_RUN = 1,
    MODE_ENFORCE = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enforce_config SEC(".maps");

// protected_pid holds the agent's own tgid, written by userspace at load. The
// self-protection hooks refuse operations aimed at it. A zero value (never
// written) leaves self-protection inert even when the mode is enforce.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} protected_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} enforce_events SEC(".maps");

static __always_inline __u32 current_mode(void)
{
    __u32 key = 0;
    __u32 *mode = bpf_map_lookup_elem(&enforce_config, &key);
    return mode ? *mode : MODE_OFF;
}

static __always_inline __u32 guarded_pid(void)
{
    __u32 key = 0;
    __u32 *pid = bpf_map_lookup_elem(&protected_pid, &key);
    return pid ? *pid : 0;
}

static __always_inline int is_temp_path(const char *path)
{
    char head[8] = {};
    bpf_probe_read_kernel_str(head, sizeof(head), path);
    return head[0] == '/' && head[1] == 't' && head[2] == 'm' &&
           head[3] == 'p' && head[4] == '/';
}

// reserve_event stages one enforcement record in the ring buffer and fills the
// fields common to every hook: the *current* task (the actor) and its identity.
// Like new_event() in edr.bpf.c it zeroes only up to `domain` — that trailing
// DNS buffer is unused here, and a full-struct memset exceeds clang's inline
// limit, forcing a memset libcall the BPF target cannot emit.
static __always_inline struct event *reserve_event(__u32 type)
{
    struct event *e = bpf_ringbuf_reserve(&enforce_events, sizeof(*e), 0);
    if (!e)
        return NULL;

    __builtin_memset(e, 0, __builtin_offsetof(struct event, domain));
    e->type = type;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (__u32)id;

    __u64 ug = bpf_get_current_uid_gid();
    e->uid = (__u32)ug;
    e->gid = ug >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret; // an earlier hook already decided; respect it

    __u32 mode = current_mode();
    if (mode == MODE_OFF)
        return 0;

    const char *path = BPF_CORE_READ(bprm, filename);
    if (!is_temp_path(path))
        return 0;

    int deny = (mode == MODE_ENFORCE);
    struct event *e = reserve_event(EVENT_EXEC_BLOCKED);
    if (e) {
        bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), path);
        e->ret = deny ? -EPERM : 0;
        bpf_ringbuf_submit(e, 0);
    }
    return deny ? -EPERM : 0;
}

// Self-protection: refuse fatal signals aimed at the agent's own process so a
// `kill -9` or SIGSTOP from another process cannot silence it. A signal the agent
// sends to itself, and any signal while self-protection is unconfigured or the
// mode is off, passes through untouched. The actor (the signaller) is recorded as
// the tamper event's process, so the alert names who tried.
SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred, int ret)
{
    if (ret != 0)
        return ret;

    __u32 guarded = guarded_pid();
    if (guarded == 0)
        return 0;

    __u32 target = BPF_CORE_READ(p, tgid);
    if (target != guarded)
        return 0;

    __u32 sender = bpf_get_current_pid_tgid() >> 32;
    if (sender == guarded)
        return 0; // the agent signalling itself is legitimate

    if (sig != SIGKILL && sig != SIGTERM && sig != SIGSTOP)
        return 0;

    __u32 mode = current_mode();
    if (mode == MODE_OFF)
        return 0;

    int deny = (mode == MODE_ENFORCE);
    struct event *e = reserve_event(EVENT_TAMPER);
    if (e) {
        e->fmode = (__u16)sig;
        e->ret = deny ? -EPERM : 0;
        bpf_ringbuf_submit(e, 0);
    }
    return deny ? -EPERM : 0;
}

// Self-protection: refuse ptrace against the agent so a debugger cannot read its
// memory or inject code into it (the classic way to neutralise an EDR without
// killing it). Same guard shape as task_kill — only the agent's own tgid, and
// never the agent tracing itself. fmode carries the PTRACE_MODE_* access flags.
SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_guard, struct task_struct *child, unsigned int ptrace_mode, int ret)
{
    if (ret != 0)
        return ret;

    __u32 guarded = guarded_pid();
    if (guarded == 0)
        return 0;

    __u32 target = BPF_CORE_READ(child, tgid);
    if (target != guarded)
        return 0;

    __u32 tracer = bpf_get_current_pid_tgid() >> 32;
    if (tracer == guarded)
        return 0; // the agent tracing itself (e.g. its own diagnostics) is fine

    __u32 mode = current_mode();
    if (mode == MODE_OFF)
        return 0;

    int deny = (mode == MODE_ENFORCE);
    struct event *e = reserve_event(EVENT_TAMPER);
    if (e) {
        e->fmode = (__u16)ptrace_mode;
        e->ret = deny ? -EPERM : 0;
        bpf_ringbuf_submit(e, 0);
    }
    return deny ? -EPERM : 0;
}

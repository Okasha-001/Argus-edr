// SPDX-License-Identifier: GPL-2.0
//
// ARGUS sensors: process, file and network telemetry collected from stable
// tracepoints and a couple of kprobes. The programs are intentionally "dumb" —
// they collect and forward, all interpretation lives in the Go agent. That
// keeps each program small, easy to verify, and cheap at runtime.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "credfile.h"

// GPL is required to call the bpf helpers we rely on (ringbuf, probe_read, ...).
char LICENSE[] SEC("license") = "GPL";

// Open flags we care about. We only forward writes/creates from the openat
// firehose to keep the ring buffer from drowning in read traffic; targeted
// read detection (e.g. /etc/shadow) is handled by the LSM file_open hook.
#define O_WRONLY 0x1
#define O_RDWR   0x2
#define O_CREAT  0x40
#define O_TRUNC  0x200

#define AF_INET  2
#define AF_INET6 10

#define RINGBUF_BYTES (8 * 1024 * 1024)

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_BYTES);
} events SEC(".maps");

// One per-CPU counter of ring-buffer drops. bpf_ringbuf_output fails when the
// buffer is full, losing the event; userspace sums this and exposes it as the
// event-loss metric (closes the O2 gap). Per-CPU so the increment needs no atomic.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped SEC(".maps");

// The event struct dwarfs the 512-byte BPF stack, so we stage each event in a
// per-CPU scratch slot instead of on the stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} scratch SEC(".maps");

// argv is only available at execve *entry*, but the resolved path and the new
// comm are only correct at sched_process_exec. We capture argv here keyed by
// pid_tgid and stitch it onto the exec event a moment later.
struct argv_buf {
    __u32 len;
    char  data[MAX_ARGS_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct argv_buf);
} argv_cache SEC(".maps");

// argv_buf is also too large for the stack, so it is assembled in a per-CPU
// slot before being copied into the per-pid cache above.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct argv_buf);
} argv_scratch SEC(".maps");

static __always_inline struct event *new_event(__u32 type)
{
    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return NULL;

    // The per-CPU scratch slot is reused between events, so clear stale data
    // before each use. We zero only up to `domain`: that trailing buffer is
    // DNS-only and larger than everything before it, so clearing it here too
    // would (a) push this memset past clang's inline limit (~1 KiB), forcing a
    // memset libcall the BPF target can't emit, and (b) cost every hot-path
    // event a needless 256-byte clear. handle_sendto is the only producer of
    // EVENT_DNS and fills `domain` itself; no other event type reads it.
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

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

static __always_inline void emit(struct event *e)
{
    if (bpf_ringbuf_output(&events, e, sizeof(*e), 0)) {
        __u32 key = 0;
        __u64 *lost = bpf_map_lookup_elem(&dropped, &key);
        if (lost)
            (*lost)++; // this CPU owns its slot, so a plain increment is safe
    }
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    struct argv_buf *buf = bpf_map_lookup_elem(&argv_scratch, &zero);
    if (!buf)
        return 0;
    __builtin_memset(buf, 0, sizeof(*buf));

    const char *const *argv = (const char *const *)ctx->args[1];
    __u32 off = 0;

#pragma unroll
    for (int i = 0; i < MAX_ARGV_COUNT; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        if (off >= MAX_ARGS_LEN - 1)
            break;
        off &= (MAX_ARGS_LEN - 1);
        long n = bpf_probe_read_user_str(&buf->data[off], MAX_ARGS_LEN - off, argp);
        if (n <= 0)
            break;
        off += n;
    }

    buf->len = off;
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&argv_cache, &id, buf, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e = new_event(EVENT_EXEC);
    if (!e)
        return 0;

    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
                              (void *)ctx + fname_off);

    __u64 id = bpf_get_current_pid_tgid();
    struct argv_buf *buf = bpf_map_lookup_elem(&argv_cache, &id);
    if (buf) {
        __builtin_memcpy(e->args, buf->data, MAX_ARGS_LEN);
        e->args_len = buf->len;
        bpf_map_delete_elem(&argv_cache, &id);
    }

    emit(e);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event *e = new_event(EVENT_FORK);
    if (!e)
        return 0;

    e->pid = ctx->child_pid;
    e->tid = ctx->child_pid;
    e->ppid = ctx->parent_pid;

    unsigned short comm_off = ctx->__data_loc_child_comm & 0xFFFF;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), (void *)ctx + comm_off);

    emit(e);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
    struct event *e = new_event(EVENT_EXIT);
    if (!e)
        return 0;

    // Only the thread-group leader's exit marks the process exiting.
    if (e->pid != e->tid)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ret = BPF_CORE_READ(task, exit_code) >> 8;

    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&argv_cache, &id);

    emit(e);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    int flags = (int)ctx->args[2];
    if (!(flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)))
        return 0;

    struct event *e = new_event(EVENT_OPEN);
    if (!e)
        return 0;

    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (const char *)ctx->args[1]);
    e->fmode = (__u16)flags;

    emit(e);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = new_event(EVENT_UNLINK);
    if (!e)
        return 0;

    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (const char *)ctx->args[1]);

    emit(e);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = new_event(EVENT_RENAME);
    if (!e)
        return 0;

    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (const char *)ctx->args[1]);
    bpf_probe_read_user_str(&e->args, sizeof(e->args),
                            (const char *)ctx->args[3]);

    emit(e);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = new_event(EVENT_CHMOD);
    if (!e)
        return 0;

    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (const char *)ctx->args[1]);
    e->fmode = (__u16)ctx->args[2];

    emit(e);
    return 0;
}

// Targeted credential-read detection (T1003). The openat sensor forwards only
// writes to keep the ring buffer quiet, so a *read* of /etc/shadow is invisible
// there. security_file_open is the open chokepoint for every path regardless of
// syscall; we match the credential files cheaply by basename + parent dir (no
// full-path walk) and forward the canonical path as an open event, so the same
// R-0002 rule fires on a live read. Detection only — a kprobe cannot deny; that
// is Phase 6 (LSM file_open).
SEC("kprobe/security_file_open")
int BPF_KPROBE(handle_file_open, struct file *file)
{
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);

    char base[8] = {};
    bpf_probe_read_kernel_str(base, sizeof(base), name);
    if (!is_shadow_basename(base))
        return 0;

    char parent[4] = {};
    bpf_probe_read_kernel_str(parent, sizeof(parent),
                              BPF_CORE_READ(dentry, d_parent, d_name.name));
    if (parent[0] != 'e' || parent[1] != 't' || parent[2] != 'c' || parent[3] != 0)
        return 0; // matched a "shadow" file, but not under /etc

    struct event *e = new_event(EVENT_OPEN);
    if (!e)
        return 0;

    // Rebuild the canonical path from verified parts: parent is "etc", basename is
    // shadow/gshadow. new_event zeroed filename, so the read NUL-terminates it.
    __builtin_memcpy(e->filename, "/etc/", 5);
    bpf_probe_read_kernel_str(&e->filename[5], sizeof(e->filename) - 5, name);
    emit(e);
    return 0;
}

static __always_inline void fill_socket(struct event *e, struct sock *sk)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->family = family;
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    // saddr/daddr hold 16 bytes (IPv6); for IPv4 we write the 4-byte address into
    // the first word and leave the rest zero (new_event cleared it). skc_addrpair
    // and skc_v6_* are unions over the same storage, so we pick by family.
    if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr);
    } else {
        __u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->saddr, &saddr, sizeof(saddr));
        __builtin_memcpy(e->daddr, &daddr, sizeof(daddr));
    }
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk)
{
    struct event *e = new_event(EVENT_CONNECT);
    if (!e)
        return 0;

    fill_socket(e, sk);
    emit(e);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(handle_inet_accept, struct sock *sk)
{
    if (!sk)
        return 0;

    struct event *e = new_event(EVENT_ACCEPT);
    if (!e)
        return 0;

    fill_socket(e, sk);
    emit(e);
    return 0;
}

// Memory protection bits we treat as suspicious when set together (RWX).
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define DNS_PORT 53

// ptrace into another process is the classic injection primitive (T1055). We
// forward request and target pid; the agent decides which requests matter.
SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = new_event(EVENT_PTRACE);
    if (!e)
        return 0;

    e->fmode = (__u16)ctx->args[0]; // request
    e->ret = (__s32)ctx->args[1];   // target pid
    emit(e);
    return 0;
}

// Loading a kernel module is how rootkits enter the kernel (T1547.006/T1014).
SEC("kprobe/do_init_module")
int BPF_KPROBE(handle_init_module, struct module *mod)
{
    struct event *e = new_event(EVENT_KMOD);
    if (!e)
        return 0;

    BPF_CORE_READ_STR_INTO(&e->filename, mod, name);
    emit(e);
    return 0;
}

// The bpf() syscall itself can be abused (malicious eBPF, map tampering); the
// agent flags unexpected callers (T1059).
SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_bpf(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = new_event(EVENT_BPF);
    if (!e)
        return 0;

    e->fmode = (__u16)ctx->args[0]; // bpf command
    emit(e);
    return 0;
}

// memfd_create backs fileless execution: a payload lives only in an anonymous
// fd, then is exec'd with no path on disk (T1620).
SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = new_event(EVENT_MEMFD);
    if (!e)
        return 0;

    bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                            (const char *)ctx->args[0]);
    e->fmode = (__u16)ctx->args[1]; // flags
    emit(e);
    return 0;
}

// A writable+executable mapping is the hallmark of shellcode staging (T1055).
// We only forward the RWX case to keep the firehose down.
SEC("kprobe/security_mmap_file")
int BPF_KPROBE(handle_mmap_file, struct file *file, unsigned long prot)
{
    if (!((prot & PROT_WRITE) && (prot & PROT_EXEC)))
        return 0;

    struct event *e = new_event(EVENT_MMAP_EXEC);
    if (!e)
        return 0;

    e->fmode = (__u16)prot;
    emit(e);
    return 0;
}

// setuid is a privilege transition; setuid(0) from a non-root context is a
// red flag for local privilege escalation (T1548).
SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e = new_event(EVENT_PRIV_CHANGE);
    if (!e)
        return 0;

    e->ret = (__s32)ctx->args[0]; // requested uid
    emit(e);
    return 0;
}

// DNS visibility (T1071.004): libc and most resolvers send the query with
// sendto(); args[1] is the user buffer holding the DNS message and args[4] the
// destination sockaddr. We forward the raw query bytes of a port-53 IPv4 send and
// let the agent parse the queried name — the sensor stays dumb. (UDP path only;
// sendmsg-based, TCP and IPv6 resolvers are not covered here — see KNOWN_LIMITATIONS.)
SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx)
{
    const void *dest_addr = (const void *)ctx->args[4];
    if (!dest_addr)
        return 0;

    struct sockaddr_in dest = {};
    bpf_probe_read_user(&dest, sizeof(dest), dest_addr);
    if (dest.sin_family != AF_INET || dest.sin_port != bpf_htons(DNS_PORT))
        return 0;

    struct event *e = new_event(EVENT_DNS);
    if (!e)
        return 0;

    // new_event leaves `domain` uninitialised; require a full read of the query
    // buffer or drop the event, so a faulted read can never emit a stale name
    // left in the per-CPU scratch by an earlier query.
    if (bpf_probe_read_user(&e->domain, sizeof(e->domain), (const void *)ctx->args[1]) != 0)
        return 0;

    e->family = AF_INET;
    __builtin_memcpy(e->daddr, &dest.sin_addr.s_addr, sizeof(dest.sin_addr.s_addr));
    e->dport = DNS_PORT;
    emit(e);
    return 0;
}

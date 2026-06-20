// SPDX-License-Identifier: GPL-2.0
//
// ARGUS enforcement via BPF LSM. Unlike the sensors, this program can return a
// non-zero value to *deny* an operation in the kernel before it happens.
//
// It is gated by a userspace-controlled mode so the dangerous part is never on
// by default:
//   0 = off      program loaded but inert
//   1 = dry-run  records what it *would* have blocked, but allows it
//   2 = enforce  actually returns -EPERM
//
// Requires CONFIG_BPF_LSM and "bpf" present in the kernel's lsm= boot list.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

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

static __always_inline int is_temp_path(const char *path)
{
    char head[8] = {};
    bpf_probe_read_kernel_str(head, sizeof(head), path);
    return head[0] == '/' && head[1] == 't' && head[2] == 'm' &&
           head[3] == 'p' && head[4] == '/';
}

static __always_inline void record(const char *path, int denied)
{
    struct event *e = bpf_ringbuf_reserve(&enforce_events, sizeof(*e), 0);
    if (!e)
        return;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_EXEC_BLOCKED;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->ret = denied ? -EPERM : 0;

    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (__u32)id;

    __u64 ug = bpf_get_current_uid_gid();
    e->uid = (__u32)ug;
    e->gid = ug >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), path);

    bpf_ringbuf_submit(e, 0);
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
    record(path, deny);
    return deny ? -EPERM : 0;
}

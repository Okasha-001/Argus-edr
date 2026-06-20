/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARGUS_COMMON_H
#define ARGUS_COMMON_H

/*
 * ABI shared between the eBPF sensors and the Go agent.
 *
 * Field order is deliberate: 8-byte fields, then 4-byte, then 2-byte, then the
 * byte arrays. That leaves no padding on x86-64/arm64, so the struct maps 1:1
 * onto the Go wire struct in internal/decode without alignment surprises.
 *
 * MAX_ARGS_LEN is a power of two on purpose: the execve argv loop masks the
 * write offset with (MAX_ARGS_LEN - 1) to prove boundedness to the verifier.
 */

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS_LEN     512
#define MAX_ARGV_COUNT   32

enum event_type {
    EVENT_EXEC         = 1,
    EVENT_FORK         = 2,
    EVENT_EXIT         = 3,
    EVENT_OPEN         = 4,
    EVENT_UNLINK       = 5,
    EVENT_RENAME       = 6,
    EVENT_CHMOD        = 7,
    EVENT_CONNECT      = 8,
    EVENT_ACCEPT       = 9,
    EVENT_EXEC_BLOCKED = 10, /* emitted by the LSM enforcement object */
};

struct event {
    __u64 timestamp_ns;             /* bpf_ktime_get_ns(), monotonic since boot */
    __u64 cgroup_id;                /* container/cgroup discriminator           */
    __u32 type;                     /* enum event_type                          */
    __u32 pid;                      /* thread-group id (the "process" pid)       */
    __u32 tid;                      /* kernel thread id                         */
    __u32 ppid;                     /* parent thread-group id                   */
    __u32 uid;
    __u32 gid;
    __u32 saddr;                    /* IPv4 source, network byte order          */
    __u32 daddr;                    /* IPv4 destination, network byte order     */
    __s32 ret;                      /* return/exit code when meaningful         */
    __u32 args_len;                 /* used bytes in args                       */
    __u16 sport;                    /* source port, host byte order             */
    __u16 dport;                    /* destination port, host byte order        */
    __u16 family;                   /* AF_INET / AF_INET6                       */
    __u16 fmode;                    /* open flags / chmod mode (low 16 bits)    */
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
    char  args[MAX_ARGS_LEN];       /* NUL-separated argv (exec) or rename dst   */
};

#endif /* ARGUS_COMMON_H */

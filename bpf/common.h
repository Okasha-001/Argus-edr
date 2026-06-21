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
#define MAX_DOMAIN_LEN   256
#define IP_ADDR_LEN      16  /* holds an IPv6 address; IPv4 uses the first 4 bytes */

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
    EVENT_PTRACE       = 11, /* ptrace() — process injection (T1055)            */
    EVENT_KMOD         = 12, /* kernel module load — rootkit (T1547.006/T1014)  */
    EVENT_BPF          = 13, /* bpf() syscall (T1059)                           */
    EVENT_MEMFD        = 14, /* memfd_create — fileless staging (T1620)         */
    EVENT_MMAP_EXEC    = 15, /* RWX mmap/mprotect — shellcode (T1055)           */
    EVENT_PRIV_CHANGE  = 16, /* setuid/setgid — privilege change (T1548)        */
    EVENT_DNS          = 17, /* DNS query (raw query bytes; T1071.004)          */
    EVENT_TAMPER       = 18, /* self-protection tripwire — kill/ptrace vs agent */
};

/*
 * Field reuse for the syscall sensors above (no layout change):
 *   ptrace      : fmode = request,    ret = target pid
 *   kmod        : filename = module name
 *   bpf         : fmode = bpf command
 *   memfd       : filename = memfd name, fmode = flags
 *   mmap_exec   : fmode = prot flags
 *   priv_change : ret = requested uid
 *   tamper      : comm/pid = the actor attacking the agent, fmode = signal or
 *                 ptrace mode, ret = -EPERM when the attempt was denied else 0
 */

struct event {
    __u64 timestamp_ns;             /* bpf_ktime_get_ns(), monotonic since boot */
    __u64 cgroup_id;                /* container/cgroup discriminator           */
    __u32 type;                     /* enum event_type                          */
    __u32 pid;                      /* thread-group id (the "process" pid)       */
    __u32 tid;                      /* kernel thread id                         */
    __u32 ppid;                     /* parent thread-group id                   */
    __u32 uid;
    __u32 gid;
    __s32 ret;                      /* return/exit code when meaningful         */
    __u32 args_len;                 /* used bytes in args                       */
    __u16 sport;                    /* source port, host byte order             */
    __u16 dport;                    /* destination port, host byte order        */
    __u16 family;                   /* AF_INET / AF_INET6                       */
    __u16 fmode;                    /* open flags / chmod mode (low 16 bits)    */
    __u8  saddr[IP_ADDR_LEN];       /* source IP, network byte order; IPv4 in   */
                                    /* the first 4 bytes, rest zero             */
    __u8  daddr[IP_ADDR_LEN];       /* destination IP, same encoding as saddr   */
    char  comm[TASK_COMM_LEN];
    char  filename[MAX_FILENAME_LEN];
    char  args[MAX_ARGS_LEN];       /* NUL-separated argv (exec) or rename dst   */
    char  domain[MAX_DOMAIN_LEN];   /* raw DNS query bytes (EVENT_DNS); parsed   */
                                    /* into a name in userspace                  */
};

#endif /* ARGUS_COMMON_H */

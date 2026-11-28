// Chaperon Integrity kernel-Sentinel: real kernel eBPF, cgroup-WIDE syscall monitor.
// Scope = any task whose cgroup_id is in protected_cgroups (so the tenant AND all its
// children/descendants in that cgroup are covered — the cgroup advantage over PID).
// Memory-tamper syscalls that TARGET a sealed/protected address range -> bpf_send_signal(SIGKILL).
// /proc/<pid>/mem is caught at the kernel open handler (kprobe:mem_open), not path-string only.
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U<<10)
#endif

char LICENSE[] SEC("license") = "GPL";

#ifndef __NR_mprotect
#define __NR_mprotect       10
#define __NR_mmap            9
#define __NR_munmap         11
#define __NR_mremap         25
#define __NR_madvise        28
#define __NR_shmat          30
#define __NR_ptrace        101
#define __NR_pkey_mprotect 329
#define __NR_execve         59
#endif
#define PROT_WRITE  0x2
#define MAP_FIXED   0x10
#define MADV_DONTNEED 4
/* Request I: every advice that discards page content (a discarded private page reverts to the file / zero) */
#define MADV_FREE 8
#define MADV_REMOVE 9
#define MADV_DONTNEED_LOCKED 24
#ifndef __NR_execveat
#define __NR_execveat 322
#endif
static __always_inline int madv_discards(long a)
{ return a == MADV_DONTNEED || a == MADV_FREE || a == MADV_REMOVE || a == MADV_DONTNEED_LOCKED; }
/* Request P: a sealed process's children inherit its sealed regions. MADV_DONTFORK (range not copied to a child)
   and MADV_WIPEONFORK (range zero-filled in a child) on a protected range would break that inheritance. */
#define MADV_DONTFORK 10
#define MADV_WIPEONFORK 18
static __always_inline int madv_breaks_inherit(long a)
{ return madv_discards(a) || a == MADV_DONTFORK || a == MADV_WIPEONFORK; }

struct prange { __u64 start; __u64 end; };

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
         __uint(key_size, sizeof(__u64)); __uint(value_size, sizeof(__u8)); } protected_cgroups SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 128);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct prange)); } protected_ranges SEC(".maps");

/* violation event log for userspace visibility */
struct viol { __u64 cgid; __u32 pid; __u32 nr; __u64 addr; };
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 16); } integ_events SEC(".maps");

/* runtime control (ranges registered after load): [0]={n_ranges, block_exec} */
struct ictl { __u32 n_ranges; __u32 block_exec; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct ictl)); } integ_ctl SEC(".maps");
static __always_inline struct ictl *getctl(void){ __u32 z=0; return bpf_map_lookup_elem(&integ_ctl,&z); }

static __always_inline int in_protected_cg(__u64 *cgid_out)
{
    __u64 cg = bpf_get_current_cgroup_id();
    if (cgid_out) *cgid_out = cg;
    __u8 *w = bpf_map_lookup_elem(&protected_cgroups, &cg);
    return w ? 1 : 0;
}

#ifndef MREMAP_FIXED
#define MREMAP_FIXED 2
#endif
#define INTEG_MAXR 128u  /* == protected_ranges max_entries; integ_setranges REFUSES registering >128 (Request I: was 64) */

/* request [a,a+len) overlaps protected [s,e) ?  overflow- and zero-length-safe. */
static __always_inline int range_overlap(__u64 a, __u64 len, __u64 s, __u64 e)
{
    __u64 aend;
    if (len == 0) aend = a + 1;                 /* point request: the start addr */
    else { aend = a + len; if (aend < a) aend = ~0ULL; }   /* clamp wrap */
    return (a < e) && (aend > s);
}

/* checks ALL registered ranges (not just 8) and the FULL [addr,addr+len), not only the start. */
static __always_inline int hits_protected(__u64 addr, __u64 len)
{
    struct ictl *c = getctl(); __u32 n = c ? c->n_ranges : 0;
    if (n > INTEG_MAXR) n = INTEG_MAXR;         /* loader refuses >MAXR; clamp defensively */
#define CHK(I) do { if (n > (I)) { __u32 k=(I); struct prange *r=bpf_map_lookup_elem(&protected_ranges,&k); if (r && range_overlap(addr,len,r->start,r->end)) return 1; } } while(0)
    CHK(0); CHK(1); CHK(2); CHK(3); CHK(4); CHK(5); CHK(6); CHK(7); CHK(8); CHK(9); CHK(10); CHK(11); CHK(12); CHK(13); CHK(14); CHK(15); CHK(16); CHK(17); CHK(18); CHK(19); CHK(20); CHK(21); CHK(22); CHK(23); CHK(24); CHK(25); CHK(26); CHK(27); CHK(28); CHK(29); CHK(30); CHK(31); CHK(32); CHK(33); CHK(34); CHK(35); CHK(36); CHK(37); CHK(38); CHK(39); CHK(40); CHK(41); CHK(42); CHK(43); CHK(44); CHK(45); CHK(46); CHK(47); CHK(48); CHK(49); CHK(50); CHK(51); CHK(52); CHK(53); CHK(54); CHK(55); CHK(56); CHK(57); CHK(58); CHK(59); CHK(60); CHK(61); CHK(62); CHK(63); CHK(64); CHK(65); CHK(66); CHK(67); CHK(68); CHK(69); CHK(70); CHK(71); CHK(72); CHK(73); CHK(74); CHK(75); CHK(76); CHK(77); CHK(78); CHK(79); CHK(80); CHK(81); CHK(82); CHK(83); CHK(84); CHK(85); CHK(86); CHK(87); CHK(88); CHK(89); CHK(90); CHK(91); CHK(92); CHK(93); CHK(94); CHK(95); CHK(96); CHK(97); CHK(98); CHK(99); CHK(100); CHK(101); CHK(102); CHK(103); CHK(104); CHK(105); CHK(106); CHK(107); CHK(108); CHK(109); CHK(110); CHK(111); CHK(112); CHK(113); CHK(114); CHK(115); CHK(116); CHK(117); CHK(118); CHK(119); CHK(120); CHK(121); CHK(122); CHK(123); CHK(124); CHK(125); CHK(126); CHK(127);
#undef CHK
    return 0;
}

static __always_inline void report_and_kill(__u64 cgid, __u32 nr, __u64 addr)
{
    struct viol *e = bpf_ringbuf_reserve(&integ_events, sizeof(*e), 0);
    if (e) {
        e->cgid = cgid; e->pid = bpf_get_current_pid_tgid() >> 32; e->nr = nr; e->addr = addr;
        bpf_ringbuf_submit(e, 0);
    }
    bpf_send_signal(9);   /* SIGKILL the offending task (self-context) */
}

/* generic raw syscall entry: one program, id-switched, cgroup-filtered. */
struct raw_sys_enter { unsigned long long _pad; long id; unsigned long args[6]; };

SEC("tracepoint/raw_syscalls/sys_enter")
int integ_sys_enter(struct raw_sys_enter *ctx)
{
    __u64 cgid;
    if (!in_protected_cg(&cgid)) return 0;
    long id = ctx->id;
    unsigned long a0 = ctx->args[0];   /* addr   */
    unsigned long a1 = ctx->args[1];   /* len    */

    switch (id) {
    case __NR_mprotect:                 /* mprotect(addr,len,prot) */
    case __NR_pkey_mprotect:
        if ((ctx->args[2] & PROT_WRITE) && hits_protected(a0, a1)) report_and_kill(cgid, id, a0);
        break;
    case __NR_mmap:                     /* mmap(addr,len,prot,flags,...) : MAP_FIXED over a protected range */
        if ((ctx->args[3] & MAP_FIXED) && hits_protected(a0, a1)) report_and_kill(cgid, id, a0);
        break;
    case __NR_mremap:                   /* mremap(old,oldlen,newlen,flags,newaddr): check old AND fixed-new */
        if (hits_protected(a0, a1)) report_and_kill(cgid, id, a0);
        if ((ctx->args[3] & MREMAP_FIXED) && hits_protected(ctx->args[4], ctx->args[2])) report_and_kill(cgid, id, ctx->args[4]);
        break;
    case __NR_munmap:                   /* munmap(addr,len) */
        if (hits_protected(a0, a1)) report_and_kill(cgid, id, a0);
        break;
    case __NR_madvise:                  /* madvise(addr,len,advice) : DONTNEED on protected range */
        if (madv_breaks_inherit((long)ctx->args[2]) && hits_protected(a0, a1)) report_and_kill(cgid, id, a0);
        break;
    case __NR_shmat:                    /* shmat into the address space */
        report_and_kill(cgid, id, a0);
        break;
    case __NR_ptrace:                   /* ptrace from within the tenant cgroup */
        report_and_kill(cgid, id, a0);
        break;
    case __NR_execve:
    case __NR_execveat:
        { struct ictl *c=getctl(); if (c && c->block_exec) report_and_kill(cgid, id, 0); }
        break;
    default:
        break;
    }
    return 0;
}

/* /proc/<pid>/mem opened: caught at the kernel handler, path-string-independent. */
SEC("kprobe/mem_open")
int BPF_KPROBE(integ_mem_open)
{
    __u64 cgid;
    if (!in_protected_cg(&cgid)) return 0;
    report_and_kill(cgid, 9999 /*mem_open marker*/, 0);
    return 0;
}

/* Request I: madvise issued through io_uring (IORING_OP_MADVISE) never passes the madvise syscall entry;
   do_madvise() is reached by both paths. */
SEC("kprobe/do_madvise")
int BPF_KPROBE(integ_do_madvise, void *mm, unsigned long start, unsigned long len, int behavior)
{
    __u64 cgid;
    if (!in_protected_cg(&cgid)) return 0;
    if (madv_breaks_inherit(behavior) && hits_protected(start, len)) report_and_kill(cgid, 9998 /*do_madvise marker*/, start);
    return 0;
}


/* ===== Request P: sealed-process registry and NIC gate (RDMA uverbs command interface of the mlx5 PMD) =====
 * sealed_procs: processes that completed agent sealing. Written by the trusted Manager (root, pinned map; the tenant
 * has no bpf() access) after every protection step, and by this Sentinel itself: a process forked by a sealed process
 * inherits the sealed agent regions and the status; a successful exec removes it; the exit of the process removes it.
 * Identity = tgid + start time in clock ticks (same unit as /proc/<pid>/stat field 22), so a reused PID never matches.
 * NIC gate: for a file of the RDMA verbs device (uverbs) a tenant task (protected cgroup) that is not sealed is denied
 * (-EPERM) BEFORE the uverbs handler runs and SIGKILLed: open of the device, ioctl (the command interface), mmap
 * (doorbell/UAR pages), write (legacy command ABI). The check runs per call, so an inherited or passed FD is covered. */
#include <bpf/bpf_core_read.h>
struct file_operations;
struct inode { __u32 i_rdev; } __attribute__((preserve_access_index));
struct file { const struct file_operations *f_op; struct inode *f_inode; } __attribute__((preserve_access_index));
struct task_struct { int pid; int tgid; struct task_struct *group_leader; __u64 start_boottime; } __attribute__((preserve_access_index));

#define CHAP_TICK_NS 10000000ULL      /* nsec_to_clock_t with USER_HZ=100: /proc/<pid>/stat starttime unit */
#define NG_MAXDEV 16
struct sproc { __u64 start_ticks; __u32 origin; __u32 parent; __u64 reg_ns; };   /* origin 1 Manager, 2 fork */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct sproc)); } sealed_procs SEC(".maps");
/* fops0/fops1 = uverbs_fops / uverbs_mmap_fops (ib_uverbs); dev[] = kernel dev_t (major<<20|minor) of uverbs nodes */
struct ngcfg { __u64 fops0, fops1; __u32 enabled, ndev; __u32 dev[NG_MAXDEV]; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct ngcfg)); } nicgate_cfg SEC(".maps");
/* counters: [2k] allowed / [2k+1] denied for k = 1 open, 2 ioctl, 3 ioctl_compat, 4 mmap, 5 write;
   [12] fork inherit, [13] exec unseal, [14] exit clear, [15] stale identity removed */
struct ngstat { __u64 v[16]; };
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct ngstat)); } nicgate_stats SEC(".maps");

static __always_inline void ngstat_inc(__u32 i)
{ __u32 z = 0; struct ngstat *st = bpf_map_lookup_elem(&nicgate_stats, &z); if (st && i < 16) st->v[i]++; }

static __always_inline int cur_sealed(void)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct sproc *sp = bpf_map_lookup_elem(&sealed_procs, &tgid);
    if (!sp) return 0;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    __u64 ticks = BPF_CORE_READ(t, group_leader, start_boottime) / CHAP_TICK_NS;
    if (sp->start_ticks != ticks) { bpf_map_delete_elem(&sealed_procs, &tgid); ngstat_inc(15); return 0; }   /* reused PID */
    return 1;
}

static __always_inline int ng_decide(__u32 kind)
{
    __u64 cg;
    if (!in_protected_cg(&cg)) return 0;            /* not a tenant task */
    if (cur_sealed()) { ngstat_inc(kind * 2); return 0; }
    ngstat_inc(kind * 2 + 1);
    report_and_kill(cg, 9100 + kind, 0);            /* SIGKILL the unsealed tenant process */
    return -1;                                      /* -EPERM: the uverbs handler is not reached */
}

static __always_inline int ng_is_uverbs_fop(struct file *file, struct ngcfg *c)
{
    __u64 fop = (__u64)BPF_CORE_READ(file, f_op);
    return fop && (fop == c->fops0 || fop == c->fops1);
}

static __always_inline struct ngcfg *ng_cfg(void)
{ __u32 z = 0; struct ngcfg *c = bpf_map_lookup_elem(&nicgate_cfg, &z); return (c && c->enabled) ? c : 0; }

/* open: f_op is still def_chr_fops here (chrdev_open installs the uverbs fops later) -> match the device number */
SEC("fmod_ret/security_file_open")
int BPF_PROG(ng_open, struct file *file, int ret)
{
    if (ret) return ret;
    struct ngcfg *c = ng_cfg(); if (!c) return 0;
    __u32 rdev = BPF_CORE_READ(file, f_inode, i_rdev);
    if (!rdev) return 0;
    __u32 n = c->ndev; if (n > NG_MAXDEV) n = NG_MAXDEV;
    int hit = 0;
#pragma unroll
    for (int i = 0; i < NG_MAXDEV; i++) { if (i < (int)n && c->dev[i] == rdev) hit = 1; }
    if (!hit) return 0;
    return ng_decide(1);
}
SEC("fmod_ret/security_file_ioctl")
int BPF_PROG(ng_ioctl, struct file *file, unsigned int cmd, unsigned long arg, int ret)
{
    if (ret) return ret;
    struct ngcfg *c = ng_cfg(); if (!c || !ng_is_uverbs_fop(file, c)) return 0;
    return ng_decide(2);
}
SEC("fmod_ret/security_file_ioctl_compat")
int BPF_PROG(ng_ioctl32, struct file *file, unsigned int cmd, unsigned long arg, int ret)
{
    if (ret) return ret;
    struct ngcfg *c = ng_cfg(); if (!c || !ng_is_uverbs_fop(file, c)) return 0;
    return ng_decide(3);
}
SEC("fmod_ret/security_mmap_file")
int BPF_PROG(ng_mmap, struct file *file, unsigned long prot, unsigned long flags, int ret)
{
    if (ret || !file) return ret;
    struct ngcfg *c = ng_cfg(); if (!c || !ng_is_uverbs_fop(file, c)) return 0;
    return ng_decide(4);
}
SEC("fmod_ret/security_file_permission")
int BPF_PROG(ng_write, struct file *file, int mask, int ret)
{
    if (ret || !(mask & 2 /* MAY_WRITE */)) return ret;
    struct ngcfg *c = ng_cfg(); if (!c || !ng_is_uverbs_fop(file, c)) return 0;
    return ng_decide(5);
}

/* a NEW process (not a thread) forked by a sealed process inherits the sealed agent regions -> inherits the status */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(ng_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 pt = BPF_CORE_READ(parent, tgid), ct = BPF_CORE_READ(child, tgid);
    if (pt == ct) return 0;                                   /* thread: same tgid, nothing to record */
    struct sproc *sp = bpf_map_lookup_elem(&sealed_procs, &pt);
    if (!sp) return 0;
    if (sp->start_ticks != BPF_CORE_READ(parent, group_leader, start_boottime) / CHAP_TICK_NS) return 0;
    struct sproc nw = {};
    nw.start_ticks = BPF_CORE_READ(child, start_boottime) / CHAP_TICK_NS;   /* the child is its own group leader */
    nw.origin = 2; nw.parent = pt; nw.reg_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&sealed_procs, &ct, &nw, BPF_ANY);
    ngstat_inc(12);
    return 0;
}
/* a successful exec starts a new program without the agent: the status is removed (a failed exec emits no event) */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(ng_exec, struct task_struct *p, int old_pid, void *bprm)
{
    __u32 t = BPF_CORE_READ(p, tgid);
    if (bpf_map_delete_elem(&sealed_procs, &t) == 0) ngstat_inc(13);
    return 0;
}
/* exit of the process (group leader) removes the status; the start-time identity covers any later PID reuse */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(ng_exit, struct task_struct *p)
{
    __u32 pid = BPF_CORE_READ(p, pid), t = BPF_CORE_READ(p, tgid);
    if (pid != t) return 0;
    if (bpf_map_delete_elem(&sealed_procs, &t) == 0) ngstat_inc(14);
    return 0;
}

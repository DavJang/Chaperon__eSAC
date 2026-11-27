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
        if (madv_discards((long)ctx->args[2]) && hits_protected(a0, a1)) report_and_kill(cgid, id, a0);
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
    if (madv_discards(behavior) && hits_protected(start, len)) report_and_kill(cgid, 9998 /*do_madvise marker*/, start);
    return 0;
}

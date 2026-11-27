// Chaperon Resource Agent pre-check -- bpftime IN-PROCESS override, kernel-backed RO maps.
// Stage 1 of the 2-stage model. Loaded by the bpftime agent INSIDE the real DPDK tenant.
//   resource_usage / resource_policy : ARRAY, BPF_F_MMAPABLE, kernel-backed (same object the
//     kernel Sentinel writes), RO in the tenant (KERNEL_MAP_RO + DROP_FD, no writable handle).
//   agent_slot (.rodata) : which usage/policy slot this tenant owns (Manager injects; default 0).
// Every program reads usage RO under the writer's seqcount and GRACEFULLY denies a call that would
// exceed the tenant's quota or rate BEFORE the API runs: pointer APIs return NULL, the others -EAGAIN.
// It never mutates usage: authoritative accounting stays with the kernel Sentinel.
// Request I: all APIs of Table tab:apis (Launch, Memory, Port, NIC control); layout in ../chap_res.h.
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ufunc.bpf.h"
#ifndef barrier
#define barrier() asm volatile("" ::: "memory")
#endif
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U<<10)
#endif
#include "../chap_res.h"

char LICENSE[] SEC("license") = "GPL";
#define EAGAIN_RET ((__u64)-11)

/* kernel-backed, shared with the kernel Sentinel, Agent-RO */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, RU_N);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct ru_slot));
         __uint(map_flags, BPF_F_MMAPABLE); } resource_usage SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, RU_N);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct rp_slot));
         __uint(map_flags, BPF_F_MMAPABLE); } resource_policy SEC(".maps");

/* Manager-injected tenant slot (parameterized, not magic). Default 0 for the single tenant. */
const volatile __u32 AGENT_SLOT = 0;

/* returns 1 => DENY (soft quota reached), 0 => allow. READ-ONLY. (Request E, unchanged) */
static __always_inline int deny_create(void)
{
    /* review fix #3-1/#7: a MANAGED tenant whose required policy/usage map is unreadable, or whose
       seqlock read never stabilizes, must FAIL-CLOSED (deny) -- never fall through to ALLOW. Only an
       EXPLICIT unlimited policy (hard_flows==0) allows. */
    __u32 k = AGENT_SLOT; if (k >= RU_N) return 1;                 /* bad slot -> fail-closed */
    struct rp_slot *pol = bpf_map_lookup_elem(&resource_policy, &k);
    if (!pol) return 1;                                            /* policy unreadable -> fail-closed */
    int rate_on = pol->rate_per_sec != 0;
    if (!pol->hard_flows && !rate_on) return 0;                    /* EXPLICIT unlimited (no quota,no rate) => allow */

    struct ru_slot *s = bpf_map_lookup_elem(&resource_usage, &k);
    if (!s) return 1;                                              /* usage unreadable -> fail-closed */
    /* Request E: multi-writer seqcount -- stable only if no writer active (high32==0) and generation unchanged */
    __u64 held = 0, ln = 0, seq1, seq2; int t = 0, stable = 0;
    do { seq1 = s->seq; barrier();
         held = s->flow_held; ln = s->last_ns; barrier();
         seq2 = s->seq;
         if ((seq1 >> 32) == 0 && seq1 == seq2) { stable = 1; break; } } while (++t < 64);
    if (!stable) return 1;                                         /* retry exhausted -> fail-closed */

    if (pol->hard_flows && held >= pol->hard_flows) return 1;      /* Quota pre-check */
    if (rate_on) {   /* same GCRA state the kernel Sentinel maintains (last_ns = TAT); RO, never written here */
        __u64 T = 1000000000ull / pol->rate_per_sec; if (!T) T = 1;
        __u64 burst = pol->burst ? pol->burst : pol->rate_per_sec;
        __u64 tau = (burst - 1) * T;
        __u64 now = bpf_ktime_get_ns();
        __u64 base = ln > now ? ln : now;
        if (base - now > tau) return 1;                            /* next call would be over-rate -> graceful pre-deny */
    }
    return 0;
}

/* ---------------- Request I: shared read-only checks ---------------- */
struct snap { __u64 mem, mbufs, tat, used; };

/* stable snapshot of the fields a check needs; 0 = unreadable/unstable (caller fails closed) */
static __always_inline int read_snap(struct ru_slot *s, __u32 api, struct snap *o)
{
    if (api >= N_RAPI) return 0;
    __u64 seq1, seq2; int t = 0;
    /* Request J: bpftime JIT-compiles this through LLVM, and a BPF load carries no volatile semantics, so the seq
       loads could be merged or hoisted out of the retry loop (a first read inside another CPU's writer section
       then fails every retry). An opaque helper call (vDSO clock, no syscall) before each seq read forces reloads. */
    do { (void)bpf_ktime_get_ns(); seq1 = s->seq; barrier();
         o->mem = s->mem_bytes; o->mbufs = s->mbufs; o->tat = s->api_tat[api]; o->used = s->api_used[api]; barrier();
         (void)bpf_ktime_get_ns(); seq2 = s->seq;
         if ((seq1 >> 32) == 0 && seq1 == seq2) return 1; } while (++t < 4096);
    return 0;
}
/* rate entry check: unlimited (0,0), budget (0,b), GCRA (r,b) -- the kernel Sentinel consumes the token */
static __always_inline int over_rate(const struct rate_pol *rp, __u64 tat, __u64 used)
{
    if (!rp->rate_per_sec && !rp->burst) return 0;
    if (!rp->rate_per_sec) return used >= rp->burst;
    __u64 T = 1000000000ull / rp->rate_per_sec; if (!T) T = 1;
    __u64 burst = rp->burst ? rp->burst : rp->rate_per_sec;
    __u64 tau = (burst - 1) * T, now = bpf_ktime_get_ns(), base = tat > now ? tat : now;
    return base - now > tau;
}
/* lookups; NULL => fail-closed deny */
static __always_inline struct rp_slot *pol_of(void) { __u32 k = AGENT_SLOT; if (k >= RU_N) return 0; return bpf_map_lookup_elem(&resource_policy, &k); }
static __always_inline struct ru_slot *use_of(void) { __u32 k = AGENT_SLOT; if (k >= RU_N) return 0; return bpf_map_lookup_elem(&resource_usage, &k); }

/* rate-only API (NIC control): 1 = deny */
static __always_inline int deny_rate(__u32 api)
{
    struct rp_slot *p = pol_of(); if (!p || api >= N_RAPI) return 1;
    struct rate_pol rp = p->api[api];
    if (!rp.rate_per_sec && !rp.burst) return 0;
    struct ru_slot *s = use_of(); struct snap n;
    if (!s || !read_snap(s, api, &n)) return 1;
    return over_rate(&rp, n.tat, n.used);
}
/* Request J: this thread is inside an outermost policy API call (published by the kernel Sentinel in the usage
   map): the memory call is an internal allocation of that call (pool creation, EAL init, PMD), which the
   memory-API rate does not cover. Agent-side only; the kernel accounting never trusts this. */
static __always_inline int nested_now(struct ru_slot *s)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid(); if (!tid) return 0;
#pragma unroll
    for (int i = 0; i < RU_NEST; i++) if ((__u32)s->nest_tid[i] == tid) return 1;
    return 0;
}
/* memory API: bytes requested (+ mbufs for pktmbuf pools) against the quota, then the memory-class rate */
static __always_inline int deny_mem(__u64 bytes, __u64 mbufs)
{
    struct rp_slot *p = pol_of(); if (!p) return 1;
    struct rate_pol rp = p->api[RAPI_MEM];
    if (!p->max_mem_bytes && !p->max_mbufs && !rp.rate_per_sec && !rp.burst) return 0;
    struct ru_slot *s = use_of(); struct snap n;
    if (!s || !read_snap(s, RAPI_MEM, &n)) return 1;
    if (p->max_mem_bytes && n.mem + bytes > p->max_mem_bytes) return 1;
    if (p->max_mbufs && mbufs && n.mbufs + mbufs > p->max_mbufs) return 1;
    if (nested_now(s)) return 0;                                   /* Request J: internal allocation, no rate */
    return over_rate(&rp, n.tat, n.used);
}
struct chap_flow_error { int type; __u64 cause; __u64 message; };   /* == rte_flow_error (24B) */
static __always_inline void flow_err(__u64 ep)
{ struct chap_flow_error e = { 1 /*RTE_FLOW_ERROR_TYPE_UNSPECIFIED*/, 0, 0 }; if (ep) bpf_probe_write_user((void *)ep, &e, sizeof(e)); }

/* ---------------- NIC control ---------------- */
/* rte_flow_create(port, attr, pattern, actions, error): pointer-returning. (Request E) */
SEC("uprobe/rte_flow_create")
int agent_flow_create(struct pt_regs *ctx)
{
    if (deny_create()) { flow_err(PT_REGS_PARM5(ctx)); bpf_override_return(ctx, 0); }
    return 0;
}
/* rte_flow_destroy(port, flow, error) */
SEC("uprobe/rte_flow_destroy")
int agent_flow_destroy(struct pt_regs *ctx)
{ if (deny_rate(RAPI_FLOW_DESTROY)) { flow_err(PT_REGS_PARM3(ctx)); bpf_override_return(ctx, EAGAIN_RET); } return 0; }
/* rte_flow_flush(port, error) */
SEC("uprobe/rte_flow_flush")
int agent_flow_flush(struct pt_regs *ctx)
{ if (deny_rate(RAPI_FLOW_FLUSH)) { flow_err(PT_REGS_PARM2(ctx)); bpf_override_return(ctx, EAGAIN_RET); } return 0; }
SEC("uprobe/rte_eth_dev_start")
int agent_dev_start(struct pt_regs *ctx) { if (deny_rate(RAPI_DEV_START)) bpf_override_return(ctx, EAGAIN_RET); return 0; }
SEC("uprobe/rte_eth_dev_stop")
int agent_dev_stop(struct pt_regs *ctx) { if (deny_rate(RAPI_DEV_STOP)) bpf_override_return(ctx, EAGAIN_RET); return 0; }
SEC("uprobe/rte_eth_promiscuous_enable")
int agent_promisc_en(struct pt_regs *ctx) { if (deny_rate(RAPI_PROMISC_EN)) bpf_override_return(ctx, EAGAIN_RET); return 0; }
SEC("uprobe/rte_eth_promiscuous_disable")
int agent_promisc_dis(struct pt_regs *ctx) { if (deny_rate(RAPI_PROMISC_DIS)) bpf_override_return(ctx, EAGAIN_RET); return 0; }
SEC("uprobe/rte_eth_dev_set_mc_addr_list")
int agent_mc_addr(struct pt_regs *ctx) { if (deny_rate(RAPI_MC_ADDR)) bpf_override_return(ctx, EAGAIN_RET); return 0; }

/* ---------------- Port: queues of the VF ---------------- */
/* rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, conf) */
SEC("uprobe/rte_eth_dev_configure")
int agent_dev_configure(struct pt_regs *ctx)
{
    struct rp_slot *p = pol_of();
    __u64 nrx = PT_REGS_PARM2(ctx) & 0xffff, ntx = PT_REGS_PARM3(ctx) & 0xffff;
    if (!p || (p->max_rxq && nrx > p->max_rxq) || (p->max_txq && ntx > p->max_txq)) bpf_override_return(ctx, EAGAIN_RET);
    return 0;
}
/* rte_eth_rx_queue_setup(port_id, rx_queue_id, ...) */
SEC("uprobe/rte_eth_rx_queue_setup")
int agent_rxq_setup(struct pt_regs *ctx)
{ struct rp_slot *p = pol_of(); __u64 q = PT_REGS_PARM2(ctx) & 0xffff;
  if (!p || (p->max_rxq && q >= p->max_rxq)) bpf_override_return(ctx, EAGAIN_RET); return 0; }
SEC("uprobe/rte_eth_tx_queue_setup")
int agent_txq_setup(struct pt_regs *ctx)
{ struct rp_slot *p = pol_of(); __u64 q = PT_REGS_PARM2(ctx) & 0xffff;
  if (!p || (p->max_txq && q >= p->max_txq)) bpf_override_return(ctx, EAGAIN_RET); return 0; }

/* ---------------- Memory: hugepages ---------------- */
/* rte_malloc and rte_zmalloc are 14-byte tail-call wrappers (not patchable by Frida replace_fast): the pre-check
   sits on rte_malloc_socket(type, size, align, socket), the common entry of rte_malloc, rte_zmalloc, rte_calloc
   and their _socket variants. */
SEC("uprobe/rte_malloc_socket")
int agent_malloc(struct pt_regs *ctx) { if (deny_mem(PT_REGS_PARM2(ctx), 0)) bpf_override_return(ctx, 0); return 0; }
/* rte_memzone_reserve is an 18-byte wrapper: pre-check on rte_memzone_reserve_thread_safe(name, len, socket,
   flags, align, bound), the common entry of rte_memzone_reserve / _aligned / _bounded. */
SEC("uprobe/rte_memzone_reserve_thread_safe")
int agent_memzone(struct pt_regs *ctx) { if (deny_mem(PT_REGS_PARM2(ctx), 0)) bpf_override_return(ctx, 0); return 0; }
SEC("uprobe/rte_mempool_create")    /* rte_mempool_create(name, n, elt_size, ...) */
int agent_mempool(struct pt_regs *ctx)
{ __u64 n = PT_REGS_PARM2(ctx) & 0xffffffff, e = PT_REGS_PARM3(ctx) & 0xffffffff;
  if (deny_mem(n * e, 0)) bpf_override_return(ctx, 0); return 0; }
SEC("uprobe/rte_pktmbuf_pool_create")   /* rte_pktmbuf_pool_create(name, n, cache, priv_size, data_room_size, socket) */
int agent_pktmbuf_pool(struct pt_regs *ctx)
{ __u64 n = PT_REGS_PARM2(ctx) & 0xffffffff, priv = PT_REGS_PARM4(ctx) & 0xffff, room = PT_REGS_PARM5(ctx) & 0xffff;
  if (deny_mem(n * (128 + priv + room), n)) bpf_override_return(ctx, 0); return 0; }   /* 128 = sizeof(struct rte_mbuf) */

/* ---------------- Launch: lcores, hugepages ---------------- */
/* rte_eal_init(argc, argv): the EAL arguments decide the lcores and the hugepage memory; parsed by the
   trusted native helper chap_eal_args (provider .so, sealed). Unparsable -> deny (fail-closed). */
SEC("uprobe/rte_eal_init")
int agent_eal_init(struct pt_regs *ctx)
{
    struct rp_slot *p = pol_of(); if (!p) { bpf_override_return(ctx, EAGAIN_RET); return 0; }
    if (!p->max_lcores && !p->max_hp_mb && !p->lcore_mask_lo && !p->lcore_mask_hi) return 0;
    volatile char fn[14]; fn[0]='c';fn[1]='h';fn[2]='a';fn[3]='p';fn[4]='_';fn[5]='e';fn[6]='a';fn[7]='l';fn[8]='_';fn[9]='a';fn[10]='r';fn[11]='g';fn[12]='s';fn[13]=0;
    long id = ufunc_find_func_id((const char *)fn);
    struct chap_eal_req r = {};
    if (id < 0) { bpf_override_return(ctx, EAGAIN_RET); return 0; }
    UFUNC_CALL_3(id, PT_REGS_PARM1(ctx), PT_REGS_PARM2(ctx), (__u64)(unsigned long)&r);
    int deny = r.err != 0;
    if (p->max_lcores && r.lcores > p->max_lcores) deny = 1;
    if (p->max_hp_mb && r.mem_mb > p->max_hp_mb) deny = 1;
    if ((p->lcore_mask_lo || p->lcore_mask_hi) && ((r.mask_lo & ~p->lcore_mask_lo) || (r.mask_hi & ~p->lcore_mask_hi))) deny = 1;
    if (deny) bpf_override_return(ctx, EAGAIN_RET);
    return 0;
}
/* rte_eal_remote_launch(f, arg, worker_id): only on an admitted lcore */
SEC("uprobe/rte_eal_remote_launch")
int agent_remote_launch(struct pt_regs *ctx)
{
    struct rp_slot *p = pol_of(); if (!p) { bpf_override_return(ctx, EAGAIN_RET); return 0; }
    __u64 w = PT_REGS_PARM3(ctx) & 0xffffffff;
    if (p->lcore_mask_lo || p->lcore_mask_hi) {
        int ok = w < 64 ? ((p->lcore_mask_lo >> w) & 1) : (w < 128 ? ((p->lcore_mask_hi >> (w - 64)) & 1) : 0);
        if (!ok) bpf_override_return(ctx, EAGAIN_RET);
    }
    return 0;
}

/* TEST-ONLY (harness RES_PASS=1): attached to rte_malloc_socket INSTEAD of agent_malloc. It keeps the hook and the
   sealed-dispatch boundary but performs no pre-check, so the kernel Sentinel's memory-rate hard limit is
   exercised alone. Never attached in a normal launch. */
SEC("uprobe/rte_malloc_socket")
int agent_mem_pass(struct pt_regs *ctx) { (void)ctx; return 0; }

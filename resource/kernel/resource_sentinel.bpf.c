// Chaperon Resource kernel-Sentinel (real PMD-internal uprobe path) -- ENTRY-RESERVATION model.
//  entry uprobe @ mlx5_flow_create:
//     api_calls++ (RATE)                                  -- every executed API call
//     token-bucket RATE check (if rate_per_sec>0)         -- over-rate => denied++, SIGKILL
//     RESERVE flow_held++ + entry-time quota RE-CHECK      -- over-quota => denied++, SIGKILL
//     The entry SIGKILL is queued in-kernel and delivered on return-to-user, i.e. BEFORE the
//     userspace mlx5_flow_create body runs -> the firmware flow-insert of the crossing call does
//     NOT execute (true pre-firmware block at the kernel, unlike a uretprobe check).
//  uret @ mlx5_flow_create : on FAILURE (NULL) release the reservation (flow_held--); success commits.
//  uret @ mlx5_flow_destroy: on success (ret==0) release a holding (flow_held--).
// Agent override lives on rte_flow_create (ethdev, different addr) => no hook conflict.
// Maps: resource_usage(FROZEN,kernel-write,Agent-RO), resource_policy(Manager-RW,RO), cg_slot, last_cg.
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U<<10)
#endif
#ifndef barrier
#define barrier() asm volatile("" ::: "memory")
#endif

char LICENSE[] SEC("license") = "GPL";
#define TOK_UNIT 1000   /* milli-tokens per whole token */

#include "../chap_res.h"   /* Request I: shared policy/usage layout (Request E fields first, unchanged) */

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, RU_N);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct ru_slot));
         __uint(map_flags, BPF_F_MMAPABLE); } resource_usage SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, RU_N);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct rp_slot));
         __uint(map_flags, BPF_F_MMAPABLE); } resource_policy SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, RU_N);
         __uint(key_size, sizeof(__u64)); __uint(value_size, sizeof(__u32)); } cg_slot SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(__u64)); } last_cg SEC(".maps");

static __always_inline __u32 slot_of_current(void)
{
    __u64 cg = bpf_get_current_cgroup_id();
    __u32 *sp = bpf_map_lookup_elem(&cg_slot, &cg);
    if (!sp) { __u32 z=0; bpf_map_update_elem(&last_cg, &z, &cg, BPF_ANY); return 0xffffffffu; }
    return *sp;
}

/* Request E item-3 -------- multi-writer-safe primitives (6.8 verifier: BPF atomics on map values) -------- */
#define CAS_TRIES 32
static __always_inline void w_begin(struct ru_slot *s) { __sync_fetch_and_add((__u32 *)&s->seq + 1, 1); }
static __always_inline void w_end(struct ru_slot *s)
{ __sync_fetch_and_add((__u32 *)&s->seq, 1); __sync_fetch_and_add((__u32 *)&s->seq + 1, (__u32)-1); }
static __always_inline void cas_exhausted(struct ru_slot *s) { __sync_fetch_and_add((__u64 *)&s->tokens_milli, 1); }

/* GCRA (single 64-bit state in last_ns = theoretical arrival time): equivalent to a token bucket with
   capacity `burst` refilled at `rate_per_sec`. One CMPXCHG per admitted call -> no lost update. */
static __always_inline int rate_take(struct ru_slot *s, struct rp_slot *pol)
{
    __u64 rate = pol->rate_per_sec;
    if (!rate) return 1;                              /* rate limiting disabled */
    __u64 burst = pol->burst ? pol->burst : rate;
    __u64 T = 1000000000ull / rate; if (!T) T = 1;
    __u64 tau = (burst - 1) * T;
    __u64 now = bpf_ktime_get_ns();
    for (int i = 0; i < CAS_TRIES; i++) {
        __u64 tat = s->last_ns;
        __u64 base = tat > now ? tat : now;
        if (base - now > tau) return 0;               /* bucket empty: over-rate */
        if (__sync_val_compare_and_swap(&s->last_ns, tat, base + T) == tat) return 1;
    }
    cas_exhausted(s); return 0;
}
/* reserve one holding only if it keeps flow_held <= hard_flows (hard==0: unlimited) */
static __always_inline int reserve(struct ru_slot *s, __u64 hard)
{
    if (!hard) { __sync_fetch_and_add(&s->flow_held, 1); return 1; }
    for (int i = 0; i < CAS_TRIES; i++) {
        __u64 h = s->flow_held;
        if (h >= hard) return 0;
        if (__sync_val_compare_and_swap(&s->flow_held, h, h + 1) == h) return 1;
    }
    cas_exhausted(s); return 0;
}
static __always_inline void release(struct ru_slot *s)
{
    for (int i = 0; i < CAS_TRIES; i++) {
        __u64 h = s->flow_held;
        if (!h) return;
        if (__sync_val_compare_and_swap(&s->flow_held, h, h - 1) == h) return;
    }
    cas_exhausted(s);
}

/* ENTRY: rate accounting + token-bucket rate + reservation + entry-time quota re-check. */
static __always_inline void create_entry(void)
{
    __u32 k = slot_of_current(); if (k >= RU_N) return;
    struct ru_slot *s = bpf_map_lookup_elem(&resource_usage, &k); if (!s) return;
    struct rp_slot *pol = bpf_map_lookup_elem(&resource_policy, &k);

    w_begin(s);
    __sync_fetch_and_add(&s->api_calls, 1);           /* RATE: executed API calls */
    int over_rate = 0, over_quota = 0;
    if (pol) {
        if (!rate_take(s, pol)) over_rate = 1;        /* GCRA token-bucket RATE */
        else if (!reserve(s, pol->hard_flows)) over_quota = 1;   /* atomic RESERVE <= hard_flows */
    } else {
        __sync_fetch_and_add(&s->flow_held, 1);
    }
    if (over_rate || over_quota) __sync_fetch_and_add(&s->denied, 1);
    w_end(s);
    /* SIGKILL AFTER the seqcount close so the Agent-RO reader always sees a consistent slot. */
    if (over_rate || over_quota) bpf_send_signal(9);
}

/* uret create: FAILURE releases the entry reservation; success leaves it committed. */
static __always_inline void create_ret(int ok)
{
    __u32 k = slot_of_current(); if (k >= RU_N) return;
    struct ru_slot *s = bpf_map_lookup_elem(&resource_usage, &k); if (!s) return;
    /* the uretprobe fires only if mlx5_flow_create RETURNED => its firmware flow-insert completed.
       A crossing call SIGKILLed at ENTRY never reaches here, so completed < api_calls proves the
       crossing call firmware did NOT complete (PMD-internal instrumentation, stronger than testpmd output). */
    w_begin(s);
    __sync_fetch_and_add(&s->completed, 1);
    if (!ok) release(s);                            /* real create FAILURE: release the entry reservation */
    w_end(s);
}

static __always_inline void destroy_success(void)   /* HOLDINGS down (success only) */
{
    __u32 k = slot_of_current(); if (k >= RU_N) return;
    struct ru_slot *s = bpf_map_lookup_elem(&resource_usage, &k); if (!s) return;
    w_begin(s); release(s); w_end(s);
}

SEC("uprobe/mlx5_flow_create")
int BPF_UPROBE(rs_flow_create_entry) { create_entry(); return 0; }

SEC("uretprobe/mlx5_flow_create")
int BPF_URETPROBE(rs_flow_create_ret, void *ret) { create_ret(ret != 0); return 0; }

SEC("uretprobe/mlx5_flow_destroy")
int BPF_URETPROBE(rs_flow_destroy_ret, long ret) { if (ret == 0) destroy_success(); return 0; }

/* ======================= Request I: the remaining APIs of Table tab:apis =======================
 * Accounting points are internal functions that the Agent does NOT hook (a kernel uprobe and a bpftime
 * patch on the same entry would break each other). Every update is atomic under the writer seqcount.
 *  Memory : malloc_heap_alloc (entry: reserve size, ret: commit/release; also the memory-class token)
 *           rte_free / rte_memzone_free (release by pointer); rte_pktmbuf_pool_create_by_ops (mbufs) / rte_mempool_free
 *  Port   : eth_dev_{rx,tx}_queue_config (queues configured), mlx5_{rx,tx}_queue_setup (queue index)
 *  NIC    : mlx5_flow_destroy / mlx5_flow_flush / mlx5_dev_start / mlx5_dev_stop /
 *           mlx5_promiscuous_{enable,disable} / mlx5_set_mc_addr_list (per-API GCRA or budget token);
 *           mlx5_flow_flush success releases every held flow rule.
 * Over a quota or a NIC-control rate => SIGKILL (hard limit). The memory-class rate is consumed here per
 * heap allocation (the Agent pre-checks it per API call) but never kills: DPDK-internal allocations of a
 * legitimate tenant also pass malloc_heap_alloc. */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __uint(key_size, sizeof(__u64)); __uint(value_size, sizeof(__u64)); } rs_pend SEC(".maps");      /* tid -> pending size / n */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 262144);
         __uint(key_size, sizeof(__u64)); __uint(value_size, sizeof(__u64)); } rs_mem_ptr SEC(".maps");   /* (slot,ptr) -> bytes */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __uint(key_size, sizeof(__u64)); __uint(value_size, sizeof(__u64)); } rs_pool_n SEC(".maps");    /* (slot,mp) -> mbufs */
/* pool creation nests heap allocations on the same thread: its pending entry needs its own map */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __uint(key_size, sizeof(__u64)); __uint(value_size, sizeof(__u64)); } rs_pend_pool SEC(".maps");  /* tid -> pending mbufs */

static __always_inline __u64 pkey(__u32 slot, __u64 p) { return p ^ ((__u64)slot << 56); }
static __always_inline int add_le(__u64 *c, __u64 v, __u64 lim, struct ru_slot *s)
{
    if (!lim) { __sync_fetch_and_add(c, v); return 1; }
    for (int i = 0; i < CAS_TRIES; i++) { __u64 h = *c; if (h + v > lim) return 0;
        if (__sync_val_compare_and_swap(c, h, h + v) == h) return 1; }
    cas_exhausted(s); return 0;
}
static __always_inline void sub_sat(__u64 *c, __u64 v, struct ru_slot *s)
{
    for (int i = 0; i < CAS_TRIES; i++) { __u64 h = *c, n = h > v ? h - v : 0;
        if (__sync_val_compare_and_swap(c, h, n) == h) return; }
    cas_exhausted(s);
}
/* per-API token: budget (rate 0, burst b) or GCRA; counts every executed call; 0 = over */
static __always_inline int api_take(struct ru_slot *s, struct rp_slot *pol, __u32 api)
{
    if (api >= N_RAPI) return 1;
    __u64 used = __sync_fetch_and_add(&s->api_used[api], 1) + 1;      /* this call's ordinal, atomically */
    if (!pol) return 1;
    __u64 rate = pol->api[api].rate_per_sec, burst = pol->api[api].burst;
    if (!rate && !burst) return 1;
    if (!rate) return used <= burst;                                   /* budget of `burst` calls in total */
    if (!burst) burst = rate;
    __u64 T = 1000000000ull / rate; if (!T) T = 1;
    __u64 tau = (burst - 1) * T, now = bpf_ktime_get_ns();
    for (int i = 0; i < CAS_TRIES; i++) {
        __u64 tat = s->api_tat[api], base = tat > now ? tat : now;
        if (base - now > tau) return 0;
        if (__sync_val_compare_and_swap(&s->api_tat[api], tat, base + T) == tat) return 1;
    }
    cas_exhausted(s); return 0;
}
static __always_inline int ctx_of(__u32 *k, struct ru_slot **s, struct rp_slot **p)
{
    *k = slot_of_current(); if (*k >= RU_N) return 0;
    *s = bpf_map_lookup_elem(&resource_usage, k); if (!*s) return 0;
    *p = bpf_map_lookup_elem(&resource_policy, k); return 1;
}
/* rte_eth_dev_start replays the promiscuous state through the driver op (ethdev eth_dev_config_restore, after
   the driver start). That replay belongs to the admitted dev_start call: one credit per successful dev_start
   token, valid only for the next NIC-control event of the slot (cleared by any other one). */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, RU_N);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(__u64)); } rs_replay SEC(".maps");
static __always_inline void replay_clear(__u32 k) { __u64 *c = bpf_map_lookup_elem(&rs_replay, &k); if (c) __sync_lock_test_and_set(c, 0); }
/* NIC control: token + hard limit; returns 1 when the call is within policy */
static __always_inline int nic_entry(__u32 api)
{
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    if (api == RAPI_PROMISC_EN) { __u64 *c = bpf_map_lookup_elem(&rs_replay, &k);
        if (c && __sync_lock_test_and_set(c, 0) == 1) return 1; }      /* dev_start replay: charged to dev_start */
    else replay_clear(k);
    w_begin(s); int ok = api_take(s, p, api); if (!ok) __sync_fetch_and_add(&s->denied2, 1); w_end(s);
    if (!ok) { bpf_send_signal(9); return 0; }
    if (api == RAPI_DEV_START) { __u64 *c = bpf_map_lookup_elem(&rs_replay, &k); if (c) __sync_lock_test_and_set(c, 1); }
    return 1;
}
SEC("uprobe/mlx5_flow_destroy")      int BPF_UPROBE(rs_flow_destroy_entry) { nic_entry(RAPI_FLOW_DESTROY); return 0; }
SEC("uprobe/mlx5_flow_flush")        int BPF_UPROBE(rs_flow_flush_entry)   { nic_entry(RAPI_FLOW_FLUSH); return 0; }
SEC("uretprobe/mlx5_flow_flush")
int BPF_URETPROBE(rs_flow_flush_ret, long ret)
{   /* flush removed every flow rule of the port: holdings back to 0 */
    if (ret != 0) return 0;
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    w_begin(s); __sync_lock_test_and_set(&s->flow_held, 0); w_end(s); return 0;
}
SEC("uprobe/mlx5_dev_start")         int BPF_UPROBE(rs_dev_start)   { nic_entry(RAPI_DEV_START); return 0; }
SEC("uprobe/mlx5_dev_stop")          int BPF_UPROBE(rs_dev_stop)    { nic_entry(RAPI_DEV_STOP); return 0; }
SEC("uprobe/mlx5_promiscuous_enable")  int BPF_UPROBE(rs_promisc_en)  { nic_entry(RAPI_PROMISC_EN); return 0; }
SEC("uprobe/mlx5_promiscuous_disable") int BPF_UPROBE(rs_promisc_dis) { nic_entry(RAPI_PROMISC_DIS); return 0; }
SEC("uprobe/mlx5_set_mc_addr_list")  int BPF_UPROBE(rs_mc_addr)     { nic_entry(RAPI_MC_ADDR); return 0; }

/* Port: queues */
static __always_inline void q_config(__u64 nb, int tx)
{
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return;
    __u64 lim = p ? (tx ? p->max_txq : p->max_rxq) : 0; int over = lim && nb > lim;
    w_begin(s); __sync_lock_test_and_set(tx ? &s->txq_cfg : &s->rxq_cfg, over ? 0 : nb); if (over) __sync_fetch_and_add(&s->denied2, 1); w_end(s);
    if (over) bpf_send_signal(9);
}
static __always_inline void q_setup(__u64 idx, int tx)
{
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return;
    __u64 lim = p ? (tx ? p->max_txq : p->max_rxq) : 0; int over = lim && idx >= lim;
    w_begin(s);
    if (over) __sync_fetch_and_add(&s->denied2, 1);
    else { __u64 *u = tx ? &s->txq_used : &s->rxq_used;
           for (int i = 0; i < CAS_TRIES; i++) { __u64 h = *u; if (h >= idx + 1) break; if (__sync_val_compare_and_swap(u, h, idx + 1) == h) break; } }
    w_end(s);
    if (over) bpf_send_signal(9);
}
SEC("uprobe/eth_dev_rx_queue_config") int BPF_UPROBE(rs_rxq_config, void *dev, unsigned short nb) { q_config(nb, 0); return 0; }
SEC("uprobe/eth_dev_tx_queue_config") int BPF_UPROBE(rs_txq_config, void *dev, unsigned short nb) { q_config(nb, 1); return 0; }
SEC("uprobe/mlx5_rx_queue_setup") int BPF_UPROBE(rs_rxq_setup, void *dev, unsigned short idx) { q_setup(idx, 0); return 0; }
SEC("uprobe/mlx5_tx_queue_setup") int BPF_UPROBE(rs_txq_setup, void *dev, unsigned short idx) { q_setup(idx, 1); return 0; }

/* Memory: hugepage heap bytes (quota, hard) + memory-class token (soft, see above) */
SEC("uprobe/malloc_heap_alloc")
int BPF_UPROBE(rs_heap_alloc, const char *type, unsigned long size)
{
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    w_begin(s);
    int ok = add_le(&s->mem_bytes, size, p ? p->max_mem_bytes : 0, s);   /* quota only; the rate is taken at the gate (Request J) */
    if (!ok) __sync_fetch_and_add(&s->denied2, 1);
    w_end(s);
    if (!ok) { bpf_send_signal(9); return 0; }
    __u64 tid = bpf_get_current_pid_tgid(); __u64 v = size; bpf_map_update_elem(&rs_pend, &tid, &v, BPF_ANY);
    return 0;
}
SEC("uretprobe/malloc_heap_alloc")
int BPF_URETPROBE(rs_heap_alloc_ret, void *ret)
{
    __u64 tid = bpf_get_current_pid_tgid(); __u64 *v = bpf_map_lookup_elem(&rs_pend, &tid); if (!v) return 0;
    __u64 size = *v; bpf_map_delete_elem(&rs_pend, &tid);
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    if (!ret) { w_begin(s); sub_sat(&s->mem_bytes, size, s); w_end(s); return 0; }   /* failed: release the reservation */
    __u64 key = pkey(k, (__u64)ret); bpf_map_update_elem(&rs_mem_ptr, &key, &size, BPF_ANY);
    return 0;
}
SEC("uprobe/rte_free")
int BPF_UPROBE(rs_free, void *ptr)
{
    if (!ptr) return 0;
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    __u64 key = pkey(k, (__u64)ptr); __u64 *v = bpf_map_lookup_elem(&rs_mem_ptr, &key); if (!v) return 0;
    __u64 size = *v; bpf_map_delete_elem(&rs_mem_ptr, &key);
    w_begin(s); sub_sat(&s->mem_bytes, size, s); w_end(s);
    return 0;
}
/* memzones (memzone_reserve, mempool memory) are released by rte_memzone_free, which frees the heap element
   directly (not through rte_free). DPDK 22.11 struct rte_memzone (packed): name[32], iova, addr @40 */
SEC("uprobe/rte_memzone_free")
int BPF_UPROBE(rs_mz_free, void *mz)
{
    if (!mz) return 0;
    __u64 addr = 0; if (bpf_probe_read_user(&addr, sizeof(addr), (char *)mz + 40) || !addr) return 0;
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    __u64 key = pkey(k, addr); __u64 *v = bpf_map_lookup_elem(&rs_mem_ptr, &key); if (!v) return 0;
    __u64 size = *v; bpf_map_delete_elem(&rs_mem_ptr, &key);
    w_begin(s); sub_sat(&s->mem_bytes, size, s); w_end(s);
    return 0;
}
/* Memory: mbufs of pktmbuf pools (quota, hard) */
SEC("uprobe/rte_pktmbuf_pool_create_by_ops")
int BPF_UPROBE(rs_pool_create, const char *name, unsigned int n)
{
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    w_begin(s); int ok = add_le(&s->mbufs, n, p ? p->max_mbufs : 0, s); if (!ok) __sync_fetch_and_add(&s->denied2, 1); w_end(s);
    if (!ok) { bpf_send_signal(9); return 0; }
    __u64 tid = bpf_get_current_pid_tgid(); __u64 v = n; bpf_map_update_elem(&rs_pend_pool, &tid, &v, BPF_ANY);
    return 0;
}
SEC("uretprobe/rte_pktmbuf_pool_create_by_ops")
int BPF_URETPROBE(rs_pool_create_ret, void *mp)
{
    __u64 tid = bpf_get_current_pid_tgid(); __u64 *v = bpf_map_lookup_elem(&rs_pend_pool, &tid); if (!v) return 0;
    __u64 n = *v; bpf_map_delete_elem(&rs_pend_pool, &tid);
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    if (!mp) { w_begin(s); sub_sat(&s->mbufs, n, s); w_end(s); return 0; }
    __u64 key = pkey(k, (__u64)mp); bpf_map_update_elem(&rs_pool_n, &key, &n, BPF_ANY);
    return 0;
}
SEC("uprobe/rte_mempool_free")
int BPF_UPROBE(rs_pool_free, void *mp)
{
    if (!mp) return 0;
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    __u64 key = pkey(k, (__u64)mp); __u64 *v = bpf_map_lookup_elem(&rs_pool_n, &key); if (!v) return 0;
    __u64 n = *v; bpf_map_delete_elem(&rs_pool_n, &key);
    w_begin(s); sub_sat(&s->mbufs, n, s); w_end(s);
    return 0;
}


/* ===================== Request J: memory-API rate hard limit at the sealed-dispatch boundary =====================
 * chap_res_gate_enter / chap_res_gate_exit (agent.so, never patched by Frida) bracket every resource API call that
 * the Resource Agent admitted; slot, class and API id come from the sealed RO slot table. Per-thread nesting state
 * is kernel-only (rs_gate). An OUTERMOST call of the Memory class takes one GCRA token with an atomic CAS on
 * api_tat[RAPI_MEM]; over the rate -> SIGKILL at the enter probe, before the original function runs (no
 * allocation). A memory call nested in an open outer policy call (pool-creation internals, EAL initialization,
 * PMD allocations inside ethdev/flow APIs) takes no token, except that an outer call of another class pays one
 * memory token at its first nested memory call (each request that allocates pays exactly once; a forged or
 * hijacked outer call therefore buys at most its budget per token). A call counts as nested only while its thread has an
 * open outer call, on a deeper stack frame, and within the outer API's nesting budget (about its legitimate
 * nested-call count; rte_eal_init only on its first call). A skipped exit (longjmp out of an API) therefore
 * exempts no more than one normal call of the same API, after which calls are counted again (gate_stale).
 * Thread exit clears the state. */
#define GATE_CLASS(rc) ((__u32)(rc) & 0xffu)
#define GATE_API(rc)   (((__u32)(rc) >> 8) & 0xffu)
struct gate_st { __u64 outer_sp; __u32 depth, exempt_left, api, nested_n, charged, pad; };   /* charged: outer request paid its memory token */
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 8192);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(struct gate_st)); } rs_gate SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, RU_N);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(__u64)); } rs_eal_once SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 32);
         __uint(key_size, sizeof(__u32)); __uint(value_size, sizeof(__u64)); } rs_nest_max SEC(".maps");   /* observed nested calls per outer API */

/* nesting budget of one outer call, by API id (agent.cpp chap_res_api) */
static __always_inline __u32 exempt_cap(__u32 api, __u32 k)
{
    if (api == 6) {                                   /* rte_eal_init: the first call of the tenant only */
        __u64 *seen = bpf_map_lookup_elem(&rs_eal_once, &k); if (!seen) return 0;
        return __sync_val_compare_and_swap(seen, 0, 1) == 0 ? 1024u : 0u;
    }
    if (api == 3 || api == 4) return 64;              /* rte_mempool_create, rte_pktmbuf_pool_create */
    if (api >= 8 && api <= 10) return 32;             /* rte_eth_dev_configure, rte_eth_{rx,tx}_queue_setup */
    if (api == 14) return 256;                        /* rte_eth_dev_start */
    if (api >= 11 && api <= 18) return 64;            /* other NIC control */
    return 0;                                         /* rte_malloc_socket, memzone reserve, remote launch, test pass-through */
}
static __always_inline void nest_publish(struct ru_slot *s, __u64 tid)
{
#pragma unroll
    for (int i = 0; i < RU_NEST; i++) if (s->nest_tid[i] == tid) return;
#pragma unroll
    for (int i = 0; i < RU_NEST; i++) if (__sync_val_compare_and_swap(&s->nest_tid[i], 0, tid) == 0) return;
}
static __always_inline void nest_clear(struct ru_slot *s, __u64 tid)
{
#pragma unroll
    for (int i = 0; i < RU_NEST; i++) if (s->nest_tid[i] == tid) __sync_val_compare_and_swap(&s->nest_tid[i], tid, 0);
}
SEC("uprobe/chap_res_gate_enter")
int BPF_UPROBE(rs_gate_enter, __u64 slot, __u64 rc, __u64 func)
{
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (!ctx_of(&k, &s, &p)) return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid(); __u64 sp = PT_REGS_SP(ctx);
    __u32 cls = GATE_CLASS(rc), api = GATE_API(rc);
    struct gate_st *g = bpf_map_lookup_elem(&rs_gate, &tid);
    if (!g) { struct gate_st z = {}; bpf_map_update_elem(&rs_gate, &tid, &z, BPF_NOEXIST); g = bpf_map_lookup_elem(&rs_gate, &tid); }
    if (g && g->depth > 0 && sp < g->outer_sp && g->exempt_left > 0) {      /* nested in the open outer call */
        if (cls == RC_MEM && !g->charged) {
            /* first memory call inside an outer request of another class: that request's one memory token (lazy).
             * Without it an outer call that is not rate-limited as memory (a forged boundary call from tenant code,
             * or tenant callbacks / signal handlers running inside a real ethdev call) would exempt memory calls
             * for free. Over the rate -> SIGKILL before the original runs. */
            int ok2;
            w_begin(s);
            ok2 = api_take(s, p, RAPI_MEM);
            if (ok2) { __sync_fetch_and_add(&s->mem_calls, 1); nest_publish(s, tid); } else __sync_fetch_and_add(&s->denied2, 1);
            w_end(s);
            if (!ok2) { bpf_send_signal(9); return 0; }
            g->charged = 1; g->exempt_left--; g->depth++; g->nested_n++;
            return 0;
        }
        g->exempt_left--; g->depth++; g->nested_n++;
        if (cls == RC_MEM) { w_begin(s); __sync_fetch_and_add(&s->mem_nested, 1); w_end(s); }
        return 0;
    }
    int ok = 1;                                                              /* outermost policy API call */
    w_begin(s);
    if (g && g->depth > 0) __sync_fetch_and_add(&s->gate_stale, 1);
    if (cls == RC_MEM) { ok = api_take(s, p, RAPI_MEM); if (ok) __sync_fetch_and_add(&s->mem_calls, 1); else __sync_fetch_and_add(&s->denied2, 1); }
    if (ok && cls == RC_MEM) nest_publish(s, tid);                          /* published only once charged */
    w_end(s);
    if (!ok) { bpf_send_signal(9); return 0; }                              /* before the original function */
    if (g) { g->depth = 1; g->outer_sp = sp; g->exempt_left = exempt_cap(api, k); g->api = api; g->nested_n = 0; g->charged = (cls == RC_MEM); }
    return 0;
}
SEC("uprobe/chap_res_gate_exit")
int BPF_UPROBE(rs_gate_exit, __u64 slot, __u64 rc, __u64 ret)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct gate_st *g = bpf_map_lookup_elem(&rs_gate, &tid); if (!g || g->depth == 0) return 0;
    g->depth--;
    if (g->depth == 0) {
        __u32 a = g->api & 31u; __u64 *mx = bpf_map_lookup_elem(&rs_nest_max, &a);
        if (mx && (__u64)g->nested_n > *mx) *mx = g->nested_n;
        g->outer_sp = 0; g->exempt_left = 0; g->charged = 0;
        __u32 k; struct ru_slot *s; struct rp_slot *p; if (ctx_of(&k, &s, &p)) { w_begin(s); nest_clear(s, tid); w_end(s); }
    }
    return 0;
}
SEC("tracepoint/sched/sched_process_exit")
int rs_gate_thread_exit(void *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&rs_gate, &tid)) return 0;
    bpf_map_delete_elem(&rs_gate, &tid);
    __u32 k; struct ru_slot *s; struct rp_slot *p; if (ctx_of(&k, &s, &p)) { w_begin(s); nest_clear(s, tid); w_end(s); }
    return 0;
}

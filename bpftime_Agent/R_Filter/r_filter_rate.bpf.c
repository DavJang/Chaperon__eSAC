// eSAC control-plane + resource R_Filter rate-limiter. Throttles a tenant's shared NIC
// control-plane API churn (rate) and caps shared host-memory allocation (quota)
// via in-process uprobe override. 3 programs (attached to many symbols by the
// loader): cp_rate_ptr (rate, deny->NULL), cp_rate_int (rate, deny->-EAGAIN),
// mem_quota_ptr (count quota, deny->NULL).
#include "common_cgroup.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const volatile __u64 RATE_PER_SEC = 5;   /* control-plane ops/sec per tenant */
const volatile __u64 BURST        = 5;
const volatile __u64 MEM_QUOTA    = 8;   /* max shared-mem allocations per tenant */

struct rl { __u64 last_ns; __s64 tok_milli; __u64 allowed; __u64 denied; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u32); __type(value, struct rl); } cp_state SEC(".maps");
struct mq { __u64 count; __u64 denied; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
         __type(key, __u32); __type(value, struct mq); } mem_state SEC(".maps");

/* returns 1 if OVER-rate (caller overrides), 0 if allowed */
static __always_inline int over_rate(void)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 now = bpf_ktime_get_ns();
    __u64 cap = BURST * 1000;
    struct rl *s = bpf_map_lookup_elem(&cp_state, &pid);
    if (!s) {
        struct rl i = {}; i.last_ns = now; i.tok_milli = (__s64)cap - 1000; i.allowed = 1;
        bpf_map_update_elem(&cp_state, &pid, &i, BPF_ANY);
        bpf_printk("R_FILTER ALLOW pid=%u first", pid);
        return 0;
    }
    __u64 dt = now - s->last_ns; s->last_ns = now;
    s->tok_milli += (__s64)((dt * RATE_PER_SEC) / 1000000ULL);
    if (s->tok_milli > (__s64)cap) s->tok_milli = (__s64)cap;
    if (s->tok_milli >= 1000) { s->tok_milli -= 1000; s->allowed++;
        bpf_printk("R_FILTER ALLOW pid=%u allowed=%llu", pid, s->allowed); return 0; }
    s->denied++;
    bpf_printk("R_FILTER DENY(rate) pid=%u denied=%llu", pid, s->denied);
    return 1;
}

SEC("uprobe/cp_rate_ptr")
int BPF_UPROBE(cp_rate_ptr) { if (over_rate()) bpf_override_return(ctx, 0); return 0; }

SEC("uprobe/cp_rate_int")
int BPF_UPROBE(cp_rate_int) { if (over_rate()) bpf_override_return(ctx, (__u64)(-11)); return 0; } /* -EAGAIN */

SEC("uprobe/mem_quota_ptr")
int BPF_UPROBE(mem_quota_ptr)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct mq *m = bpf_map_lookup_elem(&mem_state, &pid);
    if (!m) { struct mq i = {}; i.count = 1; bpf_map_update_elem(&mem_state, &pid, &i, BPF_ANY);
              bpf_printk("MEMGOV ALLOW pid=%u count=1", pid); return 0; }
    if (m->count >= MEM_QUOTA) { m->denied++;
        bpf_printk("MEMGOV DENY(quota) pid=%u over=%llu", pid, MEM_QUOTA);
        bpf_override_return(ctx, 0); return 0; }
    m->count++;
    bpf_printk("MEMGOV ALLOW pid=%u count=%llu", pid, m->count);
    return 0;
}

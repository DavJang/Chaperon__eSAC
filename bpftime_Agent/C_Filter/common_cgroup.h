/* SPDX-License-Identifier: GPL-2.0
 * common.h — GUARD comm access-control shared types & constants.
 * Included by both the BPF side and the user-space loader; __bpf__ guard
 * supports both compile environments.
 */
#ifndef _GUARD_COMMON_H
#define _GUARD_COMMON_H

#ifndef __bpf__
/* User space: integer types from kernel headers. */
#include <linux/types.h>
#else
/* BPF target: define types directly, no external headers. */

/* Unsigned ints (must match kernel defs; __u64 must be ull). */
typedef unsigned char        __u8;
typedef unsigned short       __u16;
typedef unsigned int         __u32;
typedef unsigned long long   __u64;

/* Signed ints (needed by __s32/__s64 etc. in bpf_helper_defs.h). */
typedef signed char          __s8;
typedef signed short         __s16;
typedef signed int           __s32;
typedef signed long long     __s64;

/* Big/little-endian hint types (required by bpf_helper_defs.h). */
typedef __u16                __be16;
typedef __u32                __be32;
typedef __u64                __be64;
typedef __u16                __le16;
typedef __u32                __le32;
typedef __u64                __le64;
typedef __u32                __wsum;   /* checksum type */

/* BPF map types (replaces enum bpf_map_type from linux/bpf.h). */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC                = 0,
    BPF_MAP_TYPE_HASH                  = 1,
    BPF_MAP_TYPE_ARRAY                 = 2,
    BPF_MAP_TYPE_PROG_ARRAY            = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
    BPF_MAP_TYPE_PERCPU_HASH           = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
    BPF_MAP_TYPE_STACK_TRACE           = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
    BPF_MAP_TYPE_LRU_HASH              = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
    BPF_MAP_TYPE_LPM_TRIE              = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
    BPF_MAP_TYPE_DEVMAP                = 14,
    BPF_MAP_TYPE_SOCKMAP               = 15,
    BPF_MAP_TYPE_CPUMAP                = 16,
    BPF_MAP_TYPE_XSKMAP                = 17,
    BPF_MAP_TYPE_SOCKHASH              = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE                 = 22,
    BPF_MAP_TYPE_STACK                 = 23,
    BPF_MAP_TYPE_SK_STORAGE            = 24,
    BPF_MAP_TYPE_DEVMAP_HASH           = 25,
    BPF_MAP_TYPE_STRUCT_OPS            = 26,
    BPF_MAP_TYPE_RINGBUF               = 27,
    BPF_MAP_TYPE_INODE_STORAGE         = 28,
    BPF_MAP_TYPE_TASK_STORAGE          = 29,
    BPF_MAP_TYPE_BLOOM_FILTER          = 30,
};

/* BPF map update flags. */
#define BPF_ANY     0               /* create or update */
#define BPF_NOEXIST 1               /* create only */
#define BPF_EXIST   2               /* update only */

/* perf_event_output: auto-select current CPU. */
#define BPF_F_CURRENT_CPU  0xffffffffULL

/* x86_64 uprobe/kprobe arch select. bpf_tracing.h reads this macro to
 * define PT_REGS_PARM* / PT_REGS_RC; defined here since common.h is
 * included before bpf_tracing.h. */
#ifndef __TARGET_ARCH_x86
#define __TARGET_ARCH_x86
#endif

/* Full x86_64 struct pt_regs definition. libbpf v1.8.0's bpf_tracing.h
 * does not define it and bpf_helper_defs.h only forward-declares it;
 * BPF_UPROBE/BPF_URETPROBE access members directly, so define it fully. */
struct pt_regs {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long rbp;
    unsigned long rbx;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8;
    unsigned long rax;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long orig_rax;
    unsigned long rip;
    unsigned long cs;
    unsigned long eflags;
    unsigned long rsp;
    unsigned long ss;
};

#endif /* __bpf__ */

/* BPF map pin path. */
#define PIN_BASE  "/sys/fs/bpf/guard/comm"

/* Action codes. */
#define ACT_ALLOW  0
#define ACT_DROP   2   /* invalidate mbuf (bpf_probe_write_user) */
#define ACT_KILL   3   /* send SIGKILL directly (bpf_send_signal) */

/* Feature flags (runtime_config.features bitmask). */
#define FEAT_ENFORCEMENT     (1u << 0)
#define FEAT_FRAGMENT_DROP   (1u << 1)
#define FEAT_MALFORMED_DROP  (1u << 2)
#define FEAT_VLAN_COUNT      (1u << 3)
#define FEAT_LATENCY_SAMPLE  (1u << 4)

/* Latency histogram bucket count. */
#define LAT_BUCKETS 64

/* Runtime config, injected into the BPF .rodata section.
 * BPF side: const volatile struct runtime_config RCFG = { defaults };
 * Loader obtains the pointer via bpf_map__initial_value(rodata, &sz) and
 * overwrites mbuf offsets etc. before program load. */
struct runtime_config {
    __u32 mbuf_off_buf_addr;   /* byte offset of rte_mbuf.buf_addr */
    __u32 mbuf_off_data_off;   /* byte offset of rte_mbuf.data_off */
    __u32 mbuf_off_pkt_len;    /* byte offset of rte_mbuf.pkt_len */
    __u32 mbuf_off_data_len;   /* byte offset of rte_mbuf.data_len */
    __u32 max_burst_inspect;   /* max packets inspected per burst (<=32) */
    __u32 kill_signal;         /* signal sent on ACT_KILL (9=SIGKILL) */
    __u32 enabled;             /* 0 = all probes return immediately */
    __u32 generation;          /* config update counter (loader injects time()) */
    __u32 features;            /* FEAT_* bitmask */
    __u64 tenant_cgroup_id;    /* trusted host snapshot; one cgroup per loader */
};

/* Policy map key.
 * cgroup_id == 0 is a wildcard (applies to all cgroups); non-zero is a
 * cgroup-specific rule. Lookup priority (see lookup_action):
 *   1. (cgroup, proto, dst_port, src_ip, dst_ip)  — exact
 *   2. (cgroup, proto, dst_port, 0, 0)            — IP wildcard
 *   3. (cgroup, proto, 0, 0, 0)                   — port+IP wildcard
 *   4. (0, proto, dst_port, src_ip, dst_ip)       — cgroup wildcard
 *   5. (0, proto, dst_port, 0, 0)
 *   6. (0, proto, 0, 0, 0)
 */
struct comm_policy_key {
    __u64 cgroup_id;  /* host-injected cgroup-v2 inode, 0 = wildcard */
    __u32 src_ip;     /* network byte order, 0 = any */
    __u32 dst_ip;     /* network byte order, 0 = any */
    __u16 src_port;   /* host byte order, 0 = any */
    __u16 dst_port;
    __u8  protocol;   /* 6=TCP 17=UDP 1=ICMP 0=any */
    __u8  layer;      /* 1 = HW flow, 2 = eBPF */
    __u16 _pad;
};

/* Policy map value. */
struct comm_policy_value {
    __u32 action;     /* ACT_* */
    __u32 hit_count;  /* incremented atomically */
};

/* Event (perf ring -> user space). cgroup_id identifies which
 * container/process group the packet belongs to. */
struct comm_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;           /* bpf_get_current_cgroup_id() */
    __u16 port_id;
    __u16 queue_id;
    __u16 nb_pkts_returned;
    __u16 nb_pkts_dropped;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  action_taken;
    __u16 hook_dir;          /* 1=RX, 2=TX; preserves event layout */
};

/* Per-queue stats (PERCPU map value). */
struct queue_stats {
    __u64 rx;
    __u64 tx;
    __u64 drop;            /* ACT_DROP: mbuf-invalidation count */
    __u64 allow;
    __u64 vlan_seen;
    __u64 frag_drop;
    __u64 malformed_drop;
    __u64 policy_hits;
    __u64 parse_fail;
    __u64 rx_zero_burst;   /* RX starvation: zero-return burst count */
    __u64 tx_drop;         /* TX drop: nb_sent < nb_requested count */
};

/* Vuln events (vuln_events -> user space). */
#define VULN_RX_STARVATION  1u  /* consecutive zero-return bursts */
#define VULN_TX_DROP        2u  /* nb_sent < nb_requested */
#define VULN_MBUF_MALFORM   3u  /* null buf_addr / oversized pkt_len */

struct vuln_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    __u16 port_id;
    __u16 queue_id;
    __u8  vuln_type;     /* VULN_* */
    __u8  _pad[3];
    __u32 detail;        /* starvation: consecutive zero count; tx_drop: loss count */
};

/* Latency histogram. */
struct latency_hist {
    __u64 buckets[LAT_BUCKETS];
    __u64 sum;
    __u64 count;
    __u64 max;
};


/* Resource-monitor module shared types. */

#define API_RTE_EAL_INIT              0u
#define API_RTE_PKTMBUF_POOL_CREATE   1u
#define API_RTE_MEMPOOL_CREATE        2u
#define API_RTE_ETH_DEV_CONFIGURE     3u
#define API_RTE_ETH_RX_QUEUE_SETUP    4u
#define API_RTE_ETH_TX_QUEUE_SETUP    5u
#define API_RTE_ETH_DEV_START         6u
#define API_RTE_MALLOC                7u
#define API_RTE_ZMALLOC               8u
#define API_RTE_MEMZONE_RESERVE       9u
#define API_RTE_EAL_REMOTE_LAUNCH    10u  /* detect lcore over-grab */

struct resource_policy {
    __u64 max_socket_mem_mb;       /* sum of rte_eal_init --socket-mem (MB, 0=unlimited) */
    __u32 max_mbuf_count;
    __u64 max_mbuf_total_bytes;
    __u32 max_rx_queues;
    __u32 max_tx_queues;
    __u32 max_ports;
    __u64 max_rte_malloc_bytes;
    __u32 max_lcore_count;         /* max allowed lcores (0=unlimited) */
    __u32 action_on_violation;
    __u64 binary_hash;
};

struct pid_resource_stats {
    __u32 pid;
    __u32 tgid;
    __u64 socket_mem_mb;           /* sum of rte_eal_init --socket-mem (MB) */
    __u32 mbuf_pool_count;
    __u32 mbuf_total_count;
    __u64 mbuf_total_bytes;
    __u32 mempool_count;
    __u32 rx_queues_total;
    __u32 tx_queues_total;
    __u32 ports_configured;
    __u32 lcore_count;             /* rte_eal_remote_launch call count */
    __u64 rte_malloc_bytes;
    __u64 first_seen_ns;
    __u64 last_event_ns;
    __u64 violation_count;
};

union resource_arg {
    struct {
        __u32  n;
        __u32  cache_size;
        __u32  priv_size;
        __u32  data_room_size;
        __s32  socket_id;
        __u32  _rsvd;
        char   name[32];
    } pool_create;
    struct {
        __u16  port_id;
        __u16  nb_rx_queue;
        __u16  nb_tx_queue;
        __u16  _pad;
    } dev_configure;
    struct {
        __u16  port_id;
        __u16  queue_id;
        __u32  nb_desc;
        __s32  socket_id;
        __u32  _pad;
    } queue_setup;
    struct {
        __u64  size;
        __u32  align;
        __u32  _pad;
    } malloc;
};

struct resource_event {
    __u64              ts_ns;
    __u32              pid;
    __u32              tgid;
    __u32              api_id;
    __u32              action_taken;
    __u32              violation;
    __u32              _pad;
    union resource_arg arg;
};
#endif /* _GUARD_COMMON_H */

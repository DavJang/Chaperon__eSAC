/* Chaperon resource policy / usage layout (Request I: full Table tab:apis).
 * One slot per tenant in resource_policy (Manager-RW, tenant-RO) and resource_usage (FROZEN; only the
 * kernel Sentinel writes; the Agent reads it through a read-only mapping).
 * The first fields are the Request E layout of rte_flow_create and are unchanged.
 * 0 in a limit means "no limit". A rate entry with rate 0 and burst b > 0 is a budget of b calls. */
#ifndef CHAP_RES_H
#define CHAP_RES_H
#define RU_N 64u

/* per-API rate / budget entries (flow_create keeps its Request E fields rate_per_sec/burst/last_ns) */
#define RAPI_FLOW_DESTROY 0
#define RAPI_FLOW_FLUSH   1
#define RAPI_DEV_START    2
#define RAPI_DEV_STOP     3
#define RAPI_PROMISC_EN   4
#define RAPI_PROMISC_DIS  5
#define RAPI_MC_ADDR      6
#define RAPI_MEM          7   /* memory class: malloc, zmalloc, memzone_reserve, mempool_create, pktmbuf_pool_create */
#define N_RAPI            8
/* Request J: resource class of a sealed-dispatch slot (gate argument bits 0-7; bits 8-15 = API id) */
#define RC_MEM 1
#define RC_LAUNCH 2
#define RC_PORT 3
#define RC_NIC 4
#define RU_NEST 16

struct rate_pol { __u64 rate_per_sec, burst; };

struct ru_slot {
    /* Request E (rte_flow_create) */
    __u64 seq, api_calls, flow_held; __s64 tokens_milli; __u64 last_ns, denied, completed;
    /* Request I */
    __u64 mem_bytes;            /* hugepage heap bytes held (malloc_heap_alloc .. rte_free) */
    __u64 mbufs;                /* elements of pktmbuf pools held */
    __u64 rxq_cfg, txq_cfg;     /* queues configured (eth_dev_{rx,tx}_queue_config) */
    __u64 rxq_used, txq_used;   /* highest set-up queue index + 1 */
    __u64 api_tat[N_RAPI];      /* GCRA theoretical arrival time per rate entry */
    __u64 api_used[N_RAPI];     /* executed calls per rate entry (budget accounting) */
    __u64 denied2;              /* Sentinel hard-limit events of the Request I resources */
    /* Request J: memory-API rate at the sealed-dispatch boundary (written by the kernel Sentinel only) */
    __u64 mem_calls;            /* admitted outermost memory API calls (one GCRA token each) */
    __u64 mem_nested;           /* memory API calls nested in an outer policy API call (no token) */
    __u64 gate_stale;           /* outer-call state found open (skipped exit) or nesting budget used up */
    __u64 nest_tid[RU_NEST];    /* threads inside an outermost policy API call (Agent: no rate check) */
};

struct rp_slot {
    /* Request E (rte_flow_create): quota on held flow rules + rate */
    __u64 hard_flows, rate_per_sec, burst;
    /* Request I */
    __u64 max_lcores, max_hp_mb;           /* Launch: EAL arguments of rte_eal_init */
    __u64 lcore_mask_lo, lcore_mask_hi;    /* Launch: lcores the tenant may use (admitted set; 0 = any) */
    __u64 max_mem_bytes, max_mbufs;        /* Memory */
    __u64 max_rxq, max_txq;                /* Port */
    struct rate_pol api[N_RAPI];           /* NIC control + memory rates */
};

/* native helper (ufunc) filled by chap_eal_args() in the trusted provider */
struct chap_eal_req { __u64 lcores, mem_mb, mask_lo, mask_hi, err; };
#endif

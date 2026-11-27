/* policy_table.h — mmapable ARRAY-backed open-addressing hash table for eSAC comm_policy.
 *
 * Replaces BPF_MAP_TYPE_HASH comm_policy with a BPF_MAP_TYPE_ARRAY (BPF_F_MMAPABLE|BPF_F_RDONLY_PROG)
 * of fixed slots, so it can be mmapped (zero-syscall lookup) and kernel-backed. Lookup is
 * HASH + bounded open-addressing probe (NOT linear scan). The eSAC 5-tuple key, mask-probe
 * (wildcard) and ALLOW/DROP/KILL semantics are preserved: the caller still issues the same
 * sequence of masked-key lookups (see lookup_one_class), each of which becomes one pol_lookup().
 *
 * Integrity:
 *   - Per-slot SEQLOCK: a root writer publishes an entry between two seq bumps; a concurrent
 *     reader retries while seq is odd/changed, so no torn (half-written) policy is ever observed.
 *   - Collision: open addressing; every probed slot's FULL key is compared, so a hash collision
 *     never yields a wrong match.
 *   - Saturation: the writer REJECTS an insert whose probe window (POL_PROBE_MAX) fills without a
 *     free/own slot, so a policy is never silently dropped and a lookup never bypasses it. The
 *     reader uses the same POL_PROBE_MAX, so any installed key is always found in-window.
 */
#ifndef POLICY_TABLE_H
#define POLICY_TABLE_H
#include <stdint.h>

#define ACT_ALLOW 0u
#define ACT_DROP  2u
#define ACT_KILL  3u
#define POL_NOMATCH 0xffffffffu

#define POL_PROBE_MAX 16u          /* bounded probe window (both writer & reader) */

/* exact eSAC key (common.h) */
struct comm_policy_key {
    uint64_t cgroup_id;   /* 0 = any */
    uint32_t src_ip;      /* net order, 0 = any */
    uint32_t dst_ip;
    uint16_t src_port;    /* host order, 0 = any */
    uint16_t dst_port;
    uint8_t  protocol;    /* 6/17/1/0=any */
    uint8_t  layer;       /* 2 = eBPF */
    uint16_t _pad;
};

/* one mmapable array slot (value of the ARRAY map) */
struct pol_slot {
    volatile uint32_t seq;        /* seqlock: even=stable, odd=writing */
    uint32_t occupied;            /* 0=empty, 1=in use */
    struct comm_policy_key key;   /* 24 bytes */
    uint32_t action;              /* ACT_* (read-only to tenant) */
    uint32_t _pad;
};                                /* 40 bytes */

static inline uint32_t pol_hash(const struct comm_policy_key *k)
{
    /* FNV-1a over the key bytes; deterministic & identical in writer/reader/BPF */
    const uint32_t *w = (const uint32_t *)k;
    uint32_t h = 2166136261u;
    for (unsigned i = 0; i < sizeof(*k)/4u; i++) { h ^= w[i]; h *= 16777619u; }
    h ^= h >> 16; h *= 2246822519u; h ^= h >> 13;  /* word-wise + avalanche, matches c_filter/c_loader */
    return h;
}
static inline int pol_key_eq(const struct comm_policy_key *a, const struct comm_policy_key *b)
{
    const unsigned char *x=(const unsigned char*)a, *y=(const unsigned char*)b;
    for (unsigned i=0;i<sizeof(*a);i++) if (x[i]!=y[i]) return 0;
    return 1;
}

#ifndef __BPF__
#include <string.h>
/* ---- writer (root, mmap RW): seqlock publish; returns 0 ok, -1 saturated ---- */
static inline int pol_insert(struct pol_slot *tab, uint32_t n_slots,
                             const struct comm_policy_key *key, uint32_t action)
{
    uint32_t mask = n_slots - 1;              /* n_slots must be power of two */
    uint32_t h = pol_hash(key) & mask;
    for (uint32_t i=0;i<POL_PROBE_MAX;i++){
        struct pol_slot *s = &tab[(h+i) & mask];
        int own = (s->occupied && pol_key_eq(&s->key, key));
        if (own || !s->occupied){
            uint32_t seq = s->seq & ~1u;      /* make even baseline */
            s->seq = seq + 1;                 /* odd: writing */
            __sync_synchronize();
            s->key = *key; s->action = action; s->occupied = 1;
            __sync_synchronize();
            s->seq = seq + 2;                 /* even: published */
            return 0;
        }
    }
    return -1;                                /* SATURATED -> reject (no silent drop) */
}
/* ---- reader (mmap RO): seqlock-safe open-addressing lookup; mirrors a single masked HASH lookup ---- */
static inline uint32_t pol_lookup(const struct pol_slot *tab, uint32_t n_slots,
                                  const struct comm_policy_key *key)
{
    uint32_t mask = n_slots - 1;
    uint32_t h = pol_hash(key) & mask;
    for (uint32_t i=0;i<POL_PROBE_MAX;i++){
        const struct pol_slot *s = &tab[(h+i) & mask];
        uint32_t occ, act; struct comm_policy_key k;
        for (uint32_t t=0;t<64;t++){
            uint32_t s1 = s->seq;
            if (s1 & 1u) continue;            /* writer mid-update: retry */
            __sync_synchronize();
            occ = s->occupied; k = s->key; act = s->action;
            __sync_synchronize();
            uint32_t s2 = s->seq;
            if (s1 == s2) break;              /* stable snapshot */
        }
        if (occ && pol_key_eq(&k, key)) return act;   /* MATCH */
        if (!occ) return POL_NOMATCH;                 /* empty slot: key absent */
    }
    return POL_NOMATCH;                        /* probe exhausted (writer guarantees in-window) */
}
#endif /* !__BPF__ */

#endif

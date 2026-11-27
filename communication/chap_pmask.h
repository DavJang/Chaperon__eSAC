/* chap_pmask.h -- Chaperon Request I: 64 mask-probe active-combo header, WRITER side (Manager, root, RW mmap).
 * Layout and combo numbering: see chap_lookup64.h. The comm_policy ARRAY has n_hash hash slots plus one header
 * slot at index n_hash. Callers hold chap_policy_lock() (the single host-wide comm_policy writer lock).
 * Ordering rule: a combo's bit is published BEFORE any rule of that combo, so the Filter can never hold a rule
 * it does not probe (a skipped DROP rule could otherwise let a less specific ALLOW win). Bits are only added;
 * a table reset clears the mask together with the slots.
 */
#ifndef CHAP_PMASK_H
#define CHAP_PMASK_H
#include <stdint.h>
#include <string.h>
#define CHAP_PMASK_MAGIC 0x4b53414du

static inline unsigned chap_combo_of(const struct comm_policy_key *k)
{   /* index by (sip wild) | (dip wild)<<1 | (dport wild)<<2  ->  pattern 0..7 */
    static const unsigned char pat[8] = { 0, 1, 2, 4, 3, 5, 6, 7 };
    unsigned w = (k->src_ip == 0) | ((k->dst_ip == 0) << 1) | ((k->dst_port == 0) << 2);
    return ((k->cgroup_id == 0) << 5) | ((k->protocol == 0) << 4) | ((k->src_port == 0) << 3) | pat[w];
}
static inline uint64_t chap_pmask_get(const struct pol_slot *tab, uint32_t n_hash)
{
    const volatile struct pol_slot *h = &tab[n_hash]; uint64_t m = 0;
    for (int t = 0; t < 64; t++) {
        uint32_t s1 = h->seq; if (s1 & 1u) continue; __sync_synchronize();
        uint32_t occ = h->occupied; memcpy(&m, (const void *)&h->key, 8); __sync_synchronize();
        if (h->seq == s1) return occ == CHAP_PMASK_MAGIC ? m : 0;
    }
    return 0;
}
static inline void chap_pmask_store(struct pol_slot *tab, uint32_t n_hash, uint64_t m)
{
    volatile struct pol_slot *h = &tab[n_hash];
    uint32_t q = h->seq & ~1u; h->seq = q + 1; __sync_synchronize();
    memcpy((void *)&h->key, &m, 8); h->occupied = CHAP_PMASK_MAGIC; h->action = 0;
    __sync_synchronize(); h->seq = q + 2;
}
static inline void chap_pmask_add(struct pol_slot *tab, uint32_t n_hash, uint64_t bits)
{
    uint64_t m = chap_pmask_get(tab, n_hash);
    if ((m | bits) != m || tab[n_hash].occupied != CHAP_PMASK_MAGIC) chap_pmask_store(tab, n_hash, m | bits);
}
/* map max_entries -> hash slots: a 2^k + 1 map carries the header (Request I); a 2^k map is the old layout */
static inline int chap_pol_layout(uint32_t max_entries, uint32_t *n_hash)
{
    if (max_entries >= 2 && ((max_entries - 1) & (max_entries - 2)) == 0) { *n_hash = max_entries - 1; return 1; }
    *n_hash = max_entries; return 0;
}
#endif

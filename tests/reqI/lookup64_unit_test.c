// Chaperon Request I: unit test of the 64 mask-probe lookup (communication/chap_lookup64.h, the code the Filter
// compiles) and the Manager writer helpers (communication/chap_pmask.h), over the same open-addressing table
// layout and seqlock writer (policy_table_opt.h). Checks:
//   U1 every one of the 64 combos (32 tenant + 32 global): exact fields must match, wildcard fields are free
//   U2 precedence = lowest active combo index (tenant before global), against a brute-force reference model
//   U3 the 20 combos of the previous 20-probe layout: identical decisions to the previous algorithm
//   U4 packet fields equal to 0 (exact/wildcard coincide): decisions still equal the reference model
//   U5 only active combos are probed (probes per packet <= popcount(mask))
//   U6 live update with a NEW combo: mask-first order never exposes a rule without its bit; the rule-without-bit
//      state (wrong order) is shown as the hazard it would be
//   U7 header unreadable / unstable / missing magic => mask 0 => default DROP; tenant 0 => KILL
//   build: gcc -O2 -I../../communication lookup64_unit_test.c -o lookup64_unit_test
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64; typedef uint32_t __u32; typedef uint16_t __u16; typedef uint8_t __u8;
#define __always_inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))
#define barrier() __asm__ __volatile__("" ::: "memory")
#include "policy_table_opt.h"          /* struct comm_policy_key, struct pol_slot, pol_insert, pol_lookup, ACT_* */
#define POL_N 16384u
static struct pol_slot TAB[POL_N + 1];
static int comm_policy;
static void *bpf_map_lookup_elem(void *m, const void *k) { (void)m; uint32_t i = *(const uint32_t *)k; return i <= POL_N ? &TAB[i] : NULL; }
static unsigned long g_probes;
static __u32 policy_arr_lookup(const struct comm_policy_key *k) { g_probes++; return pol_lookup(TAB, POL_N, k); }
#include "chap_pmask.h"
#include "chap_lookup64.h"

struct rule { struct comm_policy_key k; uint32_t act; };
static struct rule R[256]; static int NR;
static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; if (fails < 20) { printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); } } } while (0)

static void reset(void) { memset(TAB, 0, sizeof TAB); chap_pmask_store(TAB, POL_N, 0); NR = 0; }
static void write_rule(struct comm_policy_key k, uint32_t act)          /* the Manager order: bit, then rule */
{
    k.layer = 2; chap_pmask_add(TAB, POL_N, 1ull << chap_combo_of(&k));
    if (pol_insert(TAB, POL_N, &k, act) != 0) { printf("saturated\n"); exit(2); }
    for (int i = 0; i < NR; i++) if (!memcmp(&R[i].k, &k, sizeof k)) { R[i].act = act; return; }
    R[NR].k = k; R[NR].act = act; NR++;
}
static uint32_t ref(const struct chap_lk *p)                            /* brute force: lowest matching combo */
{
    if (!p->tenant) return ACT_KILL;
    int best = 99; uint32_t act = ACT_DROP;
    for (int i = 0; i < NR; i++) {
        const struct comm_policy_key *k = &R[i].k;
        if (k->cgroup_id && k->cgroup_id != p->tenant) continue;
        if (k->protocol && k->protocol != p->proto) continue;
        if (k->src_port && k->src_port != p->sport) continue;
        if (k->dst_port && k->dst_port != p->dport) continue;
        if (k->src_ip && k->src_ip != p->sip) continue;
        if (k->dst_ip && k->dst_ip != p->dip) continue;
        int c = (int)chap_combo_of(k); if (c < best) { best = c; act = R[i].act; }
    }
    return act;
}
/* the previous 20-probe algorithm (lookup_action_slow + lookup_one_class), on the same table */
static uint32_t old_class(struct comm_policy_key k, const struct chap_lk *a, uint32_t mask, uint32_t base)
{
    uint32_t r; k.src_ip = a->sip; k.dst_ip = a->dip;
    if ((mask & (1u << (base + 0))) && (r = pol_lookup(TAB, POL_N, &k)) != POL_NOMATCH) return r;
    k.src_ip = 0;
    if ((mask & (1u << (base + 1))) && (r = pol_lookup(TAB, POL_N, &k)) != POL_NOMATCH) return r;
    k.dst_ip = 0;
    if ((mask & (1u << (base + 2))) && (r = pol_lookup(TAB, POL_N, &k)) != POL_NOMATCH) return r;
    k.dst_port = 0; k.dst_ip = a->dip;
    if ((mask & (1u << (base + 3))) && (r = pol_lookup(TAB, POL_N, &k)) != POL_NOMATCH) return r;
    k.dst_ip = 0;
    if ((mask & (1u << (base + 4))) && (r = pol_lookup(TAB, POL_N, &k)) != POL_NOMATCH) return r;
    return POL_NOMATCH;
}
static uint32_t old_lookup(const struct chap_lk *a, uint32_t mask)
{
    if (!a->tenant) return ACT_KILL;
    struct comm_policy_key k = {0}; uint32_t r; k.layer = 2; k.protocol = a->proto; k.dst_port = a->dport;
    k.cgroup_id = a->tenant; k.src_port = a->sport;
    if ((mask & 0x1Fu) && (r = old_class(k, a, mask, 0)) != POL_NOMATCH) return r;
    k.src_port = 0; if ((mask & (0x1Fu << 5)) && (r = old_class(k, a, mask, 5)) != POL_NOMATCH) return r;
    k.cgroup_id = 0; k.src_port = a->sport; if ((mask & (0x1Fu << 10)) && (r = old_class(k, a, mask, 10)) != POL_NOMATCH) return r;
    k.src_port = 0; if ((mask & (0x1Fu << 15)) && (r = old_class(k, a, mask, 15)) != POL_NOMATCH) return r;
    return ACT_DROP;
}
static uint32_t old_mask_of(void)   /* compute_probe_mask() of the loader for the installed rules */
{
    uint32_t m = 0;
    for (int i = 0; i < NR; i++) { const struct comm_policy_key *k = &R[i].k; unsigned base = (k->cgroup_id ? 0u : 10u) + (k->src_port ? 0u : 5u); int p = -1;
        if (k->src_ip && k->dst_ip && k->dst_port) p = 0; else if (!k->src_ip && k->dst_ip && k->dst_port) p = 1;
        else if (!k->src_ip && !k->dst_ip && k->dst_port) p = 2; else if (!k->src_ip && k->dst_ip && !k->dst_port) p = 3;
        else if (!k->src_ip && !k->dst_ip && !k->dst_port) p = 4;
        if (p >= 0) m |= 1u << (base + p); }
    return m;
}
static struct comm_policy_key key_of(int c, uint64_t T, const struct chap_lk *p)   /* rule of combo c matching p */
{
    struct comm_policy_key k = {0}; __u32 w = chap_pat_w(c & 7);
    k.cgroup_id = (c & 32) ? 0 : T; k.protocol = (c & 16) ? 0 : p->proto; k.src_port = (c & 8) ? 0 : p->sport;
    k.src_ip = (w & CHAP_W_SIP) ? 0 : p->sip; k.dst_ip = (w & CHAP_W_DIP) ? 0 : p->dip; k.dst_port = (w & CHAP_W_DP) ? 0 : p->dport; k.layer = 2;
    return k;
}
static uint64_t rnd(void) { static uint64_t s = 0x9E3779B97F4A7C15ull; s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
static struct chap_lk rpkt(uint64_t T, int zero_fields)
{
    struct chap_lk p = {0}; p.tenant = T;
    static const uint8_t pr[3] = { 17, 6, 1 }; p.proto = pr[rnd() % 3];
    p.sip = 0x0a000001u + (uint32_t)(rnd() % 3); p.dip = 0x0a000101u + (uint32_t)(rnd() % 3);
    p.sport = (uint16_t)(1000 + rnd() % 3); p.dport = (uint16_t)(2000 + rnd() % 3);
    if (zero_fields) { if (rnd() & 1) p.sport = 0; if (rnd() & 1) p.dport = 0; }
    if (p.proto == 1) { p.sport = 0; p.dport = 0; }   /* ICMP: no ports */
    return p;
}
static struct comm_policy_key rrule(uint64_t T, int old_only)
{
    struct chap_lk p = rpkt(T, 0); int c;
    if (old_only) { static const int pat[5] = { 0, 1, 4, 5, 7 }; c = (int)(rnd() % 2) * 32 + (int)(rnd() % 2) * 8 + pat[rnd() % 5];
                    if (!p.proto || p.proto == 1) p.proto = 17; if (!p.dport) p.dport = 2000; if (!p.sport) p.sport = 1000; }
    else c = (int)(rnd() % 64);
    if (!(c & 16) && p.proto == 1 && (!(c & 8) || !(chap_pat_w(c & 7) & CHAP_W_DP))) p.proto = 17;   /* exact ports need a port protocol */
    return key_of(c, T, &p);
}

int main(void)
{
    const uint64_t T = 0x1234;
    /* ---- U1: every combo, exact fields must match, wildcard fields are free ---- */
    int u1 = 0;
    for (int c = 0; c < 64; c++) {
        reset(); struct chap_lk base = { .tenant = T, .sip = 0x0a000001, .dip = 0x0a000101, .sport = 1111, .dport = 2222, .proto = 17 };
        struct comm_policy_key k = key_of(c, T, &base); write_rule(k, ACT_ALLOW);
        CHECK(chap_combo_of(&k) == (unsigned)c, "combo_of(key_of(%d))=%u", c, chap_combo_of(&k));
        uint64_t m = chap_pmask_read(); CHECK(m == (1ull << c), "combo %d: mask %llx", c, (unsigned long long)m);
        CHECK(chap_lookup64(&base, m) == ACT_ALLOW, "combo %d: base packet not ALLOW", c);
        for (int f = 0; f < 6; f++) {          /* change one field: sip dip sport dport proto tenant */
            struct chap_lk p = base; int wild;
            __u32 w = chap_pat_w(c & 7);
            switch (f) { case 0: p.sip ^= 0x100; wild = !!(w & CHAP_W_SIP); break; case 1: p.dip ^= 0x100; wild = !!(w & CHAP_W_DIP); break;
                         case 2: p.sport += 1; wild = !!(c & 8); break; case 3: p.dport += 1; wild = !!(w & CHAP_W_DP); break;
                         case 4: p.proto = 6; wild = !!(c & 16); break; default: p.tenant = T + 1; wild = !!(c & 32); }
            uint32_t got = chap_lookup64(&p, m), exp = wild ? ACT_ALLOW : ACT_DROP;
            CHECK(got == exp, "combo %d field %d (wild=%d): got %u exp %u", c, f, wild, got, exp);
            if (got == exp) u1++;
        }
    }
    printf("U1 64 combos x 6 field variations: %d/384 as expected\n", u1);
    /* ---- U2/U4/U5: random rule sets vs the reference (with and without zero packet fields) ---- */
    long u2 = 0, u2bad = 0, maxpr = 0, probes_over = 0;
    for (int set = 0; set < 400; set++) {
        reset(); int n = 1 + (int)(rnd() % 40);
        for (int i = 0; i < n; i++) write_rule(rrule(T, 0), (rnd() & 1) ? ACT_ALLOW : ACT_DROP);
        uint64_t m = chap_pmask_read();
        for (int q = 0; q < 2000; q++) {
            struct chap_lk p = rpkt((rnd() % 10) ? T : T + 1, q & 1);
            g_probes = 0; uint32_t got = chap_lookup64(&p, m), exp = ref(&p);
            if ((long)g_probes > maxpr) maxpr = (long)g_probes;
            if (g_probes > (unsigned long)__builtin_popcountll(m)) probes_over++;
            u2++; if (got != exp) { u2bad++; CHECK(0, "set %d: got %u exp %u", set, got, exp); }
        }
    }
    printf("U2+U4 random rule sets (all 64 combos, tenant/global, half the packets with 0 ports, ICMP): %ld decisions, %ld mismatches vs reference\n", u2, u2bad);
    printf("U5 probes per packet <= active combos: violations=%ld (max probes seen %ld)\n", probes_over, maxpr); if (probes_over) fails++;
    /* ---- U3: previous 20-probe combos -> identical decisions to the previous algorithm ---- */
    long u3 = 0, u3bad = 0;
    for (int set = 0; set < 400; set++) {
        reset(); int n = 1 + (int)(rnd() % 40);
        for (int i = 0; i < n; i++) write_rule(rrule(T, 1), (rnd() & 1) ? ACT_ALLOW : ACT_DROP);
        uint64_t m = chap_pmask_read(); uint32_t om = old_mask_of();
        for (int q = 0; q < 2000; q++) { struct chap_lk p = rpkt((rnd() % 10) ? T : T + 1, 0);
            uint32_t a = chap_lookup64(&p, m), b = old_lookup(&p, om); u3++; if (a != b) { u3bad++; CHECK(0, "old-layout set %d: new %u old %u", set, a, b); } }
    }
    printf("U3 previous 20-probe combos: %ld decisions, %ld differ from the previous algorithm\n", u3, u3bad);
    /* ---- U6: live update with a new combo ---- */
    reset(); struct chap_lk p = { .tenant = T, .sip = 0x0a000009, .dip = 0x0a000101, .sport = 1111, .dport = 2222, .proto = 17 };
    struct comm_policy_key g = key_of(32 + 8 + 7, T, &p);  write_rule(g, ACT_ALLOW);          /* global allow udp, everything else wild */
    uint32_t before = chap_lookup64(&p, chap_pmask_read());
    struct comm_policy_key d = key_of(16 + 8 + 6, T, &p);                                       /* NEW combo: tenant, proto*, sport*, sip exact */
    chap_pmask_add(TAB, POL_N, 1ull << chap_combo_of(&d));                                      /* step 1: bit */
    uint32_t mid = chap_lookup64(&p, chap_pmask_read());
    pol_insert(TAB, POL_N, &d, ACT_DROP); R[NR].k = d; R[NR].act = ACT_DROP; NR++;               /* step 2: rule */
    uint32_t after = chap_lookup64(&p, chap_pmask_read());
    CHECK(before == ACT_ALLOW && mid == ACT_ALLOW && after == ACT_DROP && after == ref(&p), "live: before %u mid %u after %u", before, mid, after);
    reset(); write_rule(g, ACT_ALLOW); pol_insert(TAB, POL_N, &d, ACT_DROP);                    /* WRONG order: rule without bit */
    uint32_t hazard = chap_lookup64(&p, chap_pmask_read());
    printf("U6 live new combo (mask first): before=%u mid=%u after=%u ; rule-without-bit (wrong order) would give %u (the ignored DROP)\n", before, mid, after, hazard);
    CHECK(hazard == ACT_ALLOW, "hazard demo");
    /* ---- U7: broken header -> DROP ; tenant 0 -> KILL ---- */
    reset(); struct comm_policy_key a = key_of(0, T, &p); write_rule(a, ACT_ALLOW);
    uint32_t ok = chap_lookup64(&p, chap_pmask_read());
    TAB[POL_N].seq |= 1u; uint32_t odd = chap_lookup64(&p, chap_pmask_read()); TAB[POL_N].seq += 1u;
    TAB[POL_N].occupied = 0; uint32_t nomagic = chap_lookup64(&p, chap_pmask_read()); TAB[POL_N].occupied = CHAP_PMASK_MAGIC;
    struct chap_lk z = p; z.tenant = 0; uint32_t kill = chap_lookup64(&z, chap_pmask_read());
    printf("U7 header ok=%u writer-stuck(odd seq)=%u no-magic=%u ; tenant 0=%u\n", ok, odd, nomagic, kill);
    CHECK(ok == ACT_ALLOW && odd == ACT_DROP && nomagic == ACT_DROP && kill == ACT_KILL, "U7");
    printf("LOOKUP64 RESULT: %s (%d failing)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}

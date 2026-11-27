/* chap_lookup64.h -- Chaperon Request I: 64 mask-probe L4 lookup (reader side, BPF filter + native unit test).
 *
 * A probe combination ("combo") fixes which of the 5 tuple fields (+ tenant/global class) are exact and which
 * are wildcard (0) in the comm_policy key. Combo index c (0..63) = probe order = precedence:
 *   bit5  class        0 tenant (cgroup_id = tenant)   1 global (cgroup_id = 0)
 *   bit4  protocol     0 exact                          1 wildcard
 *   bit3  src_port     0 exact                          1 wildcard
 *   bit2..0 pattern over {src_ip, dst_ip, dst_port} wildcards:
 *         0 {}  1 {sip}  2 {dip}  3 {dport}  4 {sip,dip}  5 {sip,dport}  6 {dip,dport}  7 {sip,dip,dport}
 * Tenant combos (0..31) precede global ones (32..63); the 20 combos of the previous 20-probe layout
 * (protocol exact, patterns 0/1/4/5/7) keep their previous relative order.
 *
 * The Manager keeps a 64-bit ACTIVE-COMBO mask in one header slot of the same kernel ARRAY (index POL_N,
 * outside the hash range, own seqlock, magic CHAP_PMASK_MAGIC). Writers set a combo's bit BEFORE inserting a
 * rule of that combo (never a rule without its bit). The Filter reads the mask once per burst and probes only
 * the set bits, lowest first, until the first match. Unreadable/unstable header => mask 0 => default DROP.
 * Value 0 in a key field means wildcard (an exact 0 is not expressible). For a packet field that is 0 the probes
 * that would match that field exactly are skipped (they would coincide with the wildcard combo and reorder rules).
 *
 * Includer provides: __u8/__u16/__u32/__u64, __always_inline, __noinline, barrier(), struct comm_policy_key,
 * struct pol_slot, POL_N, POL_NOMATCH, ACT_DROP, ACT_KILL, policy_arr_lookup(key), and either the BPF map
 * comm_policy with bpf_map_lookup_elem() or equivalent shims.
 */
#ifndef CHAP_LOOKUP64_H
#define CHAP_LOOKUP64_H
#define CHAP_PMASK_MAGIC 0x4b53414du       /* "MASK" in pol_slot.occupied of the header slot */
#define CHAP_W_SIP 1u
#define CHAP_W_DIP 2u
#define CHAP_W_DP  4u

/* pattern (combo bits 2..0) -> wildcard field bits */
static __always_inline __u32 chap_pat_w(__u32 p)
{
    return p == 0 ? 0u : p == 1 ? CHAP_W_SIP : p == 2 ? CHAP_W_DIP : p == 3 ? CHAP_W_DP :
           p == 4 ? (CHAP_W_SIP | CHAP_W_DIP) : p == 5 ? (CHAP_W_SIP | CHAP_W_DP) :
           p == 6 ? (CHAP_W_DIP | CHAP_W_DP) : (CHAP_W_SIP | CHAP_W_DIP | CHAP_W_DP);
}
/* index of the single set bit of x (branch-only binary search, no table) */
static __always_inline __u32 chap_ctz64(__u64 x)
{
    __u32 n = 0;
    if (!(x & 0xffffffffull)) { n += 32; x >>= 32; }
    if (!(x & 0xffffull))     { n += 16; x >>= 16; }
    if (!(x & 0xffull))       { n += 8;  x >>= 8; }
    if (!(x & 0xfull))        { n += 4;  x >>= 4; }
    if (!(x & 0x3ull))        { n += 2;  x >>= 2; }
    if (!(x & 0x1ull))        { n += 1; }
    return n;
}

struct chap_lk { __u64 tenant; __u32 sip, dip; __u16 sport, dport; __u8 proto; __u8 _pad[3]; };

static __noinline __u32 chap_probe_combo(const struct chap_lk *a, __u32 c)
{
    struct comm_policy_key k = {};
    __u32 w = chap_pat_w(c & 7u);
    /* 0 in a key field means wildcard, so a packet field equal to 0 cannot be matched EXACTLY: that probe would
       build the key of the field-wildcard combo and find its rules ahead of their own precedence. Skip it; the
       rule is found at its own combo index (if active). */
    if ((!(c & 16u) && !a->proto) || (!(c & 8u) && !a->sport) || (!(w & CHAP_W_SIP) && !a->sip) ||
        (!(w & CHAP_W_DIP) && !a->dip) || (!(w & CHAP_W_DP) && !a->dport)) return POL_NOMATCH;
    k.layer     = 2;
    k.cgroup_id = (c & 32u) ? 0 : a->tenant;
    k.protocol  = (c & 16u) ? 0 : a->proto;
    k.src_port  = (c & 8u)  ? 0 : a->sport;
    k.src_ip    = (w & CHAP_W_SIP) ? 0 : a->sip;
    k.dst_ip    = (w & CHAP_W_DIP) ? 0 : a->dip;
    k.dst_port  = (w & CHAP_W_DP)  ? 0 : a->dport;
    return policy_arr_lookup(&k);
}

/* first match over the ACTIVE combos only (popcount(mask) probes at most), else the default action */
static __always_inline __u32 chap_lookup64(const struct chap_lk *a, __u64 mask)
{
    if (a->tenant == 0) return ACT_KILL;    /* a missing host-injected identity never selects a wildcard ALLOW */
    __u64 m = mask;
#pragma unroll
    for (int i = 0; i < 64; i++) {
        if (!m) break;
        __u64 low = m & (~m + 1);
        m &= m - 1;
        __u32 r = chap_probe_combo(a, chap_ctz64(low));
        if (r != POL_NOMATCH) return r;
    }
    return ACT_DROP;                         /* parsed IPv4 packet without an explicit policy */
}

/* active-combo mask from the header slot; 0 (no probe => DROP) if unreadable, unstable or not initialized */
static __always_inline __u64 chap_pmask_read(void)
{
    __u32 hk = POL_N;
    struct pol_slot *h = bpf_map_lookup_elem(&comm_policy, &hk);
    if (!h) return 0;
#pragma unroll
    for (int t = 0; t < 4; t++) {
        __u32 s1 = h->seq; barrier();
        if (s1 & 1u) continue;
        __u32 occ = h->occupied; __u64 m; __builtin_memcpy(&m, (const void *)&h->key, 8); barrier();
        if (h->seq == s1) return occ == CHAP_PMASK_MAGIC ? m : 0;
    }
    return 0;
}
#endif

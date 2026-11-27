// Chaperon Manager: write a tenant's resource policy (Table tab:apis) into the pinned resource_policy map.
// Root only (BPF object pin / map fd). Unspecified fields keep their current value; 0 = no limit.
//   usage: chap_res_policy <pinned resource_policy> <slot> key=value ...
//   keys : hard_flows flow_rate flow_burst | max_lcores max_hp_mb lcores=<list> | max_mem_bytes max_mem_mb max_mbufs |
//          max_rxq max_txq | <api>.rate <api>.burst <api>.budget  (api: flow_destroy flow_flush dev_start dev_stop
//          promisc_en promisc_dis mc_addr mem)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include "../chap_res.h"
static const char *apin[N_RAPI] = { "flow_destroy", "flow_flush", "dev_start", "dev_stop", "promisc_en", "promisc_dis", "mc_addr", "mem" };
static void lcores(struct rp_slot *p, const char *v)
{
    p->lcore_mask_lo = p->lcore_mask_hi = 0;
    while (v && *v) { char *e; long a = strtol(v, &e, 10), b = a; if (e == v) { fprintf(stderr, "bad lcores\n"); exit(2); }
        if (*e == '-') b = strtol(e + 1, &e, 10);
        for (long c = a; c <= b && c < 128; c++) { if (c < 64) p->lcore_mask_lo |= 1ull << c; else p->lcore_mask_hi |= 1ull << (c - 64); }
        if (*e == ',') e++; else if (*e) { fprintf(stderr, "bad lcores\n"); exit(2); } v = e; }
}
int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s <pinned resource_policy> <slot> key=value ...\n", argv[0]); return 2; }
    int fd = bpf_obj_get(argv[1]); if (fd < 0) { fprintf(stderr, "bpf_obj_get %s: %s\n", argv[1], strerror(errno)); return 1; }
    __u32 k = (__u32)atoi(argv[2]); struct rp_slot p; memset(&p, 0, sizeof p);
    if (bpf_map_lookup_elem(fd, &k, &p)) { fprintf(stderr, "lookup: %s\n", strerror(errno)); return 1; }
    for (int i = 3; i < argc; i++) {
        char key[64]; const char *eq = strchr(argv[i], '='); if (!eq || eq - argv[i] >= 63) { fprintf(stderr, "bad arg %s\n", argv[i]); return 2; }
        memcpy(key, argv[i], eq - argv[i]); key[eq - argv[i]] = 0; const char *v = eq + 1; unsigned long long x = strtoull(v, 0, 0);
        if (!strcmp(key, "hard_flows")) p.hard_flows = x; else if (!strcmp(key, "flow_rate")) p.rate_per_sec = x; else if (!strcmp(key, "flow_burst")) p.burst = x;
        else if (!strcmp(key, "max_lcores")) p.max_lcores = x; else if (!strcmp(key, "max_hp_mb")) p.max_hp_mb = x; else if (!strcmp(key, "lcores")) lcores(&p, v);
        else if (!strcmp(key, "max_mem_bytes")) p.max_mem_bytes = x; else if (!strcmp(key, "max_mem_mb")) p.max_mem_bytes = x << 20; else if (!strcmp(key, "max_mbufs")) p.max_mbufs = x;
        else if (!strcmp(key, "max_rxq")) p.max_rxq = x; else if (!strcmp(key, "max_txq")) p.max_txq = x;
        else { int done = 0;
            for (int a = 0; a < N_RAPI && !done; a++) { size_t L = strlen(apin[a]);
                if (!strncmp(key, apin[a], L) && key[L] == '.') { const char *f = key + L + 1;
                    if (!strcmp(f, "rate")) p.api[a].rate_per_sec = x; else if (!strcmp(f, "burst")) p.api[a].burst = x;
                    else if (!strcmp(f, "budget")) { p.api[a].rate_per_sec = 0; p.api[a].burst = x; } else { fprintf(stderr, "bad field %s\n", key); return 2; }
                    done = 1; } }
            if (!done) { fprintf(stderr, "unknown key %s\n", key); return 2; } }
    }
    if (bpf_map_update_elem(fd, &k, &p, BPF_ANY)) { fprintf(stderr, "update: %s\n", strerror(errno)); return 1; }
    printf("RESPOLICY slot=%u hard_flows=%llu flow_rate=%llu flow_burst=%llu max_lcores=%llu max_hp_mb=%llu lcores=0x%llx:%llx max_mem_bytes=%llu max_mbufs=%llu max_rxq=%llu max_txq=%llu",
           k, (unsigned long long)p.hard_flows, (unsigned long long)p.rate_per_sec, (unsigned long long)p.burst, (unsigned long long)p.max_lcores, (unsigned long long)p.max_hp_mb,
           (unsigned long long)p.lcore_mask_hi, (unsigned long long)p.lcore_mask_lo, (unsigned long long)p.max_mem_bytes, (unsigned long long)p.max_mbufs, (unsigned long long)p.max_rxq, (unsigned long long)p.max_txq);
    for (int a = 0; a < N_RAPI; a++) if (p.api[a].rate_per_sec || p.api[a].burst) printf(" %s=%llu/s,b%llu", apin[a], (unsigned long long)p.api[a].rate_per_sec, (unsigned long long)p.api[a].burst);
    printf("\n"); return 0;
}

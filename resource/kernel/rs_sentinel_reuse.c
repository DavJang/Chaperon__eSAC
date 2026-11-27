// Chaperon kernel Resource Sentinel -- REUSE variant (single shared kernel object with the Agent).
// The bpftime Agent loader already created kernel resource_usage + resource_policy (ids passed in).
// Here we bpf_map__reuse_fd() those SAME kernel objects into resource_sentinel.bpf.o, create our
// own cg_slot + last_cg (kernel-only), set policy + cgroup->slot, freeze usage (best-effort), and
// attach the real kernel uprobe/uretprobe WRITERS to the tenant's mlx5_flow_create/destroy.
// => the Agent RO-reads and the kernel Sentinel writes the SAME kernel map. SIGUSR1 dumps usage.
//   usage: rs_sentinel_reuse <bpf.o> <pid> <cgid> <hard> <lib> <coff> <doff> <usage_id> <policy_id> <pindir>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include "../chap_res.h"


static int ru_fd = -1, lc_fd = -1, nm_fd = -1;
static volatile int stop = 0;
static void on_int(int s){ (void)s; stop = 1; }
static void on_usr1(int s){ (void)s;
    if (ru_fd >= 0) { void *ro = mmap(NULL, sizeof(struct ru_slot)*64, PROT_READ, MAP_SHARED, ru_fd, 0);
        if (ro != MAP_FAILED){ volatile struct ru_slot *r = ro;
            fprintf(stderr,"[sentinel] USAGE api_calls=%llu flow_held=%llu denied=%llu completed=%llu\n", (unsigned long long)r->api_calls, (unsigned long long)r->flow_held, (unsigned long long)r->denied, (unsigned long long)r->completed);
            fprintf(stderr,"[sentinel] USAGE2 mem_bytes=%llu mbufs=%llu rxq_cfg=%llu txq_cfg=%llu rxq_used=%llu txq_used=%llu denied2=%llu api_used=%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
                (unsigned long long)r->mem_bytes, (unsigned long long)r->mbufs, (unsigned long long)r->rxq_cfg, (unsigned long long)r->txq_cfg, (unsigned long long)r->rxq_used, (unsigned long long)r->txq_used, (unsigned long long)r->denied2,
                (unsigned long long)r->api_used[0], (unsigned long long)r->api_used[1], (unsigned long long)r->api_used[2], (unsigned long long)r->api_used[3], (unsigned long long)r->api_used[4], (unsigned long long)r->api_used[5], (unsigned long long)r->api_used[6], (unsigned long long)r->api_used[7]);
            { int nn = 0; for (int i = 0; i < RU_NEST; i++) if (r->nest_tid[i]) nn++;
              fprintf(stderr,"[sentinel] USAGE3 mem_calls=%llu mem_nested=%llu gate_stale=%llu mem_tat=%llu mem_used=%llu nest_open=%d\n",
                (unsigned long long)r->mem_calls, (unsigned long long)r->mem_nested, (unsigned long long)r->gate_stale,
                (unsigned long long)r->api_tat[RAPI_MEM], (unsigned long long)r->api_used[RAPI_MEM], nn); }
            munmap(ro, sizeof(struct ru_slot)*64); } }
    if (nm_fd >= 0) { char b[512]; int o = 0; for (unsigned int a = 1; a < 19; a++) { unsigned long long v = 0; bpf_map_lookup_elem(nm_fd, &a, &v); o += snprintf(b + o, sizeof b - o, " %u:%llu", a, v); }
        fprintf(stderr,"[sentinel] NESTMAX api:max_nested%s\n", b); }
    if (lc_fd >= 0){ unsigned int z=0; unsigned long d=0; bpf_map_lookup_elem(lc_fd,&z,&d);
        fprintf(stderr,"[sentinel] last_cg(discovered)=%lu\n", d); }
}

int main(int argc, char **argv)
{
    if (argc < 11) { fprintf(stderr,"usage: %s bpf.o pid cgid hard lib coff doff usage_id policy_id pindir\n", argv[0]); return 2; }
    const char *obj=argv[1]; int pid=atoi(argv[2]);
    unsigned long cgid=strtoul(argv[3],0,0), hard=strtoul(argv[4],0,0);
    const char *lib=argv[5]; unsigned long coff=strtoul(argv[6],0,16), doff=strtoul(argv[7],0,16);
    unsigned int usage_id=strtoul(argv[8],0,0), policy_id=strtoul(argv[9],0,0);
    const char *pindir=argv[10];
    signal(SIGINT,on_int); signal(SIGTERM,on_int); signal(SIGUSR1,on_usr1);

    struct bpf_object *o = bpf_object__open(obj);
    if (!o) { fprintf(stderr,"open fail\n"); return 1; }

    /* REUSE the Agent-loader's kernel maps => same object */
    int u_ext = bpf_map_get_fd_by_id(usage_id);
    int p_ext = bpf_map_get_fd_by_id(policy_id);
    if (u_ext < 0 || p_ext < 0) { fprintf(stderr,"get_fd_by_id usage=%d policy=%d fail\n", u_ext, p_ext); return 1; }
    struct bpf_map *mu = bpf_object__find_map_by_name(o,"resource_usage");
    struct bpf_map *mp = bpf_object__find_map_by_name(o,"resource_policy");
    if (bpf_map__reuse_fd(mu, u_ext) || bpf_map__reuse_fd(mp, p_ext)) {
        fprintf(stderr,"reuse_fd fail: %s\n", strerror(errno)); return 1; }

    if (bpf_object__load(o)) { fprintf(stderr,"load fail: %s\n", strerror(errno)); return 1; }
    ru_fd = bpf_object__find_map_fd_by_name(o,"resource_usage");
    int rp = bpf_object__find_map_fd_by_name(o,"resource_policy");
    int cg = bpf_object__find_map_fd_by_name(o,"cg_slot");
    lc_fd  = bpf_object__find_map_fd_by_name(o,"last_cg");

    struct rp_slot pol = { .hard_flows=hard, .rate_per_sec=0, .burst=0 };
    unsigned int z=0; bpf_map_update_elem(rp,&z,&pol,BPF_ANY);     /* policy NOT frozen (Manager-RW) */
    unsigned int slot=0; bpf_map_update_elem(cg,&cgid,&slot,BPF_ANY);

    /* freeze usage: best-effort. The loader (bpftime) may hold a writable mmap -> EBUSY; even then
       the tenant cannot write (KERNEL_MAP_RO + DROP_FD removes its only writable handle). */
    int fr = bpf_map_freeze(ru_fd);
    fprintf(stderr,"[sentinel] freeze(resource_usage)=%s\n", fr==0?"OK":strerror(errno));

    char p[256];
    snprintf(p,sizeof p,"%s/resource_usage",  pindir); bpf_obj_pin(ru_fd,p);
    snprintf(p,sizeof p,"%s/resource_policy", pindir); bpf_obj_pin(rp,p);

    struct bpf_program *pe = bpf_object__find_program_by_name(o,"rs_flow_create_entry");
    struct bpf_program *pc = bpf_object__find_program_by_name(o,"rs_flow_create_ret");
    struct bpf_program *pd = bpf_object__find_program_by_name(o,"rs_flow_destroy_ret");
    struct bpf_link *le = bpf_program__attach_uprobe(pe, false, pid, lib, coff);
    struct bpf_link *lc = bpf_program__attach_uprobe(pc, true,  pid, lib, coff);
    struct bpf_link *ld = bpf_program__attach_uprobe(pd, true,  pid, lib, doff);
    if (!le || !lc || !ld) { fprintf(stderr,"attach fail (le=%p lc=%p ld=%p) errno=%d\n",(void*)le,(void*)lc,(void*)ld,errno); return 1; }
    /* Request I: remaining Table tab:apis accounting points, "prog:hexoff[:ret]" comma-separated */
    const char *xa = getenv("CHAP_RS_ATTACH"); int nx = 0;
    if (xa && *xa) { char *dup = strdup(xa), *sv = 0;
        for (char *tok = strtok_r(dup, ",", &sv); tok; tok = strtok_r(0, ",", &sv)) {
            const char *path = lib; char *at = strchr(tok, '@'); if (at) { *at = 0; path = at + 1; }   /* Request J: other binary (agent.so) */
            char *c1 = strchr(tok, ':'); if (!c1) continue; *c1 = 0; char *c2 = strchr(c1 + 1, ':'); int ret = 0; if (c2) { *c2 = 0; ret = !strcmp(c2 + 1, "ret"); }
            unsigned long off = strtoul(c1 + 1, 0, 16); struct bpf_program *xp = bpf_object__find_program_by_name(o, tok);
            struct bpf_link *xl = xp ? bpf_program__attach_uprobe(xp, ret, pid, path, off) : 0;
            if (!xp || !xl || libbpf_get_error(xl)) { fprintf(stderr,"[sentinel] REQUIRED attach FAILED %s@0x%lx -> refuse\n", tok, off); return 1; }
            fprintf(stderr,"[sentinel] attached %s %s@0x%lx\n", tok, ret ? "uret" : "entry", off); nx++; }
        free(dup); }
    fprintf(stderr,"[sentinel] Request-I accounting points attached=%d\n", nx);
    {   /* Request J: per-thread gate state is cleared when a tenant thread exits */
        struct bpf_program *tp = bpf_object__find_program_by_name(o, "rs_gate_thread_exit");
        if (tp) { struct bpf_link *tl = bpf_program__attach_tracepoint(tp, "sched", "sched_process_exit");
            if (!tl || libbpf_get_error(tl)) { fprintf(stderr,"[sentinel] REQUIRED attach FAILED rs_gate_thread_exit -> refuse\n"); return 1; }
            fprintf(stderr,"[sentinel] attached rs_gate_thread_exit tracepoint sched/sched_process_exit\n"); }
        nm_fd = bpf_object__find_map_fd_by_name(o, "rs_nest_max"); }

    fprintf(stderr,"[sentinel] READY REUSE pid=%d cgid=%lu hard=%lu usage_id=%u policy_id=%u (writer create@0x%lx destroy@0x%lx)\n",
            pid, cgid, hard, usage_id, policy_id, coff, doff);
    while (!stop) pause();
    bpf_link__destroy(le); bpf_link__destroy(lc); bpf_link__destroy(ld);
    return 0;
}

// Chaperon resident Integrity Sentinel for a REAL tenant. Loads integrity_sentinel.bpf.o, attaches
// the cgroup-wide syscall tracepoint + mem_open kprobe, registers the tenant's cgroup and the
// PROTECTED memory ranges (e.g. the Agent's enforcement-hook code page + the RO policy mmap).
// Any task in the cgroup that mprotect/mmap-FIXED/mremap/... a protected range is SIGKILLed.
//   usage: integ_sentinel_run <bpf.o> <cgid> <pindir> <start:end> [start:end ...]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct prange { unsigned long start, end; };
struct ictl { unsigned int n_ranges, block_exec; };
static volatile int stop = 0;
static void on_int(int s){ (void)s; stop = 1; }

int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr,"usage: %s bpf.o cgid pindir start:end [start:end ...]\n", argv[0]); return 2; }
    const char *obj=argv[1]; unsigned long cgid=strtoul(argv[2],0,0); const char *pindir=argv[3];
    signal(SIGINT,on_int); signal(SIGTERM,on_int);

    struct bpf_object *o = bpf_object__open(obj);
    if (!o || bpf_object__load(o)) { fprintf(stderr,"load fail: %s\n", strerror(errno)); return 1; }
    int pcg = bpf_object__find_map_fd_by_name(o,"protected_cgroups");
    int rng = bpf_object__find_map_fd_by_name(o,"protected_ranges");
    int ctl = bpf_object__find_map_fd_by_name(o,"integ_ctl");

    /* attach integ_sys_enter (tracepoint) + integ_mem_open (kprobe) */
    const char *pn[3] = {"integ_sys_enter","integ_mem_open","integ_do_madvise"};
    for (int i=0;i<3;i++){ struct bpf_program *p=bpf_object__find_program_by_name(o,pn[i]);
        if (p && !bpf_program__attach(p)) fprintf(stderr,"attach warn %s\n", pn[i]); }

    unsigned char one=1; bpf_map_update_elem(pcg,&cgid,&one,BPF_ANY);     /* protect this cgroup */
    unsigned int n=0;
    for (int i=4;i<argc && n<128;i++){ char *c=strchr(argv[i],':'); if(!c) continue; *c=0;
        struct prange r={ strtoul(argv[i],0,0), strtoul(c+1,0,0) }; unsigned int k=n;
        bpf_map_update_elem(rng,&k,&r,BPF_ANY); n++;
        fprintf(stderr,"[integ] protected range[%u] = 0x%lx-0x%lx\n", k, r.start, r.end); }
    struct ictl c = { .n_ranges=n, .block_exec=0 }; unsigned int z=0; bpf_map_update_elem(ctl,&z,&c,BPF_ANY);

    char p[256];
    snprintf(p,sizeof p,"%s/protected_cgroups",pindir); bpf_obj_pin(pcg,p);
    snprintf(p,sizeof p,"%s/protected_ranges",pindir); bpf_obj_pin(rng,p);
    snprintf(p,sizeof p,"%s/integ_ctl",pindir); bpf_obj_pin(ctl,p);
    fprintf(stderr,"[integ] READY cgid=%lu ranges=%u (mprotect/pkey_mprotect/mmapFIXED/mremap/munmap/madvise+do_madvise/shmat/ptrace/execve(at)/mem_open watched)\n", cgid, n);
    while (!stop) pause();
    return 0;
}

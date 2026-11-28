// Chaperon Request P -- Manager tool for the kernel Sentinel's sealed-process registry and NIC gate (root only:
// the maps are pinned under the root-only bpffs directory and the tenant has no bpf() access).
//   chap_nicgate cfg   <pindir> on|off      uverbs fops (/proc/kallsyms) + uverbs device numbers (sysfs) -> nicgate_cfg
//   chap_nicgate seal  <pindir> <tgid>      register a sealed process (identity: tgid + /proc start time)
//   chap_nicgate unseal <pindir> <tgid>
//   chap_nicgate dump  <pindir>             sealed entries + gate counters
//   chap_nicgate put   <pindir> <tgid> <ticks>   TEST-ONLY: insert an entry with a given start time (PID-reuse test)
#include <bpf/bpf.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NG_MAXDEV 16
struct sproc { unsigned long long start_ticks; unsigned int origin, parent; unsigned long long reg_ns; };
struct ngcfg { unsigned long long fops0, fops1; unsigned int enabled, ndev; unsigned int dev[NG_MAXDEV]; };
struct ngstat { unsigned long long v[16]; };

static int pinfd(const char *dir, const char *name)
{ char p[512]; snprintf(p, sizeof p, "%s/%s", dir, name); int fd = bpf_obj_get(p); if (fd < 0) fprintf(stderr, "bpf_obj_get %s: %s\n", p, strerror(errno)); return fd; }

static int proc_start_ticks(unsigned int pid, unsigned long long *out)
{   /* /proc/<pid>/stat field 22 (starttime, clock ticks since boot); comm may contain spaces/parens */
    char p[64], b[4096]; snprintf(p, sizeof p, "/proc/%u/stat", pid);
    FILE *f = fopen(p, "r"); if (!f) return -1;
    size_t n = fread(b, 1, sizeof b - 1, f); fclose(f); b[n] = 0;
    char *r = strrchr(b, ')'); if (!r) return -1;
    int field = 2; char *tok = strtok(r + 1, " ");
    while (tok) { field++; if (field == 22) { *out = strtoull(tok, 0, 10); return 0; } tok = strtok(0, " "); }
    return -1;
}

static unsigned long long ksym(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r"); if (!f) return 0;
    char line[512]; unsigned long long a = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long long x; char t, s[256];
        if (sscanf(line, "%llx %c %255s", &x, &t, s) == 3 && !strcmp(s, name)) { a = x; break; }
    }
    fclose(f); return a;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s cfg|seal|unseal|dump|put <pindir> ...\n", argv[0]); return 2; }
    const char *cmd = argv[1], *dir = argv[2];
    if (!strcmp(cmd, "cfg")) {
        int fd = pinfd(dir, "nicgate_cfg"); if (fd < 0) return 1;
        struct ngcfg c = {0};
        c.fops0 = ksym("uverbs_fops"); c.fops1 = ksym("uverbs_mmap_fops");
        DIR *d = opendir("/sys/class/infiniband_verbs");
        struct dirent *e;
        while (d && (e = readdir(d)) && c.ndev < NG_MAXDEV) {
            if (strncmp(e->d_name, "uverbs", 6)) continue;
            char p[300]; snprintf(p, sizeof p, "/sys/class/infiniband_verbs/%s/dev", e->d_name);
            FILE *f = fopen(p, "r"); unsigned int ma, mi;
            if (f && fscanf(f, "%u:%u", &ma, &mi) == 2) c.dev[c.ndev++] = (ma << 20) | mi;   /* kernel dev_t encoding */
            if (f) fclose(f);
        }
        if (d) closedir(d);
        c.enabled = (argc > 3 && !strcmp(argv[3], "on")) ? 1 : 0;
        if (c.enabled && (!c.fops0 || !c.fops1 || !c.ndev)) { fprintf(stderr, "NICGATE_CFG FAIL fops0=%llx fops1=%llx ndev=%u\n", c.fops0, c.fops1, c.ndev); return 1; }
        unsigned int z = 0;
        if (bpf_map_update_elem(fd, &z, &c, BPF_ANY)) { perror("update nicgate_cfg"); return 1; }
        struct ngcfg rb; if (bpf_map_lookup_elem(fd, &z, &rb) || memcmp(&rb, &c, sizeof c)) { fprintf(stderr, "NICGATE_CFG readback mismatch\n"); return 1; }
        printf("NICGATE_CFG enabled=%u uverbs_fops=0x%llx uverbs_mmap_fops=0x%llx uverbs_devs=%u [", c.enabled, c.fops0, c.fops1, c.ndev);
        for (unsigned i = 0; i < c.ndev; i++) printf("%s%u:%u", i ? " " : "", c.dev[i] >> 20, c.dev[i] & 0xfffff);
        printf("]\n"); return 0;
    }
    if (!strcmp(cmd, "seal") || !strcmp(cmd, "put")) {
        if (argc < 4) return 2;
        int fd = pinfd(dir, "sealed_procs"); if (fd < 0) return 1;
        unsigned int pid = (unsigned)strtoul(argv[3], 0, 10);
        struct sproc v = {0}; struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
        v.reg_ns = (unsigned long long)ts.tv_sec * 1000000000ull + ts.tv_nsec; v.origin = 1;
        if (!strcmp(cmd, "put")) { if (argc < 5) return 2; v.start_ticks = strtoull(argv[4], 0, 10); v.origin = 9; }
        else if (proc_start_ticks(pid, &v.start_ticks)) { fprintf(stderr, "SEAL FAIL pid %u not found\n", pid); return 1; }
        if (bpf_map_update_elem(fd, &pid, &v, BPF_ANY)) { perror("update sealed_procs"); return 1; }
        if (!strcmp(cmd, "seal")) {   /* TOCTOU guard: the same process must still exist after the write */
            unsigned long long t2 = 0;
            if (proc_start_ticks(pid, &t2) || t2 != v.start_ticks) { bpf_map_delete_elem(fd, &pid); fprintf(stderr, "SEAL FAIL pid %u changed during registration\n", pid); return 1; }
        }
        struct sproc rb; if (bpf_map_lookup_elem(fd, &pid, &rb) || rb.start_ticks != v.start_ticks) { fprintf(stderr, "SEAL readback mismatch\n"); return 1; }
        printf("%s pid=%u start_ticks=%llu origin=%u\n", !strcmp(cmd, "seal") ? "SEALED" : "PUT", pid, rb.start_ticks, rb.origin); return 0;
    }
    if (!strcmp(cmd, "unseal")) {
        if (argc < 4) return 2;
        int fd = pinfd(dir, "sealed_procs"); if (fd < 0) return 1;
        unsigned int pid = (unsigned)strtoul(argv[3], 0, 10);
        int r = bpf_map_delete_elem(fd, &pid); printf("UNSEAL pid=%u %s\n", pid, r ? strerror(errno) : "ok"); return r ? 1 : 0;
    }
    if (!strcmp(cmd, "dump")) {
        int fd = pinfd(dir, "sealed_procs"), sf = pinfd(dir, "nicgate_stats"); if (fd < 0 || sf < 0) return 1;
        unsigned int k, nk; int first = 1, n = 0;
        while (!bpf_map_get_next_key(fd, first ? NULL : &k, &nk)) {
            first = 0; k = nk; struct sproc v;
            if (!bpf_map_lookup_elem(fd, &k, &v)) { printf("ENTRY pid=%u start_ticks=%llu origin=%u parent=%u\n", k, v.start_ticks, v.origin, v.parent); n++; }
        }
        long nc = sysconf(_SC_NPROCESSORS_CONF); struct ngstat *pc = calloc(nc, sizeof *pc); unsigned int z = 0;
        unsigned long long t[16] = {0};
        if (!bpf_map_lookup_elem(sf, &z, pc)) for (long c = 0; c < nc; c++) for (int i = 0; i < 16; i++) t[i] += pc[c].v[i];
        printf("NICGATE_STATS entries=%d allow{open=%llu ioctl=%llu ioctl32=%llu mmap=%llu write=%llu} deny{open=%llu ioctl=%llu ioctl32=%llu mmap=%llu write=%llu} fork_inherit=%llu exec_unseal=%llu exit_clear=%llu stale_removed=%llu\n",
               n, t[2], t[4], t[6], t[8], t[10], t[3], t[5], t[7], t[9], t[11], t[12], t[13], t[14], t[15]);
        return 0;
    }
    fprintf(stderr, "unknown command %s\n", cmd); return 2;
}

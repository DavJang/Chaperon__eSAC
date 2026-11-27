// Chaperon: register MANY protected ranges (from esac_seal's /tmp/esac_seal_ranges_<pid>.txt) into a
// running Integrity Sentinel's pinned protected_ranges + integ_ctl. Each line: "<hexstart> <hexend>".
// Optionally appends an extra range (the kernel-hook code segment) at the end.
// review fix #4: if more ranges are registered than the Sentinel can check (INTEG_MAXR=128), REFUSE
// (return non-zero) instead of silently dropping -- the launch must then refuse, not run unprotected.
//   usage: integ_setranges <ranges_pin> <ctl_pin> <ranges_file> [extra_start_hex extra_end_hex [block_exec]]
// Request I: block_exec=1 (set by the Manager at GO, after the launcher's own exec) kills any later execve/execveat.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#define INTEG_MAXR 128u   /* Request I: was 64 */
struct prange { unsigned long start, end; };
struct ictl { unsigned int n_ranges, block_exec; };
int main(int argc, char **argv)
{
    if (argc < 4) { fprintf(stderr,"usage: %s ranges_pin ctl_pin ranges_file [xstart xend]\n", argv[0]); return 2; }
    int rng = bpf_obj_get(argv[1]); int ctl = bpf_obj_get(argv[2]);
    if (rng < 0 || ctl < 0) { fprintf(stderr,"obj_get fail rng=%d ctl=%d: %s\n", rng, ctl, strerror(errno)); return 1; }
    FILE *f = fopen(argv[3], "r");
    unsigned int n = 0; char line[256];
    if (f) {
        while (fgets(line, sizeof line, f)) {
            unsigned long s=0, e=0;
            if (sscanf(line, "%lx %lx", &s, &e) == 2 && e > s) {
                if (n >= INTEG_MAXR) { fprintf(stderr,"[setranges] REFUSE: >%u ranges exceeds Sentinel support limit\n", INTEG_MAXR); fclose(f); return 2; }
                struct prange r = { s, e }; unsigned int k = n;
                if (bpf_map_update_elem(rng, &k, &r, 0) == 0) {
                    fprintf(stderr,"[setranges] range[%u]=0x%lx-0x%lx (sealed)\n", k, s, e); n++;
                }
            }
        }
        fclose(f);
    } else fprintf(stderr,"[setranges] no ranges file %s (0 sealed ranges)\n", argv[3]);
    if (argc >= 6) {
        unsigned long s = strtoul(argv[4],0,16), e = strtoul(argv[5],0,16);
        if (e > s) {
            if (n >= INTEG_MAXR) { fprintf(stderr,"[setranges] REFUSE: hook-seg range would exceed limit %u\n", INTEG_MAXR); return 2; }
            struct prange r = { s, e }; unsigned int k = n;
            if (bpf_map_update_elem(rng, &k, &r, 0) == 0) { fprintf(stderr,"[setranges] range[%u]=0x%lx-0x%lx (hook code seg)\n", k, s, e); n++; }
        }
    }
    unsigned int bx = (argc >= 7) ? (unsigned int)atoi(argv[6]) : 0u;
    struct ictl c = { .n_ranges = n, .block_exec = bx }; unsigned int z = 0;
    if (bpf_map_update_elem(ctl, &z, &c, 0)) { fprintf(stderr,"ctl update fail: %s\n", strerror(errno)); return 1; }
    fprintf(stderr,"[setranges] TOTAL n_ranges=%u registered (<= %u) block_exec=%u\n", n, INTEG_MAXR, bx);
    return n > 0 ? 0 : 1;
}

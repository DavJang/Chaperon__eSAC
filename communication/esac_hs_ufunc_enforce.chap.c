/* esac_hs_ufunc.so -- Hyperscan payload-scan provider for eSAC + RO hardening.
 *
 * Hardening (so the tenant cannot tamper the L7 patterns):
 *   (1) the compiled Hyperscan DB is placed on page-aligned memory and
 *       mprotect()'d READ-ONLY after compile.
 *   (2) the state pointers (db, scratch_proto) live in a dedicated page-aligned
 *       struct that is also mprotect()'d READ-ONLY after init -> the db pointer
 *       itself cannot be NULLed/forged. (Isolated to its own page so RO'ing it
 *       does NOT touch .data the C runtime needs at exit.)
 * Scratch stays RW (per-scan). TamperSentinel catches mprotect/proc-self-mem bypass.
 *
 * build: gcc -shared -fPIC -O2 esac_hs_ufunc.c -o esac_hs_ufunc.so -lhs
 */
#define _GNU_SOURCE
#include <hs/hs.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE 4096UL
static int g_stats_on = 0;   /* ESAC_HS_STATS=1 enables the periodic stats line (stderr write) */
static unsigned long pdown(unsigned long a){ return a & ~(PAGE-1); }
static unsigned long pup(unsigned long a){ return (a + PAGE - 1) & ~(PAGE-1); }

/* ---- protected state: its own page, RO'd after init ---- */
/* Request I: per-rule action/scope. Rules written with an explicit action ("allow ..." / "drop ...") get ids
 * 0..nmeta-1 and an entry here; bare legacy rules get ids >= nmeta and mean "drop, any scope" (deny-list).
 * The table lives in the same page as the DB pointers, which is RO after init and registered with the
 * Tamper Sentinel (hs_state), so a tenant cannot flip a rule's action. */
#define HS_MAXMETA 960
#define HS_MAXSVC  16
struct hs_rule { unsigned char act, proto; unsigned short port; };      /* act 0 drop / 1 allow; port 0 = any */
struct hs_state {
    hs_database_t *db;
    hs_scratch_t  *scratch_proto;
    unsigned long  db_ro_base;
    unsigned long  db_ro_len;
    unsigned int   nmeta, nsvc;
    struct { unsigned char proto; unsigned char pad; unsigned short port; } svc[HS_MAXSVC];   /* allow-listed services */
    struct hs_rule meta[HS_MAXMETA];
};
_Static_assert(sizeof(struct hs_state) <= 4096, "hs_state must fit its RO page");
static union { struct hs_state s; char pad[PAGE]; }
    g_sp __attribute__((aligned(4096)));
#define g_db            (g_sp.s.db)
#define g_scratch_proto (g_sp.s.scratch_proto)
#define g_db_ro_base    (g_sp.s.db_ro_base)
#define g_db_ro_len     (g_sp.s.db_ro_len)

static __thread hs_scratch_t *t_scratch = NULL;
/* review #3: explicit init state so DB/scratch failure is NOT silently treated as no-L7. */
enum { HS_NOT_CONFIGURED=0, HS_OK=1, HS_FAILED=2 };
static int g_init_state = HS_NOT_CONFIGURED;
int esac_hs_init_failed(void){ return g_init_state == HS_FAILED; }
int esac_hs_init_ok(void){ return g_init_state == HS_OK; }
   /* per-thread, stays RW (TLS) */

/* page-aligned allocator used ONLY for the HS database (so it can be RO'd). */
#define MAXDB 64
static struct { void *base; size_t len; } g_dba[MAXDB];
static int g_ndba = 0;
static void *db_alloc(size_t n){
    size_t len = pup(n ? n : 1);
    void *p = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (g_ndba < MAXDB) { g_dba[g_ndba].base = p; g_dba[g_ndba].len = len; g_ndba++; }
    return p;
}
static void db_free(void *p){
    if (!p) return;
    for (int i = 0; i < g_ndba; i++) if (g_dba[i].base == p) { munmap(p, g_dba[i].len); g_dba[i].base = NULL; return; }
}

struct mctx { int drop, allow; unsigned char proto; unsigned short port; };
static int on_match(unsigned int id, unsigned long long from,
                    unsigned long long to, unsigned int flags, void *ctx)
{
    (void)from;(void)to;(void)flags; struct mctx *m = ctx;
    if (id >= g_sp.s.nmeta) { m->drop = 1; return 1; }                   /* legacy rule: drop, any scope */
    const struct hs_rule *r = &g_sp.s.meta[id];
    if (r->port && !(r->proto == m->proto && r->port == m->port)) return 0;   /* rule of another service */
    if (r->act == 0) { m->drop = 1; return 1; }                           /* DROP decided: stop scanning */
    m->allow = 1; return 0;                                               /* ALLOW: keep looking for a DROP */
}
static int svc_of(unsigned char proto, unsigned short port)
{ for (unsigned i = 0; i < g_sp.s.nsvc; i++) if (g_sp.s.svc[i].proto == proto && g_sp.s.svc[i].port == port) return (int)i; return -1; }
/* "[allow|drop] [tcp/<port>|udp/<port>] <regex>" (regex may be written /.../). Returns 0 legacy, 1 explicit, -1 bad. */
static int parse_rule(char *line, struct hs_rule *r, char **re)
{
    char *p = line; r->act = 0; r->proto = 0; r->port = 0; int expl = 0;
    if (!strncmp(p, "allow ", 6)) { r->act = 1; p += 6; expl = 1; } else if (!strncmp(p, "drop ", 5)) { p += 5; expl = 1; }
    while (*p == ' ') p++;
    if (expl && (!strncmp(p, "tcp/", 4) || !strncmp(p, "udp/", 4))) {
        r->proto = (p[0] == 't') ? 6 : 17; char *e; long port = strtol(p + 4, &e, 10);
        if (port <= 0 || port > 65535 || *e != ' ') return -1;
        r->port = (unsigned short)port; p = e; while (*p == ' ') p++;
    }
    if (r->act == 1 && !r->port) return -1;                               /* an allow rule needs its service */
    size_t n = strlen(p); if (n >= 2 && p[0] == '/' && p[n - 1] == '/') { p[n - 1] = 0; p++; }
    if (!*p) return -1;
    *re = p; return expl;
}

__attribute__((constructor))
static void esac_hs_init(void)
{
    char **pats = NULL; unsigned n = 0, cap = 0;
    { const char *st = getenv("ESAC_HS_STATS"); g_stats_on = (st && st[0] == '1'); }   /* Request G: stats print is debug-only */
    const char *env = getenv("ESAC_HS_PATTERNS");
    FILE *pf = (env && *env) ? fopen(env, "r") : NULL;
    if (pf) {
        char line[512];
        while (fgets(line, sizeof(line), pf)) {
            size_t ln = strlen(line);
            while (ln && (line[ln-1]=='\n'||line[ln-1]=='\r'||line[ln-1]==' '||line[ln-1]=='\t')) line[--ln]=0;
            if (ln==0 || line[0]=='#') continue;
            if (n >= cap) { cap = cap ? cap*2 : 1024; pats = realloc(pats, cap*sizeof(char*)); }
            pats[n++] = strdup(line);
        }
        fclose(pf);
        fprintf(stderr, "[esac_hs] loaded %u patterns from file %s\n", n, env);
    } else if (env && *env) {
        char *dup = strdup(env);
        for (char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
            if (n >= cap) { cap = cap ? cap*2 : 8; pats = realloc(pats, cap*sizeof(char*)); }
            pats[n++] = strdup(tok);
        }
        free(dup);
    } else {
        static const char *def[] = { "evil", "malware", "phishing", "baddomain" };
        n = 4; pats = malloc(n*sizeof(char*));
        for (unsigned i=0;i<n;i++) pats[i] = strdup(def[i]);
    }
    if (n == 0) { fprintf(stderr, "[esac_hs] no patterns (L7 not configured)\n"); g_init_state = HS_NOT_CONFIGURED; return; }
    /* Request I: explicit rules first (ids 0..nmeta-1, with action/scope), then legacy deny rules */
    { char **ord = malloc(n * sizeof(char *)); unsigned no = 0, nm = 0, nallow = 0;
      for (int pass = 0; pass < 2; pass++)
        for (unsigned i = 0; i < n; i++) {
            struct hs_rule r; char *re = NULL; char *cp = strdup(pats[i]); int k = parse_rule(cp, &r, &re);
            if (k < 0) { fprintf(stderr, "[esac_hs] bad rule '%s' -> HS_FAILED (fail-closed)\n", pats[i]); g_init_state = HS_FAILED; return; }
            if ((pass == 0) != (k == 1)) { free(cp); continue; }
            if (k == 1) {
                if (nm >= HS_MAXMETA) { fprintf(stderr, "[esac_hs] >%d explicit rules -> HS_FAILED\n", HS_MAXMETA); g_init_state = HS_FAILED; return; }
                g_sp.s.meta[nm++] = r;
                if (r.act == 1) { nallow++;
                    int f = 0; for (unsigned s = 0; s < g_sp.s.nsvc; s++) if (g_sp.s.svc[s].proto == r.proto && g_sp.s.svc[s].port == r.port) f = 1;
                    if (!f) { if (g_sp.s.nsvc >= HS_MAXSVC) { fprintf(stderr, "[esac_hs] >%d services -> HS_FAILED\n", HS_MAXSVC); g_init_state = HS_FAILED; return; }
                              g_sp.s.svc[g_sp.s.nsvc].proto = r.proto; g_sp.s.svc[g_sp.s.nsvc].port = r.port; g_sp.s.nsvc++; } }
            }
            ord[no++] = strdup(re); free(cp);
        }
      g_sp.s.nmeta = nm; free(pats); pats = ord; n = no;
      fprintf(stderr, "[esac_hs] rules: %u explicit (%u allow, %u allow-listed services), %u legacy deny\n", nm, nallow, g_sp.s.nsvc, n - nm);
      for (unsigned s = 0; s < g_sp.s.nsvc; s++) fprintf(stderr, "[esac_hs] allow-listed service %s/%u: unmatched payload -> DROP\n", g_sp.s.svc[s].proto == 6 ? "tcp" : "udp", g_sp.s.svc[s].port); }

    unsigned *ids = malloc(n*sizeof(unsigned)), *flags = malloc(n*sizeof(unsigned));
    for (unsigned i=0;i<n;i++){ ids[i]=i; flags[i]=HS_FLAG_DOTALL|HS_FLAG_SINGLEMATCH; }

    hs_set_database_allocator(db_alloc, db_free);   /* DB on page-aligned mem */

    hs_compile_error_t *err = NULL;
    if (hs_compile_multi((const char*const*)pats, flags, ids, n, HS_MODE_BLOCK, NULL, &g_db, &err) != HS_SUCCESS) {
        fprintf(stderr, "[esac_hs] compile FAILED: %s -> HS_FAILED (fail-closed)\n", err?err->message:"?");
        hs_free_compile_error(err); g_init_state = HS_FAILED; return;
    }
    if (hs_alloc_scratch(g_db, &g_scratch_proto) != HS_SUCCESS) {
        fprintf(stderr, "[esac_hs] scratch alloc FAILED -> HS_FAILED (fail-closed)\n"); g_init_state = HS_FAILED; return;
    }

    /* (1) RO the compiled DB */
    size_t dbsz = 0;
    if (hs_database_size(g_db, &dbsz) == HS_SUCCESS) {
        unsigned long base = pdown((unsigned long)g_db);
        unsigned long len  = pup(((unsigned long)g_db - base) + dbsz);
        if (mprotect((void*)base, len, PROT_READ) == 0) { g_db_ro_base = base; g_db_ro_len = len; }
    }
    /* (2) RO the state page (db / scratch_proto pointers) -- own page, safe */
    int sp_ro = (mprotect(&g_sp, PAGE, PROT_READ) == 0);
    fprintf(stderr, "[esac_hs] compiled %u patterns, DB RO @ %lx(%zuB), state-page RO=%d\n",
            n, g_db_ro_base, dbsz, sp_ro);
    g_init_state = HS_OK;
}

/* RO'd DB range + state-page address (for verification / tamper_sentinel) */
void esac_hs_db_region(void **addr, unsigned long *len){ if(addr)*addr=(void*)g_db_ro_base; if(len)*len=g_db_ro_len; }
void *esac_hs_dbptr_addr(void){ return (void*)&g_db; }

/* batch-aware: gate calls esac_hs_scan(&item[0], n); scan each real payload. */
struct esac_hs_item { uint64_t pl_ptr; uint32_t pl_len; uint32_t act; uint32_t meta; uint32_t rsv; };   /* Request I: meta = class | proto<<8 | dport<<16 */
static unsigned long g_calls=0,g_pkts=0,g_bytes=0,g_matches=0;
static int g_match_act=-1; /* verdict written to item.act on match (ENFORCE path) */
uint64_t esac_hs_scan(const void *batch, uint32_t count)
{
    struct esac_hs_item *items = (struct esac_hs_item *)batch;
    if (!batch || count == 0) return 0;
    if (count > 128u) count = 128u;
    if (g_match_act<0){const char*e=getenv("ESAC_MATCH_ACT"); g_match_act = e?atoi(e):2;}
    const uint32_t FAILCLOSED = 2u; /* DROP */
    /* review #3: L7 configured but init FAILED -> fail-closed DROP for every inspected payload. */
    if (g_init_state == HS_FAILED) {
        for (uint32_t i = 0; i < count; i++) if (items[i].pl_ptr && items[i].pl_len) items[i].act = FAILCLOSED;
        return count;
    }
    /* NOT_CONFIGURED (no L7 patterns) -> no inspection; leave the L4 verdict untouched. */
    if (g_init_state != HS_OK || !g_db) return 0;
    if (!t_scratch) { if (hs_clone_scratch(g_scratch_proto, &t_scratch) != HS_SUCCESS) {
        /* scratch clone failure is a scan ERROR, not NOMATCH -> fail-closed */
        for (uint32_t i = 0; i < count; i++) if (items[i].pl_ptr && items[i].pl_len) items[i].act = FAILCLOSED;
        return count; } }
    uint64_t total = 0;
    for (uint32_t i = 0; i < count; i++) {
        const char *pl = (const char *)(uintptr_t)items[i].pl_ptr;
        uint32_t len = items[i].pl_len;
        if (!pl || len == 0) continue;
        uint32_t meta = items[i].meta; unsigned char proto = (meta >> 8) & 0xff; unsigned short dport = (unsigned short)(meta >> 16);
        int svc = svc_of(proto, dport);
        if (svc < 0 && (meta & 0xff) == 0) continue;           /* no content class, not an allow-listed service: L4 verdict */
        struct mctx m = { 0, 0, proto, dport };
        hs_error_t rc = hs_scan(g_db, pl, len, 0, t_scratch, on_match, &m);
        if (rc != HS_SUCCESS && rc != HS_SCAN_TERMINATED) {   /* scan ERROR != NOMATCH -> fail-closed */
            items[i].act = FAILCLOSED; continue;
        }
        int matched = m.drop;
        total += (uint64_t)matched;
        if (matched) items[i].act = (uint32_t)g_match_act;    /* DROP rule matched -> verdict */
        else if (svc >= 0 && !m.allow) items[i].act = FAILCLOSED;   /* allow-listed service, no allow rule matched -> DROP */
        g_pkts++; g_bytes += len; g_matches += (unsigned)matched;
    }
    if ((g_calls++ % 4096ul) == 0 && g_stats_on)
        fprintf(stderr, "[esac_hs-enf] call#%lu pkts=%lu bytes=%lu matches=%lu lastlen=%u\n", g_calls, g_pkts, g_bytes, g_matches, (unsigned)(count?items[count-1].pl_len:0));
    return total;
}

/* item-6: publish L7 provider init status so the Manager refuses launch on L7-init-failure. */
__attribute__((constructor))
static void chap_hs_write_initmarker(void){
    char p[80]; snprintf(p, sizeof p, "/tmp/chap_hs_init_%d", (int)getpid());
    FILE *f = fopen(p, "w");
    if (f) { fputs(g_init_state==HS_OK ? "OK\n" : (g_init_state==HS_FAILED ? "FAIL\n" : "NOT_CONFIGURED\n"), f); fclose(f); }
}

/* Request E: HS state page (db + scratch-proto pointers, RO after init) for Tamper-Sentinel registration. */
void esac_hs_state_region(void **addr, unsigned long *len)
{ if (g_init_state != HS_OK) { if (addr) *addr = 0; if (len) *len = 0; return; }
  if (addr) *addr = (void *)&g_sp; if (len) *len = PAGE; }


/* Request I (Launch quota): native helper for the Agent's rte_eal_init pre-check. Parses the EAL arguments
 * the application passes: -l/--lcores (list, ranges), -c (hex mask), -m / --socket-mem / --socket-limit (MB).
 * No lcore option => EAL uses every online CPU. Anything it cannot parse sets err (Agent denies, fail-closed). */
#include <stdint.h>
#include <unistd.h>
struct chap_eal_req { uint64_t lcores, mem_mb, mask_lo, mask_hi, err; };
static void chap_lc(struct chap_eal_req *r, long c) { if (c < 0 || c > 127) { r->err = 1; return; } if (c < 64) r->mask_lo |= 1ull << c; else r->mask_hi |= 1ull << (c - 64); }
static void chap_lcore_list(struct chap_eal_req *r, const char *v)
{
    while (v && *v) {
        if (*v < '0' || *v > '9') { r->err = 1; return; }
        char *e; long a = strtol(v, &e, 10), b = a;
        if (*e == '-') { b = strtol(e + 1, &e, 10); }
        if (b < a || b - a > 127) { r->err = 1; return; }
        for (long c = a; c <= b; c++) chap_lc(r, c);
        if (*e == ',') e++; else if (*e) { r->err = 1; return; }
        v = e;
    }
}
static uint64_t chap_mb_list(const char *v) { uint64_t t = 0; while (v && *v) { char *e; t += strtoull(v, &e, 10); if (*e == ',') e++; else break; v = e; } return t; }
uint64_t chap_eal_args(uint64_t argc, uint64_t argv_p, uint64_t out_p)
{
    struct chap_eal_req *r = (struct chap_eal_req *)out_p; char **argv = (char **)argv_p;
    if (!r) return (uint64_t)-1; memset(r, 0, sizeof *r);
    int have_lc = 0;
    for (int i = 1; i < (int)argc && argv && argv[i]; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) break;
        const char *nx = (i + 1 < (int)argc) ? argv[i + 1] : 0;
        if (!strcmp(a, "-l") || !strcmp(a, "--lcores")) { if (!nx) { r->err = 1; break; } chap_lcore_list(r, nx); have_lc = 1; i++; }
        else if (!strncmp(a, "-l", 2) && a[2]) { chap_lcore_list(r, a + 2); have_lc = 1; }
        else if (!strncmp(a, "--lcores=", 9)) { chap_lcore_list(r, a + 9); have_lc = 1; }
        else if (!strcmp(a, "-c") || (!strncmp(a, "-c", 2) && a[2])) {
            const char *v = a[2] ? a + 2 : nx; if (!v) { r->err = 1; break; } if (!a[2]) i++;
            unsigned long long m = strtoull(v, 0, 16); for (int c = 0; c < 64; c++) if ((m >> c) & 1) chap_lc(r, c); have_lc = 1; }
        else if (!strcmp(a, "-m")) { if (!nx) { r->err = 1; break; } r->mem_mb = strtoull(nx, 0, 10); i++; }
        else if (!strcmp(a, "--socket-mem") || !strcmp(a, "--socket-limit")) { if (!nx) { r->err = 1; break; } uint64_t t = chap_mb_list(nx); if (t > r->mem_mb) r->mem_mb = t; i++; }
        else if (!strncmp(a, "--socket-mem=", 13)) { uint64_t t = chap_mb_list(a + 13); if (t > r->mem_mb) r->mem_mb = t; }
    }
    if (!have_lc) { long n = sysconf(_SC_NPROCESSORS_ONLN); for (long c = 0; c < n && c < 128; c++) chap_lc(r, c); }
    r->lcores = (uint64_t)__builtin_popcountll(r->mask_lo) + (uint64_t)__builtin_popcountll(r->mask_hi);
    return 0;
}

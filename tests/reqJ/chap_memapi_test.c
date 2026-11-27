// Chaperon Request J -- TEST-ONLY tenant-side driver of DPDK memory API calls (never part of a normal launch).
// Preloaded into the tenant only when the harness runs MEMJ tests (CHAP_MEMAPI_TEST=1); otherwise inert.
// A thread named "chap-memapi" waits for command lines in /tmp/chap_memapi_cmd_<pid> (written by the Manager)
// and issues the calls exactly as application code would (public API through the hooked entries):
//   malloc N SIZE GAP_US FREE   N x rte_malloc(SIZE) (FREE=1: rte_free right after, holdings stay flat)
//   pool N                      rte_pktmbuf_pool_create(N mbufs) + rte_mempool_free (nested allocations)
//   par2 N SIZE CPU_A CPU_B     two threads pinned to two CPUs, N x (rte_malloc + rte_free) each, started together
//   forge R N SIZE              ATTACK: R rounds of { call agent.so chap_res_gate_enter directly (class NIC, API
//                               rte_eth_dev_start; offset from CHAP_MEMAPI_GATE_OFF), then N x (rte_malloc + rte_free) }
//   devrestart P MS             one rte_malloc/rte_free, then rte_eth_dev_stop(P) + rte_eth_dev_start(P) at once,
//                               and rte_eth_dev_start(P) again after MS ms
// Results (unbuffered, one write per line): $CHAP_MEMAPI_DIR/memapi_out.txt
//   "CALL <i> begin" / "CALL <i> ok|null" for N <= 64, and "RESULT <cmd> ok=.. null=.." per command.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef void *(*malloc_fn)(const char *, size_t, unsigned);
typedef void (*free_fn)(void *);
typedef void *(*pool_fn)(const char *, unsigned, unsigned, uint16_t, uint16_t, int);
typedef void (*mpfree_fn)(void *);
static malloc_fn p_malloc; static free_fn p_free; static pool_fn p_pool; static mpfree_fn p_mpfree;
static char g_out[512], g_cmd[128];
static uintptr_t g_agent_base;
static int find_agent(struct dl_phdr_info *i, size_t sz, void *d)
{ (void)sz; (void)d; const char *n = i->dlpi_name; size_t l = n ? strlen(n) : 0;
  if (l >= 8 && !strcmp(n + l - 8, "agent.so")) { g_agent_base = i->dlpi_addr; return 1; } return 0; }

static void outl(const char *fmt, ...)
{
    char b[256]; va_list ap; va_start(ap, fmt); int n = vsnprintf(b, sizeof b - 1, fmt, ap); va_end(ap);
    if (n < 0) return; if (n > (int)sizeof b - 2) n = sizeof b - 2; b[n++] = '\n';
    int fd = open(g_out, O_WRONLY | O_CREAT | O_APPEND, 0644); if (fd >= 0) { if (write(fd, b, n) < 0) {} close(fd); }
}
static uint64_t now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec; }

struct par { int cpu, n; size_t size; volatile int *go; long ok, nul; };
static void *par_worker(void *a)
{
    struct par *p = a; cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(p->cpu, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof cs, &cs); pthread_setname_np(pthread_self(), "chap-memapi");
    while (!*p->go) __asm__ __volatile__("pause");
    for (int i = 0; i < p->n; i++) { void *m = p_malloc("chapt", p->size, 0); if (m) { p->ok++; p_free(m); } else p->nul++; }
    return 0;
}
static void run(char *line)
{
    char op[16] = ""; long a = 0, b = 0, c = 0, d = 0;
    int k = sscanf(line, "%15s %ld %ld %ld %ld", op, &a, &b, &c, &d); if (k < 1) return;
    if (!strcmp(op, "malloc")) {
        long ok = 0, nul = 0; uint64_t t0 = now_ns();
        for (long i = 0; i < a; i++) {
            if (a <= 64) outl("CALL %ld begin", i);
            void *m = p_malloc("chapt", (size_t)b, 0);
            if (m) ok++; else nul++;
            if (a <= 64) outl("CALL %ld %s", i, m ? "ok" : "null");
            if (m && d) p_free(m);
            if (c > 0) usleep((useconds_t)c);
        }
        outl("RESULT malloc n=%ld size=%ld free=%ld ok=%ld null=%ld t0_ns=%llu dt_us=%llu", a, b, d, ok, nul, (unsigned long long)t0, (unsigned long long)((now_ns() - t0) / 1000));
    } else if (!strcmp(op, "pool")) {
        char nm[32]; snprintf(nm, sizeof nm, "chapt_pool_%ld", (long)(now_ns() % 100000));
        uint64_t t0 = now_ns(); void *mp = p_pool(nm, (unsigned)a, 0, 0, 2176, 0);
        outl("RESULT pool n=%ld %s t0_ns=%llu", a, mp ? "ok" : "null", (unsigned long long)t0);
        if (mp) p_mpfree(mp);
    } else if (!strcmp(op, "api")) {     /* one outermost call of one memory API (and its release) */
        char which[24] = ""; sscanf(line, "%*s %23s", which); void *r = 0; char nm[32]; snprintf(nm, sizeof nm, "chapt_%s_%ld", which, (long)(now_ns() % 100000));
        if (!strcmp(which, "malloc")) { r = p_malloc("chapt", 128, 0); if (r) p_free(r); }
        else if (!strcmp(which, "zmalloc")) { void *(*f)(const char *, size_t, unsigned) = dlsym(RTLD_DEFAULT, "rte_zmalloc"); r = f ? f("chapt", 128, 0) : 0; if (r) p_free(r); }
        else if (!strcmp(which, "calloc")) { void *(*f)(const char *, size_t, size_t, unsigned) = dlsym(RTLD_DEFAULT, "rte_calloc"); r = f ? f("chapt", 4, 32, 0) : 0; if (r) p_free(r); }
        else if (!strcmp(which, "malloc_socket")) { void *(*f)(const char *, size_t, unsigned, int) = dlsym(RTLD_DEFAULT, "rte_malloc_socket"); r = f ? f("chapt", 128, 0, 0) : 0; if (r) p_free(r); }
        else if (!strcmp(which, "zmalloc_socket")) { void *(*f)(const char *, size_t, unsigned, int) = dlsym(RTLD_DEFAULT, "rte_zmalloc_socket"); r = f ? f("chapt", 128, 0, 0) : 0; if (r) p_free(r); }
        else if (!strcmp(which, "memzone")) { void *(*f)(const char *, size_t, int, unsigned) = dlsym(RTLD_DEFAULT, "rte_memzone_reserve"); int (*fr)(const void *) = dlsym(RTLD_DEFAULT, "rte_memzone_free");
                                               r = f ? f(nm, 65536, 0, 0) : 0; if (r && fr) fr(r); }
        else if (!strcmp(which, "memzone_aligned")) { void *(*f)(const char *, size_t, int, unsigned, unsigned) = dlsym(RTLD_DEFAULT, "rte_memzone_reserve_aligned"); int (*fr)(const void *) = dlsym(RTLD_DEFAULT, "rte_memzone_free");
                                               r = f ? f(nm, 65536, 0, 0, 4096) : 0; if (r && fr) fr(r); }
        else if (!strcmp(which, "mempool")) { void *(*f)(const char *, unsigned, unsigned, unsigned, unsigned, void *, void *, void *, void *, int, unsigned) = dlsym(RTLD_DEFAULT, "rte_mempool_create");
                                               r = f ? f(nm, 255, 128, 0, 0, 0, 0, 0, 0, 0, 0) : 0; if (r) p_mpfree(r);
                                               if (!r) { int *e = dlsym(RTLD_DEFAULT, "per_lcore__rte_errno"); outl("NOTE mempool rte_errno=%d", e ? *e : -1); } }
        else if (!strcmp(which, "pktmbuf_pool")) { r = p_pool(nm, 255, 0, 0, 2176, 0); if (r) p_mpfree(r); }
        outl("RESULT api %s %s", which, r ? "ok" : "null");
    } else if (!strcmp(op, "forge")) {   /* TEST-ONLY attack: an outer call that never reaches an original */
        const char *off = getenv("CHAP_MEMAPI_GATE_OFF"); if (!g_agent_base) dl_iterate_phdr(find_agent, 0);
        if (!off || !g_agent_base) { outl("RESULT forge error base=%lx off=%s", (unsigned long)g_agent_base, off ? off : "-"); return; }
        void (*ge)(uint64_t, uint64_t, uint64_t) = (void (*)(uint64_t, uint64_t, uint64_t))(g_agent_base + strtoull(off, 0, 16));
        long ok = 0, nul = 0, idx = 0; uint64_t t0 = now_ns();
        for (long r = 0; r < a; r++) {
            outl("ROUND %ld forge", r); ge(0, (14u << 8) | 4u, 0);          /* forged: class NIC (4), API rte_eth_dev_start (14) */
            for (long i = 0; i < b; i++, idx++) { outl("CALL %ld begin", idx); void *m = p_malloc("chapt", (size_t)c, 0); if (m) { ok++; p_free(m); } else nul++; }
        }
        outl("RESULT forge rounds=%ld n=%ld size=%ld ok=%ld null=%ld t0_ns=%llu dt_us=%llu", a, b, c, ok, nul, (unsigned long long)t0, (unsigned long long)((now_ns() - t0) / 1000));
    } else if (!strcmp(op, "devrestart")) {
        int (*stop)(uint16_t) = dlsym(RTLD_DEFAULT, "rte_eth_dev_stop"); int (*start)(uint16_t) = dlsym(RTLD_DEFAULT, "rte_eth_dev_start");
        if (!stop || !start) { outl("RESULT devrestart error dlsym"); return; }
        void *m = p_malloc("chapt", 64, 0); if (m) p_free(m);
        int rs = stop((uint16_t)a); int r1 = start((uint16_t)a);
        usleep((useconds_t)(b * 1000)); int r2 = start((uint16_t)a);
        outl("RESULT devrestart port=%ld malloc=%s stop=%d start1=%d start2=%d", a, m ? "ok" : "null", rs, r1, r2);
    } else if (!strcmp(op, "par2")) {
        volatile int go = 0; struct par x = { (int)c, (int)a, (size_t)b, &go, 0, 0 }, y = { (int)d, (int)a, (size_t)b, &go, 0, 0 };
        pthread_t tx, ty; pthread_create(&tx, 0, par_worker, &x); pthread_create(&ty, 0, par_worker, &y);
        usleep(100000); uint64_t t0 = now_ns(); go = 1; pthread_join(tx, 0); pthread_join(ty, 0);
        outl("RESULT par2 n=%ld size=%ld ok=%ld null=%ld cpus=%ld,%ld t0_ns=%llu dt_us=%llu", a, b, x.ok + y.ok, x.nul + y.nul, c, d, (unsigned long long)t0, (unsigned long long)((now_ns() - t0) / 1000));
    }
}
static void *driver(void *arg)
{
    (void)arg; pthread_setname_np(pthread_self(), "chap-memapi");
    off_t done = 0; char buf[4096];
    for (;;) {
        int fd = open(g_cmd, O_RDONLY);
        if (fd >= 0) {
            off_t sz = lseek(fd, 0, SEEK_END);
            if (sz > done) {
                lseek(fd, done, SEEK_SET); ssize_t n = read(fd, buf, sizeof buf - 1);
                if (n > 0) { buf[n] = 0; char *e = strrchr(buf, '\n');
                    if (e) { *e = 0; done += (e - buf) + 1;
                        if (!p_malloc) { p_malloc = (malloc_fn)dlsym(RTLD_DEFAULT, "rte_malloc"); p_free = (free_fn)dlsym(RTLD_DEFAULT, "rte_free");
                                         p_pool = (pool_fn)dlsym(RTLD_DEFAULT, "rte_pktmbuf_pool_create"); p_mpfree = (mpfree_fn)dlsym(RTLD_DEFAULT, "rte_mempool_free"); }
                        if (!p_malloc || !p_free || !p_pool || !p_mpfree) { outl("RESULT error dlsym"); }
                        else for (char *l = strtok(buf, "\n"); l; l = strtok(NULL, "\n")) run(l); } }
            }
            close(fd);
        }
        usleep(50000);
    }
    return 0;
}
__attribute__((constructor)) static void chap_memapi_init(void)
{
    const char *on = getenv("CHAP_MEMAPI_TEST"); if (!on || strcmp(on, "1")) return;
    const char *dir = getenv("CHAP_MEMAPI_DIR"); if (!dir) dir = "/tmp";
    snprintf(g_out, sizeof g_out, "%s/memapi_out.txt", dir); snprintf(g_cmd, sizeof g_cmd, "/tmp/chap_memapi_cmd_%d", (int)getpid());
    pthread_t t; pthread_attr_t at; pthread_attr_init(&at); pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &at, driver, 0);
}

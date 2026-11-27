// Chaperon Request-E item-3: 2-thread CONCURRENT create/destroy against the kernel resource Sentinel.
// NIC-free stub lib (same as rs_test.c) but the uprobe/uretprobe BPF writers run truly concurrently on two
// pinned CPUs. Compares kernel usage with per-thread ground truth.
//   usage: rs_concurrency_test <sentinel.bpf.o> <libstub_flow.so> <create_off> <destroy_off> <atomic|legacy> [iter] [cpuA] [cpuB]
//   S1 accounting (hard=2^40, no rate): api_calls/completed/flow_held/denied/seq vs truth
//   S2 rate state (rate=1000/s, burst>N): no lost rate-state update (atomic: GCRA TAT; legacy: token count)
//   S3 hard-limit boundary (hard=H): 2 threads create until the Sentinel SIGKILLs; holdings must be exactly H
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <linux/types.h>
#include "../chap_res.h"   /* Request I: shared layout (Request E fields first, unchanged) */
static void *(*create_fn)(int); static int (*destroy_fn)(int);
static pthread_barrier_t bar; static long ITER = 200000; static int CPUA = 2, CPUB = 3;
struct tres { long c_try, c_ok, c_fail, d_ok, d_fail; int cpu; };
static int fails = 0;
#define CHECK(c, ...) do { if (c) { printf("  PASS: "); } else { printf("  FAIL: "); fails++; } printf(__VA_ARGS__); printf("\n"); } while (0)
static unsigned long mono(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000000000ul + t.tv_nsec; }
static void pin(int cpu) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu, &s); pthread_setaffinity_np(pthread_self(), sizeof s, &s); }

static void *worker(void *arg)
{
    struct tres *r = arg; pin(r->cpu); long held = 0;
    pthread_barrier_wait(&bar);
    for (long i = 0; i < ITER; i++) {
        int f = (i % 5) == 4;                                   /* 20% create FAILURE (NULL) */
        void *p = create_fn(f); r->c_try++;
        if (p) { r->c_ok++; held++; } else r->c_fail++;
        if ((i % 3) == 2 && held > 0) {
            int df = (i % 7) == 6;                              /* some destroy FAILURES */
            if (destroy_fn(df) == 0) { r->d_ok++; held--; } else r->d_fail++;
        }
    }
    return 0;
}
static void *flood(void *arg) { pin(*(int *)arg); pthread_barrier_wait(&bar); for (;;) create_fn(0); return 0; }

static void read_slot(volatile struct ru_slot *s, struct ru_slot *o)
{
    for (int t = 0; t < 100000; t++) {
        unsigned long a = s->seq; __atomic_thread_fence(__ATOMIC_ACQUIRE);
        *o = *(struct ru_slot *)s; __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (a == s->seq) break;
    }
}
static void run2(struct tres *A, struct tres *B)
{
    pthread_t ta, tb; memset(A, 0, sizeof *A); memset(B, 0, sizeof *B); A->cpu = CPUA; B->cpu = CPUB;
    pthread_barrier_init(&bar, 0, 2);
    pthread_create(&ta, 0, worker, A); pthread_create(&tb, 0, worker, B);
    pthread_join(ta, 0); pthread_join(tb, 0); pthread_barrier_destroy(&bar);
}

int main(int argc, char **argv)
{
    if (argc < 6) { fprintf(stderr, "usage: %s obj stub c_off d_off atomic|legacy [iter] [cpuA] [cpuB]\n", argv[0]); return 2; }
    const char *obj = argv[1], *stub = argv[2];
    unsigned long c_off = strtoul(argv[3], 0, 16), d_off = strtoul(argv[4], 0, 16);
    int atomic = !strcmp(argv[5], "atomic");
    if (argc > 6) ITER = atol(argv[6]);
    if (argc > 7) CPUA = atoi(argv[7]);
    if (argc > 8) CPUB = atoi(argv[8]);
    printf("== rs_concurrency_test obj=%s mode=%s iter/thread=%ld cpus=%d,%d ==\n", obj, argv[5], ITER, CPUA, CPUB);

    struct bpf_object *o = bpf_object__open(obj);
    if (!o || bpf_object__load(o)) { fprintf(stderr, "load fail\n"); return 1; }
    int ru = bpf_object__find_map_fd_by_name(o, "resource_usage"), rp = bpf_object__find_map_fd_by_name(o, "resource_policy");
    int cg = bpf_object__find_map_fd_by_name(o, "cg_slot"), lc = bpf_object__find_map_fd_by_name(o, "last_cg");
    const long H = 2000;
    struct rp_slot pol[3] = { { 1ul << 40, 0, 0 }, { 1ul << 40, 1000, (unsigned long)(2 * ITER + 1000) }, { (unsigned long)H, 0, 0 } };
    for (unsigned int k = 0; k < 3; k++) bpf_map_update_elem(rp, &k, &pol[k], BPF_ANY);
    void *rw = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, ru, 0);
    memset(rw, 0, sizeof(struct ru_slot) * 3); munmap(rw, 4096);
    CHECK(bpf_map_freeze(ru) == 0, "usage map FROZEN (userspace RO; only the BPF Sentinel writes)");
    struct bpf_link *le = bpf_program__attach_uprobe(bpf_object__find_program_by_name(o, "rs_flow_create_entry"), false, -1, stub, c_off);
    struct bpf_link *lr = bpf_program__attach_uprobe(bpf_object__find_program_by_name(o, "rs_flow_create_ret"), true, -1, stub, c_off);
    struct bpf_link *ld = bpf_program__attach_uprobe(bpf_object__find_program_by_name(o, "rs_flow_destroy_ret"), true, -1, stub, d_off);
    CHECK(le && lr && ld, "entry uprobe + create/destroy uretprobes attached");
    if (!(le && lr && ld)) return 2;
    void *h = dlopen(stub, RTLD_NOW);
    create_fn = (void *(*)(int))dlsym(h, "stub_flow_create"); destroy_fn = (int (*)(int))dlsym(h, "stub_flow_destroy");
    create_fn(0);                                                   /* discover kernel cgroup id (unaccounted) */
    unsigned int zk = 0; unsigned long disc = 0; bpf_map_lookup_elem(lc, &zk, &disc);
    volatile struct ru_slot *U = mmap(NULL, 4096, PROT_READ, MAP_SHARED, ru, 0);
    struct ru_slot r; struct tres A, B;

    /* ---------------- S1 accounting ---------------- */
    unsigned int slot = 0; bpf_map_update_elem(cg, &disc, &slot, BPF_ANY);
    unsigned long t0 = mono(); run2(&A, &B); unsigned long t1 = mono();
    read_slot(&U[0], &r);
    long tt = A.c_try + B.c_try, ok = A.c_ok + B.c_ok, dok = A.d_ok + B.d_ok, dfl = A.d_fail + B.d_fail, cfl = A.c_fail + B.c_fail;
    printf("[S1] truth: creates=%ld ok=%ld fail=%ld destroys_ok=%ld destroys_fail=%ld held=%ld (%.2fs)\n", tt, ok, cfl, dok, dfl, ok - dok, (t1 - t0) / 1e9);
    printf("[S1] kernel: api_calls=%lu completed=%lu flow_held=%lu denied=%lu seq=%#lx cas_exhausted=%ld\n", r.api_calls, r.completed, r.flow_held, r.denied, r.seq, r.tokens_milli);
    CHECK(r.api_calls == (unsigned long)tt, "S1 api_calls == create attempts (%lu vs %ld)", r.api_calls, tt);
    CHECK(r.completed == (unsigned long)tt, "S1 completed == returned creates (%lu vs %ld)", r.completed, tt);
    CHECK(r.flow_held == (unsigned long)(ok - dok), "S1 flow_held == create_ok - destroy_ok (%lu vs %ld)", r.flow_held, ok - dok);
    CHECK(r.denied == 0, "S1 denied == 0");
    if (atomic) {
        CHECK((r.seq >> 32) == 0 && (r.seq & 0xffffffffu) == (unsigned long)(2 * tt + dok) % (1ul << 32), "S1 seqcount: no active writer, generation == writer sections (%lu vs %ld)", r.seq & 0xffffffffu, 2 * tt + dok);
        CHECK(r.tokens_milli == 0, "S1 no CAS-retry exhaustion");
    }

    /* ---------------- S2 rate state ---------------- */
    slot = 1; bpf_map_update_elem(cg, &disc, &slot, BPF_ANY);
    t0 = mono(); run2(&A, &B); t1 = mono();
    read_slot(&U[1], &r);
    tt = A.c_try + B.c_try; ok = A.c_ok + B.c_ok; dok = A.d_ok + B.d_ok;
    printf("[S2] truth: creates=%ld ok=%ld destroys_ok=%ld (%.2fs)   kernel: api=%lu completed=%lu held=%lu denied=%lu last_ns=%lu tokens/cas=%ld\n",
           tt, ok, dok, (t1 - t0) / 1e9, r.api_calls, r.completed, r.flow_held, r.denied, r.last_ns, r.tokens_milli);
    CHECK(r.api_calls == (unsigned long)tt && r.completed == (unsigned long)tt && r.flow_held == (unsigned long)(ok - dok) && r.denied == 0,
          "S2 accounting exact with rate limiting enabled");
    const unsigned long T = 1000000ul;                                /* 1e9 / 1000 */
    if (atomic) {
        long lo = (long)(t0 + tt * T), hi = (long)(t1 + tt * T);      /* TAT = first_call + N*T, first_call in [t0,t1] */
        CHECK((long)r.last_ns >= lo && (long)r.last_ns <= hi, "S2 GCRA state advanced by EXACTLY N*T: no lost rate update (TAT-t0-N*T = %ld ns, window %lu ns)", (long)r.last_ns - lo, t1 - t0);
        CHECK(r.tokens_milli == 0, "S2 no CAS-retry exhaustion");
    } else {
        long cap = (long)pol[1].burst * 1000, el_ms = (long)((t1 - t0) / 1000000ul) + 1;
        long lost = (r.tokens_milli - (cap - tt * 1000) - el_ms * 1000) / 1000;
        printf("[S2] legacy token-bucket: tokens=%ld expected<=%ld -> lost_consumes>=%ld\n", r.tokens_milli, cap - tt * 1000 + el_ms * 1000, lost > 0 ? lost : 0);
        CHECK(lost <= 0, "S2 legacy: no lost token consume");
    }

    /* ---------------- S3 hard-limit boundary ---------------- */
    slot = 2; bpf_map_update_elem(cg, &disc, &slot, BPF_ANY);
    pid_t c = fork();
    if (c == 0) { pthread_t x, y; int a = CPUA, b = CPUB; pthread_barrier_init(&bar, 0, 2);
                  pthread_create(&x, 0, flood, &a); pthread_create(&y, 0, flood, &b); pthread_join(x, 0); _exit(0); }
    int st = 0; for (int w = 0; w < 200; w++) { if (waitpid(c, &st, WNOHANG) == c) break; usleep(50000); }
    if (kill(c, 0) == 0) { kill(c, SIGKILL); waitpid(c, &st, 0); printf("[S3] child NOT killed by Sentinel within 10s\n"); }
    read_slot(&U[2], &r);
    printf("[S3] hard=%ld kernel: api=%lu completed=%lu flow_held=%lu denied=%lu cas=%ld ; child %s sig=%d\n", H, r.api_calls, r.completed,
           r.flow_held, r.denied, r.tokens_milli, WIFSIGNALED(st) ? "SIGNALED" : "exited", WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "S3 over-quota caller SIGKILLed by the kernel Sentinel");
    CHECK(r.flow_held == (unsigned long)H, "S3 holdings == hard limit exactly (no over-reservation under 2-thread race): %lu vs %ld", r.flow_held, H);
    CHECK(r.denied >= 1 && r.api_calls == r.flow_held + r.denied, "S3 every entry either reserved or denied, none lost: api_calls == held + denied (%lu == %lu + %lu)", r.api_calls, r.flow_held, r.denied);
    CHECK(r.completed <= r.flow_held && r.flow_held - r.completed <= 1, "S3 reserved-but-unreturned == calls in flight when the GROUP SIGKILL hit (%lu <= threads-1)", r.flow_held - r.completed);

    printf("\nRS_CONCURRENCY RESULT (%s): %s (%d failing checks)\n", argv[5], fails ? "FAIL" : "PASS", fails);
    return fails ? 3 : 0;
}

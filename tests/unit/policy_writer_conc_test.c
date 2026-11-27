// Request E item-3-1: concurrent comm_policy WRITERS on a real BPF_F_MMAPABLE kernel ARRAY.
// 2 writer threads insert DISJOINT keys that all fall into ONE probe chain (16-slot table), many rounds,
// while a reader validates seqlock snapshots (action = checksum(key) => a torn slot is detectable).
//   mode "locked"  : each insert holds chap_policy_lock() (what chaperon_loader / chap_policy_flip do now)
//   mode "unlocked": the previous single-writer protocol run concurrently (pre-fix behaviour)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include "policy_table_opt.h"
#include "chap_policy_lock.h"
#define NSLOT 16u
static struct pol_slot *T; static int LOCKED; static volatile int stop;
static pthread_barrier_t bar; static long ROUNDS = 20000; static long torn = 0;
static struct comm_policy_key K[2][8];
static uint32_t ck(const struct comm_policy_key *k) { return (pol_hash(k) & 0x3fffffffu) | 0x40000000u; }
static void pin(int c) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(c, &s); pthread_setaffinity_np(pthread_self(), sizeof s, &s); }
static void *wr(void *a)
{
    int id = (int)(long)a; pin(2 + id);
    for (long r = 0; r < ROUNDS; r++) {
        pthread_barrier_wait(&bar);                       /* round start (table reset by thread 0) */
        for (int i = 0; i < 8; i++) {
            int lk = LOCKED ? chap_policy_lock() : -1;
            pol_insert(T, NSLOT, &K[id][i], ck(&K[id][i]));
            if (LOCKED) chap_policy_unlock(lk);
        }
        pthread_barrier_wait(&bar);                       /* round end */
        if (id == 0) { /* verified by main via counters */ }
    }
    return 0;
}
static void *rd(void *a)
{
    (void)a; pin(4);
    while (!stop) for (uint32_t i = 0; i < NSLOT; i++) {
        struct pol_slot *s = &T[i]; uint32_t q1 = s->seq; __sync_synchronize();
        if (q1 & 1u) continue;
        struct comm_policy_key k = s->key; uint32_t act = s->action, occ = s->occupied; __sync_synchronize();
        if (s->seq != q1 || !occ) continue;
        if (act != ck(&k)) __sync_fetch_and_add(&torn, 1);   /* accepted a stable-looking but torn slot */
    }
    return 0;
}
int main(int argc, char **argv)
{
    LOCKED = argc > 1 && !strcmp(argv[1], "locked"); if (argc > 2) ROUNDS = atol(argv[2]);
    union bpf_attr at; memset(&at, 0, sizeof at);
    at.map_type = BPF_MAP_TYPE_ARRAY; at.key_size = 4; at.value_size = sizeof(struct pol_slot);
    at.max_entries = NSLOT; at.map_flags = BPF_F_MMAPABLE; strncpy(at.map_name, "chap_poltest", sizeof at.map_name - 1);
    int fd = (int)syscall(__NR_bpf, BPF_MAP_CREATE, &at, sizeof at);
    if (fd < 0) { perror("map_create"); return 1; }
    T = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (T == MAP_FAILED) { perror("mmap"); return 1; }
    /* 16 disjoint keys whose hash lands in the SAME bucket -> one shared probe chain */
    int n = 0; uint32_t want = 0xffffffffu;
    for (uint32_t x = 1; n < 16 && x < 50000000u; x++) {
        struct comm_policy_key k; memset(&k, 0, sizeof k); k.cgroup_id = 77; k.src_ip = x; k.layer = 2; k.protocol = 17;
        uint32_t b = pol_hash(&k) & (NSLOT - 1);
        if (want == 0xffffffffu) want = b;
        if (b == want) { K[n % 2][n / 2] = k; n++; }
    }
    if (n < 16) { fprintf(stderr, "could not build colliding keys\n"); return 1; }
    pthread_barrier_init(&bar, 0, 3);
    pthread_t a, b, c; pthread_create(&a, 0, wr, (void *)0L); pthread_create(&b, 0, wr, (void *)1L); pthread_create(&c, 0, rd, 0);
    long lost_rounds = 0, lost_keys = 0, dup_rounds = 0;
    for (long r = 0; r < ROUNDS; r++) {
        { int lk = LOCKED ? chap_policy_lock() : -1;     /* reset is a WRITER too */
          if (LOCKED) { CHAP_POL_RESET(T, NSLOT); chap_policy_unlock(lk); } else memset(T, 0, NSLOT * sizeof(struct pol_slot)); }
        pthread_barrier_wait(&bar); pthread_barrier_wait(&bar);
        int present = 0, occ = 0;
        for (uint32_t i = 0; i < NSLOT; i++) if (T[i].occupied) occ++;
        for (int t = 0; t < 2; t++) for (int i = 0; i < 8; i++)
            if (pol_lookup(T, NSLOT, &K[t][i]) == ck(&K[t][i])) present++;
        if (present < 16) { lost_rounds++; lost_keys += 16 - present; }
        if (occ != present) dup_rounds++;
    }
    stop = 1; pthread_join(a, 0); pthread_join(b, 0); pthread_join(c, 0);
    printf("POLICY_WRITERS mode=%s rounds=%ld (16 colliding inserts/round, 2 writer threads): lost_rounds=%ld lost_keys=%ld dup_or_orphan_rounds=%ld torn_reads_accepted=%ld\n",
           LOCKED ? "locked" : "unlocked", ROUNDS, lost_rounds, lost_keys, dup_rounds, torn);
    int ok = lost_rounds == 0 && dup_rounds == 0 && torn == 0;
    printf("POLICY_WRITER_RESULT (%s): %s\n", LOCKED ? "locked" : "unlocked", ok ? "PASS" : "FAIL");
    return ok ? 0 : 3;
}

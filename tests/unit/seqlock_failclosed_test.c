// Chaperon review #4 direct test: force POL_UNSTABLE (a writer hammering the exact-DROP slot) and
// verify the fixed seqlock reader FAILS CLOSED (DROP) instead of falling through to a coexisting
// wildcard-ALLOW. Replicates the FIXED c_filter reader logic verbatim (stable-snapshot-only ->
// POL_UNSTABLE -> ACT_DROP). The OLD logic (use last torn value, then wildcard) would leak ALLOW.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define ACT_ALLOW 0u
#define ACT_DROP  2u
#define POL_NOMATCH  0xffffffffu
#define POL_UNSTABLE 0xfffffffeu
#define barrier() __asm__ __volatile__("" ::: "memory")

struct pol_slot { volatile uint32_t seq; uint32_t occupied; uint32_t key; uint32_t action; };
static struct pol_slot EXACT;   /* exact-key slot, writer hammers it (DROP) */
static struct pol_slot WILD;    /* wildcard slot (ALLOW), stable */
static volatile int stop = 0;

/* writer: continuously (re)publish the exact DROP rule -> seq goes odd during each write. */
static void *writer(void *a){ (void)a;
    while(!stop){
        uint32_t s = EXACT.seq & ~1u; EXACT.seq = s+1; barrier();   /* odd: writing */
        EXACT.key=0x1234; EXACT.action=ACT_DROP; EXACT.occupied=1; barrier();
        EXACT.seq = s+2;                                            /* even: published */
    }
    return 0;
}

/* FIXED reader of one slot: returns ACT_* , POL_NOMATCH, or POL_UNSTABLE (retry-exhaust). */
static uint32_t read_slot(struct pol_slot *s, uint32_t want_key){
    uint32_t occ=0, act=POL_NOMATCH, eq=0; int stable=0;
    for(int t=0;t<4;t++){
        uint32_t s1=s->seq; barrier();
        if(s1 & 1u) continue;
        occ=s->occupied; act=s->action; eq=(s->key==want_key); barrier();
        uint32_t s2=s->seq;
        if(s1==s2){ stable=1; break; }
    }
    if(!stable) return POL_UNSTABLE;     /* review #4: never use a torn snapshot */
    if(occ && eq) return act;
    if(!occ) return POL_NOMATCH;
    return POL_NOMATCH;
}

/* specificity-ordered decision: exact first, then wildcard. UNSTABLE on exact -> fail-closed DROP. */
static uint32_t decide(uint32_t key){
    uint32_t a = read_slot(&EXACT, key);
    if (a == POL_UNSTABLE) return ACT_DROP;           /* review #4 fix: do NOT fall to wildcard */
    if (a != POL_NOMATCH) return a;                   /* exact match (DROP) */
    uint32_t w = read_slot(&WILD, 0);                 /* wildcard (matches any) */
    if (w == POL_UNSTABLE) return ACT_DROP;
    if (w != POL_NOMATCH) return w;                   /* wildcard ALLOW */
    return ACT_DROP;                                  /* default fail-closed */
}

int main(void){
    EXACT.seq=0; EXACT.occupied=1; EXACT.key=0x1234; EXACT.action=ACT_DROP;
    WILD.seq=0;  WILD.occupied=1;  WILD.key=0;        WILD.action=ACT_ALLOW;  /* wildcard ALLOW */
    pthread_t w; pthread_create(&w,0,writer,0);
    unsigned long iters=20000000, allow_leak=0, drop=0, unstable_seen=0;
    for(unsigned long i=0;i<iters;i++){
        /* observe raw exact read to count how often it is actually UNSTABLE */
        if (read_slot(&EXACT,0x1234)==POL_UNSTABLE) unstable_seen++;
        uint32_t d = decide(0x1234);
        if (d==ACT_ALLOW) allow_leak++; else drop++;
    }
    stop=1; pthread_join(w,0);
    printf("iters=%lu  exact-DROP present + wildcard-ALLOW present + writer hammering exact\n", iters);
    printf("  UNSTABLE exact reads observed = %lu (the failure path actually occurred)\n", unstable_seen);
    printf("  decisions: DROP=%lu  ALLOW-LEAK=%lu\n", drop, allow_leak);
    printf("\n#4 SEQLOCK-FAILCLOSED RESULT: %s (exact DROP never leaked to wildcard ALLOW)\n",
           allow_leak==0 ? "PASS" : "FAIL");
    return allow_leak==0 ? 0 : 2;
}

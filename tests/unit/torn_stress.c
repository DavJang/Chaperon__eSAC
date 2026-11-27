/* Torn-read / TOCTOU stress for the OPTIMIZED in-place seqlock read (mirrors policy_arr_lookup's
 * optimized loop: read seq, read occ/action, compare key IN-PLACE, barrier, re-read seq).
 * Writer continuously republishes a slot with ALL key fields + action set to a running value V
 * (a self-consistent snapshot). A reader that ACCEPTS a read (seq even & unchanged) must observe a
 * FULLY CONSISTENT snapshot (all fields == action). Any accepted-but-inconsistent read = torn bug. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

struct key { uint64_t cgroup_id; uint32_t src_ip,dst_ip; uint16_t src_port,dst_port; uint8_t proto,layer; uint16_t _pad; };
struct slot { volatile uint32_t seq; uint32_t occupied; struct key k; uint32_t action; uint32_t _pad; };
static struct slot S;
static atomic_ullong torn=0, accepted=0, retries=0, stop=0;
#define barrier() atomic_signal_fence(memory_order_seq_cst)

static void* writer(void*_){
    uint32_t V=1;
    while(!atomic_load(&stop)){
        uint32_t seq = S.seq & ~1u;
        S.seq = seq+1; barrier(); atomic_thread_fence(memory_order_release);   /* odd: writing */
        S.k.cgroup_id=V; S.k.src_ip=V; S.k.dst_ip=V; S.k.src_port=(uint16_t)V; S.k.dst_port=(uint16_t)V; S.k.proto=(uint8_t)V; S.k.layer=2; S.k._pad=0;
        S.action=V; S.occupied=1;
        atomic_thread_fence(memory_order_release); barrier();
        S.seq = seq+2;                                                          /* even: published */
        V++;
    }
    return 0;
}
/* optimized in-place seqlock read: returns 1 if accepted (and fills out), else 0 (retry-exhausted) */
static int read_slot(struct key*ko,uint32_t*ao,uint32_t*occo){
    for(int t=0;t<8;t++){
        uint32_t s1=S.seq; barrier(); atomic_thread_fence(memory_order_acquire);
        if(s1 & 1u){ continue; }
        uint32_t occ=S.occupied, act=S.action; struct key kk=S.k;  /* read fields in window */
        atomic_thread_fence(memory_order_acquire); barrier();
        uint32_t s2=S.seq;
        if(s1==s2){ *ko=kk; *ao=act; *occo=occ; return 1; }
    }
    return 0;
}
static void* reader(void*_){
    struct key k; uint32_t a,occ;
    while(!atomic_load(&stop)){
        if(read_slot(&k,&a,&occ)){
            atomic_fetch_add(&accepted,1);
            /* a CONSISTENT snapshot: all key fields == action (== V at write time) */
            uint32_t v=a;
            if(!(k.cgroup_id==v && k.src_ip==v && k.dst_ip==v && k.src_port==(uint16_t)v && k.dst_port==(uint16_t)v && k.proto==(uint8_t)v && occ==1))
                atomic_fetch_add(&torn,1);
        } else atomic_fetch_add(&retries,1);
    }
    return 0;
}
int main(int argc,char**argv){
    int secs = argc>1?atoi(argv[1]):4, nr = argc>2?atoi(argv[2]):4;
    S.action=1; S.occupied=1; S.k.cgroup_id=1; S.k.src_ip=1; S.k.dst_ip=1; S.k.src_port=1; S.k.dst_port=1; S.k.proto=1; S.k.layer=2;
    pthread_t w, r[16]; pthread_create(&w,0,writer,0);
    for(int i=0;i<nr;i++) pthread_create(&r[i],0,reader,0);
    sleep(secs); atomic_store(&stop,1);
    pthread_join(w,0); for(int i=0;i<nr;i++) pthread_join(r[i],0);
    printf("torn-read stress: secs=%d readers=%d accepted=%llu retries=%llu TORN=%llu => %s\n",
        secs,nr,(unsigned long long)accepted,(unsigned long long)retries,(unsigned long long)torn,
        torn==0?"PASS (no torn/TOCTOU; seqlock in-place read safe)":"FAIL (torn read observed!)");
    return torn?1:0;
}

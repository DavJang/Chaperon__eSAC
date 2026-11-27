/* Security audit of the word-wise hash + open-addressing ARRAY policy table.
 * Replicates reader(word-wise) & original(byte-wise) hashes + insert/lookup + seqlock,
 * and checks: distribution, high-bit sensitivity, intentional collision (full 24B key compare
 * + correct ALLOW/DROP), max-probing fail-closed, saturation reject. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define POL_N 16384u
#define POL_MASK (POL_N-1u)
#define POL_PROBE 16u
#define NOMATCH 0xffffffffu
#define ACT_ALLOW 0u
#define ACT_DROP 2u

struct key { uint64_t cgroup_id; uint32_t src_ip,dst_ip; uint16_t src_port,dst_port; uint8_t proto,layer; uint16_t _pad; };
struct slot { volatile uint32_t seq; uint32_t occupied; struct key k; uint32_t action; uint32_t _pad; };

/* original: byte-wise FNV-1a over 24 bytes */
static uint32_t hash_byte(const struct key*k){ const unsigned char*b=(const unsigned char*)k; uint32_t h=2166136261u; for(unsigned i=0;i<sizeof(*k);i++){h^=b[i];h*=16777619u;} return h; }
/* optimized: word-wise FNV-1a over 6 u32 words */
static uint32_t hash_word(const struct key*k){ const uint32_t*b=(const uint32_t*)k; uint32_t h=2166136261u; for(unsigned i=0;i<sizeof(*k)/4u;i++){h^=b[i];h*=16777619u;} h^=h>>16; h*=2246822519u; h^=h>>13; return h; }

static int key_eq(const struct key*a,const struct key*b){ return memcmp(a,b,sizeof(*a))==0; }

/* insert (writer) using a given hash fn; returns probes used, or -1 saturated */
static int insert(struct slot*t,const struct key*k,uint32_t act,uint32_t(*hf)(const struct key*)){
    uint32_t h=hf(k)&POL_MASK;
    for(uint32_t i=0;i<POL_PROBE;i++){ struct slot*s=&t[(h+i)&POL_MASK];
        if((s->occupied && key_eq(&s->k,k)) || !s->occupied){ s->seq++; s->k=*k; s->action=act; s->occupied=1; s->seq++; return i; } }
    return -1; }
/* lookup (reader, in-place compare) using a given hash fn */
static uint32_t lookup(struct slot*t,const struct key*k,uint32_t(*hf)(const struct key*),int*probes){
    uint32_t h=hf(k)&POL_MASK;
    for(uint32_t i=0;i<POL_PROBE;i++){ struct slot*s=&t[(h+i)&POL_MASK];
        if(probes)*probes=i+1;
        if(s->occupied && key_eq(&s->k,k)) return s->action;
        if(!s->occupied) return NOMATCH; }
    return NOMATCH; }

static struct key mk(uint64_t cg,uint32_t sip,uint32_t dip,uint16_t sp,uint16_t dp,uint8_t pr){ struct key k; memset(&k,0,sizeof k); k.cgroup_id=cg;k.src_ip=sip;k.dst_ip=dip;k.src_port=sp;k.dst_port=dp;k.proto=pr;k.layer=2; return k; }

static void dist_test(const char*name,uint32_t(*hf)(const struct key*),int N){
    struct slot*t=calloc(POL_N,sizeof(struct slot)); int sat=0,maxp=0; long sump=0;
    for(int i=0;i<N;i++){ struct key k=mk(1000+i%7, 0x0a000001+((i*2654435761u)&0xffff), 0xc0a80001+i, 1024+(i%50000), 53, 17);
        int p=insert(t,&k,ACT_ALLOW,hf); if(p<0){sat++;continue;} if(p>maxp)maxp=p; sump+=p; }
    /* re-lookup all to confirm found */
    int miss=0; for(int i=0;i<N;i++){ struct key k=mk(1000+i%7,0x0a000001+((i*2654435761u)&0xffff),0xc0a80001+i,1024+(i%50000),53,17); if(lookup(t,&k,hf,0)==NOMATCH)miss++; }
    printf("  [%s] N=%d saturated=%d max_probe=%d avg_probe=%.2f lookup_miss=%d\n",name,N,sat,maxp,N-sat?(double)sump/(N-sat):0,miss);
    free(t);
}

int main(){
    printf("=== 1. HIGH-BIT sensitivity (keys differ ONLY in high bits -> must get different index) ===\n");
    struct key a=mk(0x0000000100000000ULL,1,2,3,4,17);   /* cgroup high word =1, low=0 */
    struct key b=mk(0x0000000200000000ULL,1,2,3,4,17);   /* cgroup high word =2 */
    struct key c=mk(0,0xFF000001u,2,3,4,17);             /* dst high byte differs */
    struct key d=mk(0,0x00000001u,2,3,4,17);
    printf("  cgroup high bit: word idx a=%u b=%u %s | byte idx a=%u b=%u\n",hash_word(&a)&POL_MASK,hash_word(&b)&POL_MASK,(hash_word(&a)&POL_MASK)!=(hash_word(&b)&POL_MASK)?"DIFFER(ok)":"SAME(!)",hash_byte(&a)&POL_MASK,hash_byte(&b)&POL_MASK);
    printf("  src_ip high byte: word idx c=%u d=%u %s\n",hash_word(&c)&POL_MASK,hash_word(&d)&POL_MASK,(hash_word(&c)&POL_MASK)!=(hash_word(&d)&POL_MASK)?"DIFFER(ok)":"SAME(!)");

    printf("=== 2. DISTRIBUTION & max-probe (word vs byte) at N=2/100/1000/10000 ===\n");
    int Ns[]={2,100,1000,10000}; for(int i=0;i<4;i++){ dist_test("word",hash_word,Ns[i]); dist_test("byte",hash_byte,Ns[i]); }

    printf("=== 3. INTENTIONAL COLLISION: 2 keys same index, different full key, ALLOW vs DROP ===\n");
    /* brute-force find two distinct keys with same word-hash index */
    struct key k1=mk(5,0x01020304,0x05060708,100,200,6), k2; uint32_t i1=hash_word(&k1)&POL_MASK; int found=0;
    for(uint32_t x=1;x<2000000 && !found;x++){ k2=mk(5,0x01020304,0x05060708+x,100,200,6); if((hash_word(&k2)&POL_MASK)==i1 && !key_eq(&k1,&k2)){found=1;} }
    if(found){ struct slot*t=calloc(POL_N,sizeof(struct slot));
        insert(t,&k1,ACT_ALLOW,hash_word); insert(t,&k2,ACT_DROP,hash_word);
        uint32_t r1=lookup(t,&k1,hash_word,0), r2=lookup(t,&k2,hash_word,0);
        printf("  collide at idx=%u: K1->%s (want ALLOW) K2->%s (want DROP) => %s\n",i1,r1==ACT_ALLOW?"ALLOW":(r1==ACT_DROP?"DROP":"NOMATCH"),r2==ACT_DROP?"DROP":(r2==ACT_ALLOW?"ALLOW":"NOMATCH"),(r1==ACT_ALLOW&&r2==ACT_DROP)?"PASS(full-key compare distinguishes)":"FAIL");
        free(t);
    } else printf("  (no collision found in search range)\n");

    printf("=== 4. MAX-PROBING fail-closed + saturation reject ===\n");
    struct slot*t=calloc(POL_N,sizeof(struct slot));
    /* craft 17 keys all hashing to the SAME base index -> fill 16-slot window, 17th must be rejected */
    struct key base=mk(7,0xaabbccdd,0x11223344,1,2,17); uint32_t bi=hash_word(&base)&POL_MASK;
    int filled=0; uint32_t x=0; struct key keys[20];
    while(filled<17 && x<5000000){ struct key kk=mk(7,0xaabbccdd,0x11223344+x,1,2,17); if((hash_word(&kk)&POL_MASK)==bi){ keys[filled++]=kk; } x++; }
    int rc_last=-99; for(int i=0;i<filled;i++){ int rc=insert(t,&keys[i],ACT_DROP,hash_word); if(i==16)rc_last=rc; if(i<16 && rc<0){ printf("  unexpected early reject at %d\n",i);} }
    printf("  filled %d colliding keys; 17th insert rc=%d => %s\n",filled,rc_last, rc_last<0?"REJECTED(saturation, no silent drop) PASS":"ACCEPTED(unexpected)");
    /* lookup a NON-installed key that probes into the full window -> must NOMATCH (fail-closed) */
    struct key absent=mk(7,0xaabbccdd,0x11223344+9999999u,1,2,17);
    uint32_t ra=lookup(t,&absent,hash_word,0);
    printf("  absent key lookup => %s (NOMATCH => caller fail-closed default) %s\n", ra==NOMATCH?"NOMATCH":"MATCH(!)", ra==NOMATCH?"PASS":"FAIL");
    free(t);
    printf("=== key size check: sizeof(key)=%zu (expect 24), sizeof/4=%zu words ===\n",sizeof(struct key),sizeof(struct key)/4);
    return 0;
}

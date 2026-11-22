/* esac_hs_ufunc.so (v2, DNS-aware) — Hyperscan domain-blocking provider for eSAC.
 *
 * FIX vs prior raw-payload scanner:
 *   - parse the DNS QNAME from the packet (bounds-checked), lowercase it, then
 *     Hyperscan-match the *normalized name* (not raw payload bytes).
 *   - patterns are compiled CASE-INSENSITIVE and ANCHORED to label boundaries:
 *         (^|\.)<escaped-domain>$     -> matches the domain and any subdomain,
 *     never an arbitrary substring. Same detection semantics as a DNS IDS.
 *   - non-DNS / compressed / malformed payloads fall back to a raw full-payload
 *     scan (honest fail-open to inspection, never a silent miss).
 * Hardening unchanged: compiled DB + state page are mprotect() READ-ONLY.
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
#include <dlfcn.h>
#include <signal.h>

/* ---- dlsym-visible rte_pktmbuf_free_bulk shim (for the L7 per-packet DROP path) ----
 * The tenant's rte_pktmbuf_free_bulk is statically linked and NOT resolvable via
 * dlsym(RTLD_DEFAULT) at bpftime-agent-init time (verified: nil early, found late), so the
 * agent skips registering it and the C_Filter gate fail-closes to ACT_KILL on an L7 match.
 * This provider .so is already in scope at agent-init (it also exports esac_hs_scan), so a
 * same-named shim here IS found -> the agent registers it as the `rte_pktmbuf_free_bulk` ufunc.
 * At CALL time (gate dropping packets, late) it lazily resolves the REAL symbol from the MAIN
 * program handle and forwards. The tenant's own calls are static/direct and unaffected; this
 * shim is only reached via the ufunc call path / dlsym, never the tenant's internal calls. */
uint64_t esac_hs_scan(const void *batch, uint32_t count);   /* fwd decl: stable symbol in THIS .so */

__attribute__((visibility("default")))
void rte_pktmbuf_free_bulk(void **mbufs, unsigned int count)
{
    static void (*real_fb)(void **, unsigned int) = NULL;
    if (!real_fb) {
        void *mainh = dlopen(NULL, RTLD_NOW);                 /* main program (tenant) symbols */
        if (mainh) {
            void *s = dlsym(mainh, "rte_pktmbuf_free_bulk");
            Dl_info si, mi;
            /* accept s only if it lives in a DIFFERENT object than this provider .so
             * (robust against symbol interposition — never forwards to our own shim). */
            if (s && dladdr(s, &si) && dladdr((void *)&esac_hs_scan, &mi)
                && si.dli_fname && mi.dli_fname
                && strcmp(si.dli_fname, mi.dli_fname) != 0)
                real_fb = (void (*)(void **, unsigned int))s;
        }
    }
    if (real_fb) { real_fb(mbufs, count); return; }
    /* Real symbol unresolved at drop time: the gate has already excluded these mbufs from the
     * returned burst, so NOT freeing them would silently leak them out of the mempool. Do NOT
     * return as if it succeeded. Fail-closed: terminate the tenant (SIGKILL) so the leak cannot
     * accumulate and the enforcement failure is unmistakable — same safety posture as the
     * gate's own ufunc-absent fail-close, just now detectable here. */
    { static volatile int warned = 0; if (!warned) { warned = 1;
        fprintf(stderr, "[esac_hs] FATAL: rte_pktmbuf_free_bulk unresolved at drop time; "
                        "fail-close (SIGKILL self) to avoid mbuf leak\n"); } }
    kill(getpid(), SIGKILL);
}

#define PAGE 4096UL
static unsigned long pdown(unsigned long a){ return a & ~(PAGE-1); }
static unsigned long pup(unsigned long a){ return (a + PAGE - 1) & ~(PAGE-1); }

struct hs_state { hs_database_t *db; hs_scratch_t *scratch_proto; unsigned long db_ro_base, db_ro_len; };
static union { struct hs_state s; char pad[PAGE]; } g_sp __attribute__((aligned(4096)));
#define g_db            (g_sp.s.db)
#define g_scratch_proto (g_sp.s.scratch_proto)
#define g_db_ro_base    (g_sp.s.db_ro_base)
#define g_db_ro_len     (g_sp.s.db_ro_len)
static __thread hs_scratch_t *t_scratch = NULL;

#define MAXDB 64
static struct { void *base; size_t len; } g_dba[MAXDB];
static int g_ndba = 0;
static void *db_alloc(size_t n){
    size_t len = pup(n ? n : 1);
    void *p = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    if (g_ndba < MAXDB){ g_dba[g_ndba].base=p; g_dba[g_ndba].len=len; g_ndba++; }
    return p;
}
static void db_free(void *p){ if(!p)return; for(int i=0;i<g_ndba;i++) if(g_dba[i].base==p){ munmap(p,g_dba[i].len); g_dba[i].base=NULL; return; } }

static int on_match(unsigned int id, unsigned long long f, unsigned long long t,
                    unsigned int fl, void *ctx){ (void)id;(void)f;(void)t;(void)fl; *(int*)ctx=1; return 1; }

/* ---- DNS parse (bounds-checked; same logic as the hybrid provider) ---- */
static int dns_sane(const unsigned char*p,uint32_t len){ if(len<12)return 0; uint32_t qd=(p[4]<<8)|p[5]; if(qd<1||qd>8)return 0; if(((p[2]>>3)&0xf)>2)return 0; return 1; }
static int dns_clean(const unsigned char *p, uint32_t len){
    if (len < 12) return 0;
    uint32_t qd=(p[4]<<8)|p[5], an=(p[6]<<8)|p[7], ns=(p[8]<<8)|p[9], ar=(p[10]<<8)|p[11];
    if (qd!=1||an!=0||ns!=0||ar!=0) return 0;
    uint32_t off=12;
    for (int i=0;i<128;i++){ if(off>=len)return 0; uint8_t ll=p[off];
        if(ll==0){off++;break;} if(ll&0xC0)return 0; off+=1+ll; }
    return (off+4<=len)?1:0;   /* allow trailing bytes (EDNS/padding); compression already rejected */
}
static uint32_t dns_qname(const unsigned char*p,uint32_t len,char*out,uint32_t cap){
    uint32_t off=12,o=0;
    for(int i=0;i<64;i++){ if(off>=len)return 0; uint8_t ll=p[off]; if(ll==0)break; if(ll&0xC0)break; off++;
        if(off+ll>len)return 0; if(o+ll+1>=cap)break; for(uint32_t j=0;j<ll;j++)out[o++]=(char)p[off+j]; off+=ll; out[o++]='.'; }
    if(o>0&&out[o-1]=='.')o--; return o;
}

/* escape regex metacharacters; build  (^|\.)<dom>$  */
static char *anchor_pattern(const char *dom){
    size_t dl=strlen(dom); char *out=malloc(dl*2+8); if(!out)return NULL;
    size_t o=0; out[o++]='('; out[o++]='^'; out[o++]='|'; out[o++]='\\'; out[o++]='.'; out[o++]=')';
    for(size_t i=0;i<dl;i++){ char c=dom[i]; if(strchr(".\\+*?()[]{}^$|",c)) out[o++]='\\'; out[o++]=c; }
    out[o++]='$'; out[o]=0; return out;
}

__attribute__((constructor))
static void esac_hs_init(void){
    const char *path=getenv("ESAC_HS_PATTERNS");
    char **pats=NULL; unsigned n=0,cap=0;
    if(path&&*path){
        FILE *f=fopen(path,"r");
        if(f){ char *ln=NULL; size_t sz=0; ssize_t r;
            while((r=getline(&ln,&sz,f))>=0){
                while(r>0&&(ln[r-1]=='\n'||ln[r-1]=='\r'||ln[r-1]==' '))ln[--r]=0;
                if(r==0||ln[0]=='#')continue;
                char *pat=anchor_pattern(ln); if(!pat)continue;
                if(n>=cap){cap=cap?cap*2:1024; pats=realloc(pats,cap*sizeof(char*));}
                pats[n++]=pat;
            }
            free(ln); fclose(f);
            fprintf(stderr,"[esac_hs] loaded %u patterns from file %s\n",n,path);
        } else fprintf(stderr,"[esac_hs] fopen(%s) failed\n",path);
    }
    if(n==0){ static const char*def[]={"(^|\\.)evil\\.com$","(^|\\.)malware\\.test$"};
        n=2; pats=malloc(n*sizeof(char*)); for(unsigned i=0;i<n;i++)pats[i]=strdup(def[i]);
        fprintf(stderr,"[esac_hs] no patterns file -> %u defaults\n",n); }

    unsigned *ids=malloc(n*sizeof(unsigned)), *flags=malloc(n*sizeof(unsigned));
    for(unsigned i=0;i<n;i++){ ids[i]=i; flags[i]=HS_FLAG_CASELESS|HS_FLAG_SINGLEMATCH|HS_FLAG_DOTALL; }

    hs_set_database_allocator(db_alloc, db_free);
    hs_compile_error_t *err=NULL;
    if(hs_compile_multi((const char*const*)pats,flags,ids,n,HS_MODE_BLOCK,NULL,&g_db,&err)!=HS_SUCCESS){
        fprintf(stderr,"[esac_hs] compile failed: %s\n",err?err->message:"?"); hs_free_compile_error(err); return; }
    if(hs_alloc_scratch(g_db,&g_scratch_proto)!=HS_SUCCESS){ fprintf(stderr,"[esac_hs] scratch alloc failed\n"); return; }

    size_t dbsz=0;
    if(hs_database_size(g_db,&dbsz)==HS_SUCCESS){
        unsigned long base=pdown((unsigned long)g_db), len=pup(((unsigned long)g_db-base)+dbsz);
        if(mprotect((void*)base,len,PROT_READ)==0){ g_db_ro_base=base; g_db_ro_len=len; } }
    int sp_ro=(mprotect(&g_sp,PAGE,PROT_READ)==0);
    fprintf(stderr,"[esac_hs] compiled %u patterns (DNS-aware, CASELESS, label-anchored), DB RO @ %lx(%zuB), state-page RO=%d\n",
            n,g_db_ro_base,dbsz,sp_ro);
}

void esac_hs_db_region(void **a, unsigned long *l){ if(a)*a=(void*)g_db_ro_base; if(l)*l=g_db_ro_len; }
void *esac_hs_dbptr_addr(void){ return (void*)&g_db; }

static unsigned long g_calls=0,g_pkts=0,g_bytes=0,g_matches=0,g_dns=0,g_fallback=0;
struct esac_hs_item { uint64_t pl_ptr; uint32_t pl_len; uint32_t act; };

/* batch entry: parse QNAME -> lowercase -> match normalized name; else raw fallback */
uint64_t esac_hs_scan(const void *batch, uint32_t count){
    if(!g_db||!batch||count==0) return 0;
    if(!t_scratch){ if(hs_clone_scratch(g_scratch_proto,&t_scratch)!=HS_SUCCESS) return 0; }
    const struct esac_hs_item *items=batch; if(count>128u)count=128u;
    uint64_t total=0;
    for(uint32_t i=0;i<count;i++){
        const unsigned char *pl=(const unsigned char*)(uintptr_t)items[i].pl_ptr;
        uint32_t len=items[i].pl_len; if(!pl||len==0)continue;
        int matched=0; char name[256]; uint32_t nl=0;
        if(len>=12 && dns_sane(pl,len) && dns_clean(pl,len)) nl=dns_qname(pl,len,name,sizeof name);
        if(nl>0){
            for(uint32_t k=0;k<nl;k++){ char c=name[k]; if(c>='A'&&c<='Z')name[k]=c+32; }
            hs_scan(g_db,name,nl,0,t_scratch,on_match,&matched); g_dns++; g_bytes+=nl;
        } else {
            hs_scan(g_db,(const char*)pl,len,0,t_scratch,on_match,&matched); g_fallback++; g_bytes+=len;
        }
        total+=(uint64_t)matched; g_pkts++; g_matches+=(unsigned)matched;
    }
    if((g_calls++ % 4096ul)==0)
        fprintf(stderr,"[esac_hs] call#%lu pkts=%lu dns=%lu fallback=%lu bytes=%lu matches=%lu\n",
                g_calls,g_pkts,g_dns,g_fallback,g_bytes,g_matches);
    return total;
}

/* esac_seal.so — eSAC W^X sealing helper, LD_PRELOAD'd into the eSAC tenant alongside the agent.
 *
 * Problem (measured): Frida Gum inline-hooking leaves the HOOKED code pages (e.g. mlx5_rx_burst)
 * AND its trampoline/code-cache pages mapped rwx (writable+executable). A tenant can then overwrite
 * the hook bytes DIRECTLY — no mprotect — and remove/redirect eSAC enforcement, which the
 * mprotect-watching Tamper Sentinel never sees.
 *
 * Fix: AFTER hooks are installed, drop write from every rwx region -> r-x (W^X). A direct write then
 * faults in hardware (kernel pre-block), and the only way to regain write is mprotect(PROT_WRITE),
 * which the Sentinel catches. We touch ONLY executable+writable regions; runtime-updatable rw- data,
 * rw-s shared memory (policy map / DPDK memfd hugepages) are left alone.
 *
 * Triggered by signal from the loader/harness AFTER "attach summary":
 *   SIGRTMIN+6 -> SEAL      (rwx -> r-x + mlock for all exec regions; also writes the sealed ranges to
 *                            /tmp/esac_seal_ranges_<pid>.txt so the Sentinel can addr-filter munmap/mremap)
 *   SIGRTMIN+7 -> VERIFY     (direct write to first sealed exec region; expect SIGSEGV)
 *   SIGRTMIN+8 -> VERIFY_MADV(madvise(MADV_DONTNEED) on a sealed region; mlock -> expect EINVAL pre-block)
 * mlock closes the madvise(MADV_DONTNEED) discard vector (DONTNEED on a locked VMA returns EINVAL),
 * so a file-backed hook page cannot be reverted to its un-hooked original, nor an anon trampoline zeroed.
 * All handlers use async-signal-safe primitives only (open/read/write/mprotect/mlock/madvise).
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>

#define SIG_SEAL      (SIGRTMIN+6)
#define SIG_VERIFY    (SIGRTMIN+7)
#define SIG_VMADV     (SIGRTMIN+8)
#define SIG_ATK_UNMAP (SIGRTMIN+9)
#define SIG_ATK_DISP  (SIGRTMIN+10)  /* Request F test: corrupt writable pointers into anon exec code */   /* self-attack: munmap a sealed hook range (should be KILLed by Sentinel) */
#define MAXSEAL 64
#ifndef MADV_DONTNEED
#define MADV_DONTNEED 4
#endif

static uintptr_t sealed_start[MAXSEAL];
static uintptr_t sealed_end[MAXSEAL];
static int       sealed_n = 0;
static int       logfd = -1;
static sigjmp_buf segjb;
static void segv(int s);   /* fwd (defined below) */
static int g_last_sealed = -1, g_last_fail = -1, g_enf_fail = 0;   /* Request E: in-process seal status */

/* ---- async-signal-safe helpers ---- */
static void wstr(const char *s){ if(logfd>=0) (void)!write(logfd, s, strlen(s)); }
static void whex(uintptr_t v){
    char b[19]="0x"; int i; for(i=0;i<16;i++){ int nib=(v>>((15-i)*4))&0xf; b[2+i]=nib<10?'0'+nib:'a'+nib-10; }
    b[18]=0; wstr(b);
}
static void wdec(long v){ char b[24]; int i=23; b[i--]=0; if(v==0)b[i--]='0'; while(v>0){b[i--]='0'+v%10;v/=10;} wstr(&b[i+1]); }

/* parse one hex token at *p, advance p */
static uintptr_t rdhex(const char **p){ uintptr_t v=0; const char*s=*p; for(;;s++){char c=*s;int d; if(c>='0'&&c<='9')d=c-'0'; else if(c>='a'&&c<='f')d=c-'a'+10; else if(c>='A'&&c<='F')d=c-'A'+10; else break; v=(v<<4)|d;} *p=s; return v; }

/* Item-1 read-only sealing of the init-once ENFORCEMENT ufunc dispatch table (func pointers incl.
 * the L7 esac_hs_scan ufunc), whose [addr,size] the fixed runtime wrote to the targets file at
 * trusted bootstrap. Seal the interior FULL pages RO + mlock (partial first/last page left untouched
 * so no neighbour allocation is caught), add to sealed_start/end so it is registered with the
 * Tamper Sentinel via the ranges file, and self-verify a direct write faults. */
static void seal_enforce_targets(void){
    char tp[96]; { char*q=tp; const char*pre="/tmp/chap_seal_targets_"; for(const char*c=pre;*c;)*q++=*c++;
        char d[16]; int i=0,v=getpid(); if(v==0)d[i++]='0'; while(v>0){d[i++]='0'+v%10;v/=10;} while(i>0)*q++=d[--i]; *q=0; }
    int fd=open(tp,O_RDONLY); if(fd<0){ wstr("ENFSEAL no-targets-file "); wstr(tp); wstr("\n"); return; }
    static char tb[1<<16]; int n,used=0;
    while((n=read(fd,tb+used,sizeof(tb)-used-1))>0){ used+=n; if(used>=(int)sizeof(tb)-1) break; }
    close(fd); tb[used]=0;
    char *u=tb; int found=0;
    while(u && *u){ char*nl=strchr(u,'\n'); if(nl)*nl=0;
        if(u[0]=='U'&&u[1]=='F'&&u[2]=='U'&&u[3]=='N'&&u[4]=='C'&&u[5]==' '){
            const char*p=u+6; while(*p==' ')p++; if(p[0]=='0'&&p[1]=='x')p+=2;
            uintptr_t addr=rdhex(&p); while(*p==' ')p++;
            unsigned long size=0; for(;*p>='0'&&*p<='9';p++) size=size*10UL+(unsigned long)(*p-'0');
            uintptr_t PAGE=4096;
            uintptr_t ist=(addr+PAGE-1)&~(PAGE-1), ien=(addr+(uintptr_t)size)&~(PAGE-1);
            if(ien>ist){
                if(mprotect((void*)ist,(size_t)(ien-ist),PROT_READ)==0){
                    int lk=mlock((void*)ist,(size_t)(ien-ist));
                    if(sealed_n<MAXSEAL){ sealed_start[sealed_n]=ist; sealed_end[sealed_n]=ien; sealed_n++; }
                    wstr("ENFSEAL ufunc_ctx RO "); whex(ist); wstr("-"); whex(ien);
                    wstr(lk==0?" mlock=ok":" mlock=FAIL"); wstr(" size="); wdec((long)size); wstr("\n");
                    struct sigaction sa,old; memset(&sa,0,sizeof sa); sa.sa_handler=segv; sigemptyset(&sa.sa_mask);
                    sigaction(SIGSEGV,&sa,&old);
                    volatile unsigned char*t=(volatile unsigned char*)(ien-PAGE); int f=0;
                    if(sigsetjmp(segjb,1)==0){ *t=0x5A; } else f=1;     /* write last interior page (unused high entry) */
                    sigaction(SIGSEGV,&old,0);
                    wstr("ENFSEAL ufunc_ctx verify direct_write=");
                    wstr(f?"FAULTED(SIGSEGV) integrity=OK\n":"SUCCEEDED integrity=BROKEN\n"); if(!f) g_enf_fail = 1;
                    found=1;
                } else { wstr("ENFSEAL ufunc_ctx mprotect FAIL\n"); g_enf_fail = 1; }
            } else { wstr("ENFSEAL ufunc_ctx too-small-no-interior-page\n"); g_enf_fail = 1; }
        }
        u = nl ? nl+1 : 0;
    }
    if(!found) { wstr("ENFSEAL no-ufunc-target\n"); g_enf_fail = 1; }
}

static void do_seal(int sig){
    (void)sig;
    int fd = open("/proc/self/maps", O_RDONLY);
    if(fd<0){ wstr("SEAL open-maps FAIL\n"); return; }
    static char buf[1<<20]; int n, used=0;
    while((n=read(fd,buf+used,sizeof(buf)-used-1))>0){ used+=n; if(used>=(int)sizeof(buf)-1) break; }
    close(fd); buf[used]=0;
    int sealed=0, skipped=0;
    char *line=buf;
    while(line && *line){
        char *nl=strchr(line,'\n'); if(nl)*nl=0;
        /* format: start-end perms off dev ino path */
        const char *p=line; uintptr_t st=rdhex(&p); if(*p=='-'){p++;} uintptr_t en=rdhex(&p);
        while(*p==' ')p++;
        char r=p[0],w=p[1],x=p[2];
        if(w=='w' && x=='x'){
            /* rwx -> r-x : drop write, keep exec */
            if(mprotect((void*)st,(size_t)(en-st),PROT_READ|PROT_EXEC)==0){
                int lk = mlock((void*)st,(size_t)(en-st));   /* block MADV_DONTNEED discard (EINVAL) */
                if(sealed_n<MAXSEAL){ sealed_start[sealed_n]=st; sealed_end[sealed_n]=en; sealed_n++; }
                sealed++;
                wstr("SEAL rwx->r-x "); whex(st); wstr("-"); whex(en); wstr(lk==0?" mlock=ok\n":" mlock=FAIL\n");
            } else {
                skipped++; wstr("SEAL FAIL "); whex(st); wstr("\n");
            }
        }
        (void)r;
        line = nl ? nl+1 : 0;
    }
    seal_enforce_targets();   /* item-1: ufunc dispatch table RO before ranges are published */
    /* write sealed ranges for the Sentinel to addr-filter munmap/mremap/madvise */
    char rp[64]; { char*q=rp; const char*pre="/tmp/esac_seal_ranges_"; for(const char*s=pre;*s;)*q++=*s++;
        char d[16]; int i=0,v=getpid(); if(v==0)d[i++]='0'; while(v>0){d[i++]='0'+v%10;v/=10;} while(i>0)*q++=d[--i];
        const char*su=".txt"; for(const char*s=su;*s;)*q++=*s++; *q=0; }
    int rf=open(rp,O_CREAT|O_WRONLY|O_TRUNC,0644);
    if(rf>=0){ int save=logfd; logfd=rf; for(int i=0;i<sealed_n;i++){ whex(sealed_start[i]); wstr(" "); whex(sealed_end[i]); wstr("\n"); } logfd=save; close(rf); }
    g_last_sealed = sealed; g_last_fail = skipped + g_enf_fail;
    wstr("SEAL_DONE sealed="); wdec(sealed); wstr(" fail="); wdec(skipped); wstr(" ranges="); wstr(rp); wstr("\n");
}

static void segv(int s){ (void)s; siglongjmp(segjb,1); }

static void do_verify(int sig){
    (void)sig;
    if(sealed_n==0){ wstr("VERIFY no-sealed-region\n"); return; }
    /* install a temporary SIGSEGV catcher and try to write the first byte of a sealed exec page */
    struct sigaction sa, old; memset(&sa,0,sizeof sa); sa.sa_handler=segv; sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV,&sa,&old);
    volatile unsigned char *tgt=(volatile unsigned char*)sealed_start[0];
    unsigned char orig=0; int faulted=0;
    if(sigsetjmp(segjb,1)==0){
        orig=*tgt;            /* read ok (r-x) */
        *tgt = orig ^ 0xAA;   /* WRITE -> must fault on r-x */
        /* if we reach here, write SUCCEEDED (bad) */
        *tgt = orig;          /* restore (won't run if faulted) */
    } else { faulted=1; }
    sigaction(SIGSEGV,&old,0);
    wstr("VERIFY target="); whex((uintptr_t)tgt);
    wstr(faulted?" direct_write=FAULTED(SIGSEGV) integrity=OK\n":" direct_write=SUCCEEDED integrity=BROKEN\n");
}

static void do_vmadv(int sig){
    (void)sig;
    if(sealed_n==0){ wstr("VMADV no-sealed-region\n"); return; }
    int rc = madvise((void*)sealed_start[0], (size_t)(sealed_end[0]-sealed_start[0]), MADV_DONTNEED);
    wstr("VMADV target="); whex(sealed_start[0]);
    if(rc==0) wstr(" madvise_DONTNEED=SUCCEEDED discard=POSSIBLE(mlock missing?)\n");
    else      wstr(" madvise_DONTNEED=EINVAL pre-blocked(mlock) integrity=OK\n");
}

static void do_atk_unmap(int sig){
    (void)sig;
    if(sealed_n==0){ wstr("ATK no-sealed-region\n"); return; }
    wstr("ATK munmap sealed "); whex(sealed_start[0]); wstr("\n");
    /* munlock first so the kernel allows munmap to proceed far enough to reach the tracepoint;
     * the Sentinel's munmap_sealed clause fires at sys_enter and SIGKILLs before this returns. */
    munlock((void*)sealed_start[0],(size_t)(sealed_end[0]-sealed_start[0]));
    munmap((void*)sealed_start[0],(size_t)(sealed_end[0]-sealed_start[0]));
    wstr("ATK munmap RETURNED (Sentinel did NOT kill)\n");   /* reached only if unwatched */
}



/* Request F verification attack (tenant-side, in-model): overwrite every writable word that points into
 * ANONYMOUS executable code (JIT + Frida slices) with the address of a function returning 0. Thread stacks
 * ([stack] and rw regions directly behind a 4 KiB guard page) are skipped. If the hook->filter dispatch
 * still depended on any such pointer, filters would stop running (bypass) or the tenant would crash. */
static unsigned long chap_atk_ret0(void) { return 0; }
static void do_atk_dispatch(int sig){
    (void)sig;
    static char buf[1<<20]; static uintptr_t cs[512], ce[512]; int nc = 0;
    int fd = open("/proc/self/maps", O_RDONLY); if (fd < 0) return;
    int n, used = 0; while ((n = read(fd, buf + used, sizeof(buf) - used - 1)) > 0) { used += n; if (used >= (int)sizeof(buf) - 1) break; }
    close(fd); buf[used] = 0;
    for (char *l = buf; l && *l; ) { char *nl = strchr(l, '\n'); const char *p = l; uintptr_t st = rdhex(&p); if (*p == '-') p++; uintptr_t en = rdhex(&p);
        while (*p == ' ') p++; char r = p[0], x = p[2]; const char *q = p; int f = 0; while (*q && *q != '\n' && f < 5) { if (*q == ' ') { f++; while (*q == ' ') q++; continue; } q++; }
        int anon = (*q == '\n' || *q == 0);
        if (r == 'r' && x == 'x' && anon && nc < 512) { cs[nc] = st; ce[nc] = en; nc++; }
        l = nl ? nl + 1 : 0; }
    long hit = 0; uintptr_t prev_s = 0, prev_e = 0; char prev_perm[5] = {0};
    for (char *l = buf; l && *l; ) { char *nl = strchr(l, '\n'); const char *p = l; uintptr_t st = rdhex(&p); if (*p == '-') p++; uintptr_t en = rdhex(&p);
        while (*p == ' ') p++; char perm[5]; memcpy(perm, p, 4); perm[4] = 0;
        int is_stack = strstr(l, "[stack") && (!nl || strstr(l, "[stack") < nl);
        int behind_guard = prev_perm[0] == '-' && prev_perm[1] == '-' && prev_e == st && (prev_e - prev_s) == 4096;
        if (perm[0] == 'r' && perm[1] == 'w' && !is_stack && !behind_guard && !(strstr(l, "/dev/") && (!nl || strstr(l, "/dev/") < nl))) {
            for (uintptr_t a = st; a + 8 <= en; a += 8) { uintptr_t v = *(volatile uintptr_t *)a;
                for (int i = 0; i < nc; i++) if (v >= cs[i] && v < ce[i]) { *(volatile uintptr_t *)a = (uintptr_t)&chap_atk_ret0; hit++; break; } }
        }
        prev_s = st; prev_e = en; memcpy(prev_perm, perm, 5);
        l = nl ? nl + 1 : 0; }
    wstr("ATK_DISPATCH anon_exec_regions="); wdec(nc); wstr(" writable_words_overwritten="); wdec(hit); wstr("\n");
}

/* file-triggered self-seal: avoids interrupting the app's stdin cmdline with a signal. */
static void *esac_seal_poller(void *arg){
    (void)arg; char tp[96]; int pid=getpid(); char *q=tp;
    const char *pre="/tmp/esac_seal_go_"; for(const char*c=pre;*c;)*q++=*c++;
    { char d[16]; int i=0,v=pid; if(v==0)d[i++]='0'; while(v>0){d[i++]='0'+v%10;v/=10;} while(i>0)*q++=d[--i]; }
    *q=0;
    for(;;){ int fd=open(tp,O_RDONLY); if(fd>=0){ close(fd); do_seal(0); return 0; }
             struct timespec ts={0,100000000}; nanosleep(&ts,0); }
}

__attribute__((constructor))
static void esac_seal_init(void){
    char path[64]; int pid=getpid();
    /* build /tmp/esac_seal_<pid>.log */
    char *q=path; const char*pre="/tmp/esac_seal_"; for(const char*s=pre;*s;)*q++=*s++;
    { char d[16]; int i=0,v=pid; if(v==0)d[i++]='0'; while(v>0){d[i++]='0'+v%10;v/=10;} while(i>0)*q++=d[--i]; }
    const char*suf=".log"; for(const char*s=suf;*s;)*q++=*s++; *q=0;
    logfd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=do_seal;   sigemptyset(&sa.sa_mask); sigaction(SIG_SEAL,&sa,0);
    struct sigaction sv; memset(&sv,0,sizeof sv); sv.sa_handler=do_verify; sigemptyset(&sv.sa_mask); sigaction(SIG_VERIFY,&sv,0);
    { const char *ta = getenv("CHAP_TEST_ATK");   /* Request G: test-only attack handlers inert unless a test run */
      if (ta && ta[0] == '1' && ta[1] == 0) {
    struct sigaction sm; memset(&sm,0,sizeof sm); sm.sa_handler=do_vmadv;  sigemptyset(&sm.sa_mask); sm.sa_flags=SA_RESTART; sigaction(SIG_VMADV,&sm,0);
    struct sigaction sk; memset(&sk,0,sizeof sk); sk.sa_handler=do_atk_unmap; sigemptyset(&sk.sa_mask); sk.sa_flags=SA_RESTART; sigaction(SIG_ATK_UNMAP,&sk,0);
    struct sigaction sd; memset(&sd,0,sizeof sd); sd.sa_handler=do_atk_dispatch; sigemptyset(&sd.sa_mask); sd.sa_flags=SA_RESTART; sigaction(SIG_ATK_DISP,&sd,0);
      } }
    wstr("esac_seal loaded pid="); wdec(pid); wstr(" SIG_SEAL="); wdec(SIG_SEAL); wstr(" SIG_VERIFY="); wdec(SIG_VERIFY); wstr(" SIG_VMADV="); wdec(SIG_VMADV); wstr(" SIG_ATK_UNMAP="); wdec(SIG_ATK_UNMAP); wstr("\n");
    { pthread_t th; if(pthread_create(&th,0,esac_seal_poller,0)==0) pthread_detach(th); }
}

/* Request E item-2: called by the trusted launch barrier (agent bootstrap) BEFORE any untrusted code. */
__attribute__((visibility("default"))) int esac_seal_now(int *sealed, int *fail)
{
    g_enf_fail = 0; do_seal(0);
    if (sealed) *sealed = g_last_sealed;
    if (fail) *fail = g_last_fail;
    return 0;
}

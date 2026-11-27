// Chaperon review #3 HS-ufunc fail-closed unit test. For each case, set the env, dlopen the fixed
// provider (its constructor runs esac_hs_init), then call esac_hs_scan on a 1-item batch and check:
//   init-FAILED (bad regex)     -> esac_hs_init_failed()==1 AND item.act == DROP(2)  (NOT silent allow)
//   OK + matching payload       -> item.act == ESAC_MATCH_ACT(2)                     (match -> verdict)
//   OK + benign payload         -> item.act unchanged (255)                          (NOMATCH, L4 stands)
//   NOT_CONFIGURED (no patterns)-> item.act unchanged (255)                          (no L7)
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/wait.h>
struct esac_hs_item { uint64_t pl_ptr; uint32_t pl_len; uint32_t act; };
static const char *SO = "communication/esac_hs_fullscan_enforce.chap.so";

// run one case in a child (fresh dlopen so the constructor re-runs with the case env). returns exit 0=PASS.
static int run_case(const char *tag, const char *patterns_file, const char *payload, uint32_t expect_act, int expect_initfail){
    pid_t c = fork();
    if (c == 0) {
        if (patterns_file) setenv("ESAC_HS_PATTERNS", patterns_file, 1); else unsetenv("ESAC_HS_PATTERNS");
        setenv("ESAC_MATCH_ACT", "2", 1);
        void *h = dlopen(SO, RTLD_NOW);
        if (!h) { fprintf(stderr, "dlopen fail: %s\n", dlerror()); _exit(10); }
        uint64_t (*scan)(const void*,uint32_t) = dlsym(h, "esac_hs_scan");
        int (*initfail)(void) = dlsym(h, "esac_hs_init_failed");
        if (!scan || !initfail) _exit(11);
        struct esac_hs_item it; it.pl_ptr=(uint64_t)(uintptr_t)payload; it.pl_len=strlen(payload); it.act=255u;
        scan(&it, 1);
        int ifl = initfail();
        int ok = (it.act == expect_act) && (ifl == expect_initfail);
        fprintf(stdout, "  [%s] init_failed=%d item.act=%u (expect act=%u initfail=%d) => %s\n",
                tag, ifl, it.act, expect_act, expect_initfail, ok?"PASS":"FAIL");
        fflush(stdout); _exit(ok?0:1);
    }
    int st; waitpid(c,&st,0); return WIFEXITED(st)?WEXITSTATUS(st):99;
}
int main(void){
    // craft pattern files
    FILE*f=fopen("/tmp/hs_bad.txt","w"); fputs("(unterminated", f); fclose(f);   // invalid HS regex
    f=fopen("/tmp/hs_good.txt","w"); fputs("evilmalware", f); fclose(f);          // valid literal
    int fails=0;
    fails += run_case("init_FAILED_badregex", "/tmp/hs_bad.txt",  "anything here",  2u,   1);
    fails += run_case("OK_match",             "/tmp/hs_good.txt", "GET /evilmalware HTTP", 2u, 0);
    fails += run_case("OK_benign_nomatch",    "/tmp/hs_good.txt", "GET /index.html HTTP",  255u, 0);
    fails += run_case("NOT_CONFIGURED",       NULL,               "anything",       255u, 0);
    printf("\n#3 HS-UFUNC FAIL-CLOSED RESULT: %s (%d failing)\n", fails?"FAIL":"PASS", fails);
    return fails?2:0;
}

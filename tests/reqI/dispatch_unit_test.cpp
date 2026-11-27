// Request I: unit test of the sealed dispatcher's burst handling, compiled from the EXACT code of agent.cpp
// (dispatch_structs.inc + dispatch_excl.inc are extracted verbatim by build_dispatch_unit.sh).
// A fake filter program follows the verdict protocol (frees what it drops); a fake PMD returns short (partial
// return) on demand. Checks return value, consumed prefix, caller-owned suffix, order, no double free / leak.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <optional>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
namespace bpftime {
struct pt_regs { uint64_t r15, r14, r13, r12, bp, bx, r11, r10, r9, r8, ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss; };
namespace attach { thread_local std::optional<std::function<void(uint64_t, uint64_t)>> curr_thread_override_return_callback; }
}
#include "dispatch_structs.inc"
static inline void chap_run_prog(const chap_disp_prog &p, uint64_t func, bpftime::pt_regs &regs) { (void)func; (void)p.fn((void *)&regs, sizeof(regs)); }
#include "dispatch_excl.inc"

struct mb { int id; };
static std::map<void *, int> g_freed;            // freed by the filter (count)
static std::vector<void *> g_sent;               // taken by the PMD, in order
static std::vector<std::string> g_err;
static int g_budget;                             // PMD capacity left (partial return)
static int g_mode;                               // 0 = odd ids dropped, 1 = all dropped, 2 = none dropped
static bool drop_of(void *p) { int id = ((mb *)p)->id; return g_mode == 1 ? true : g_mode == 2 ? false : (id & 1); }
static void free_one(void *p) { if (g_freed[p]++) g_err.push_back("double free id " + std::to_string(((mb *)p)->id)); }

/* TX filter: window of <= 32 from (rsi, rdx); drop odd ids; free dropped; 64-bit verdict */
static uint64_t fake_tx_prog(void *ctx, uint64_t)
{
    auto *r = (bpftime::pt_regs *)ctx;
    if (r->orig_ax != CHAP_TXEXCL_ADV) return 0;
    void **pk = (void **)r->si; uint32_t n = (uint16_t)r->dx, w = n < 32 ? n : 32, mask = 0;
    for (uint32_t i = 0; i < w; i++) if (drop_of(pk[i])) { mask |= 1u << i; free_one(pk[i]); }
    if (w) bpftime::attach::curr_thread_override_return_callback.value()(0, (CHAP_TXEXCL_TAG << 48) | ((uint64_t)w << 32) | mask);
    return 0;
}
static uint64_t fake_tx_pmd(uint64_t, uint64_t pkts, uint64_t n, uint64_t, uint64_t, uint64_t)
{
    void **pk = (void **)pkts; uint32_t m = (uint16_t)n, k = 0;
    for (; k < m && g_budget > 0; k++, g_budget--) {
        if (g_freed.count(pk[k])) g_err.push_back("PMD got a freed mbuf id " + std::to_string(((mb *)pk[k])->id));
        if (drop_of(pk[k])) g_err.push_back("PMD got a DROP packet id " + std::to_string(((mb *)pk[k])->id));
        g_sent.push_back(pk[k]);
    }
    return k;
}

static int tx_case(const char *name, int n, int budget, int mode)
{
    g_freed.clear(); g_sent.clear(); g_err.clear(); g_budget = budget; g_mode = mode;
    std::vector<mb> store(n); std::vector<void *> arr(n);
    for (int i = 0; i < n; i++) { store[i].id = i; arr[i] = &store[i]; }
    chap_disp_slot s; memset(&s, 0, sizeof s); s.orig = fake_tx_pmd; s.n_enter = 1; s.enter[0].fn = fake_tx_prog; s.excl = 1;
    bpftime::pt_regs regs; memset(&regs, 0, sizeof regs);
    uint32_t ret = (uint32_t)chap_dispatch_excl(&s, 0, (uint64_t)arr.data(), (uint64_t)n, 0, 0, 0, regs);
    /* expected: windows of 32; per window d dropped (freed) + sent; stop when the PMD takes fewer than allowed */
    int exp = 0, b = budget;
    for (int off = 0; off < n; off += 32) { int w = n - off < 32 ? n - off : 32, d = 0; for (int i = off; i < off + w; i++) d += drop_of(&store[i]);
        int m = w - d, sent = m < b ? m : b; b -= sent; exp += d + sent; if (sent < m) break; }
    std::map<void *, int> seen; int bad = 0;
    for (int i = 0; i < n; i++) seen[arr[i]]++;
    for (auto &kv : seen) if (kv.second != 1) bad++;                                   // array stays a permutation
    for (uint32_t i = 0; i < ret; i++) if (!g_freed.count(arr[i]) && std::find(g_sent.begin(), g_sent.end(), arr[i]) == g_sent.end())
        g_err.push_back("consumed prefix holds an unconsumed mbuf id " + std::to_string(((mb *)arr[i])->id));
    for (uint32_t i = ret; i < (uint32_t)n; i++) if (g_freed.count(arr[i]) || std::find(g_sent.begin(), g_sent.end(), arr[i]) != g_sent.end())
        g_err.push_back("caller-owned suffix holds a consumed mbuf id " + std::to_string(((mb *)arr[i])->id));
    for (size_t i = 1; i < g_sent.size(); i++) if (((mb *)g_sent[i])->id < ((mb *)g_sent[i - 1])->id) g_err.push_back("send order changed");
    /* caller then owns arr[ret..n): freed by the app or retried -> every mbuf ends in exactly one place */
    size_t total = g_freed.size() + g_sent.size() + (n - ret);
    if ((int)total != n) g_err.push_back("ownership sum " + std::to_string(total) + " != " + std::to_string(n));
    bool ok = (int)ret == exp && !bad && g_err.empty();
    printf("  TX %-34s n=%-3d pmd_budget=%-4d ret=%-3u (expected %-3d) freed=%-3zu sent=%-3zu caller_owned=%-3d  %s\n",
           name, n, budget, ret, exp, g_freed.size(), g_sent.size(), n - (int)ret, ok ? "PASS" : "FAIL");
    for (auto &e : g_err) printf("      %s\n", e.c_str());
    return ok ? 0 : 1;
}

/* RX: the PMD returns n packets; the exit program judges windows; the dispatcher compacts */
static int g_rx_n, g_rx_failwin;
static std::vector<mb> g_rx_store;
static uint64_t fake_rx_pmd(uint64_t, uint64_t pkts, uint64_t, uint64_t, uint64_t, uint64_t)
{ void **pk = (void **)pkts; for (int i = 0; i < g_rx_n; i++) pk[i] = &g_rx_store[i]; return g_rx_n; }
static uint64_t fake_rx_prog(void *ctx, uint64_t)
{
    auto *r = (bpftime::pt_regs *)ctx;
    if (r->orig_ax != CHAP_RXEXCL_ADV) return 0;                       // legacy: no verdict
    void **pk = (void **)r->si; uint32_t rem = (uint16_t)r->ax, w = rem < 32 ? rem : 32, mask = 0;
    int win = (int)(((mb *)pk[0])->id / 32);
    if (g_rx_failwin >= 0 && win == g_rx_failwin) mask = w >= 32 ? 0xffffffffu : ((1u << w) - 1u);   // inspection failed: withhold, no free
    else for (uint32_t i = 0; i < w; i++) if (drop_of(pk[i])) { mask |= 1u << i; free_one(pk[i]); }
    bpftime::attach::curr_thread_override_return_callback.value()(0, (CHAP_RXEXCL_TAG << 48) | ((uint64_t)w << 32) | mask);
    return 0;
}
static int rx_case(const char *name, int n, int mode, int failwin, bool legacy)
{
    g_freed.clear(); g_err.clear(); g_mode = mode; g_rx_n = n; g_rx_failwin = failwin; g_rx_store.assign(n, mb{});
    for (int i = 0; i < n; i++) g_rx_store[i].id = i;
    std::vector<void *> arr(n ? n : 1, nullptr);
    chap_disp_slot s; memset(&s, 0, sizeof s); s.orig = fake_rx_pmd; s.n_exit = 1; s.exit[0].fn = legacy ? (uint64_t (*)(void *, uint64_t))[](void *, uint64_t) -> uint64_t { return 0; } : fake_rx_prog; s.excl = 2;
    bpftime::pt_regs regs; memset(&regs, 0, sizeof regs);
    uint32_t ret = (uint32_t)chap_dispatch_rx(&s, 0, (uint64_t)arr.data(), 128, 0, 0, 0, regs);
    std::vector<int> expect; for (int i = 0; i < n; i++) { if (legacy) { expect.push_back(i); continue; }
        bool withheld = failwin >= 0 && i / 32 == failwin; if (!withheld && !drop_of(&g_rx_store[i])) expect.push_back(i); }
    bool ok = ret == expect.size();
    for (uint32_t i = 0; ok && i < ret; i++) if (((mb *)arr[i])->id != expect[i]) { ok = false; g_err.push_back("delivered order/content differs at " + std::to_string(i)); }
    for (uint32_t i = 0; i < ret; i++) if (g_freed.count(arr[i])) g_err.push_back("delivered a freed mbuf");
    int dropped = 0; for (int i = 0; i < n; i++) if (!legacy && !(failwin >= 0 && i / 32 == failwin) && drop_of(&g_rx_store[i])) dropped++;
    if ((int)g_freed.size() != dropped) g_err.push_back("freed " + std::to_string(g_freed.size()) + " != dropped " + std::to_string(dropped));
    ok = ok && g_err.empty();
    printf("  RX %-34s n=%-3d ret=%-3u (expected %-3zu) freed=%-3zu  %s\n", name, n, ret, expect.size(), g_freed.size(), ok ? "PASS" : "FAIL");
    for (auto &e : g_err) printf("      %s\n", e.c_str());
    return ok ? 0 : 1;
}

static uint64_t bad_tx_prog(void *ctx, uint64_t)
{ auto *r = (bpftime::pt_regs *)ctx; (void)r; bpftime::attach::curr_thread_override_return_callback.value()(0, (CHAP_TXEXCL_TAG << 48) | 0ULL); return 0; }
static int malformed_case(void)
{
    pid_t c = fork();
    if (c == 0) { std::vector<mb> st(8); std::vector<void *> arr(8); for (int i = 0; i < 8; i++) { st[i].id = i; arr[i] = &st[i]; }
        chap_disp_slot s; memset(&s, 0, sizeof s); s.orig = fake_tx_pmd; s.n_enter = 1; s.enter[0].fn = bad_tx_prog; s.excl = 1;
        bpftime::pt_regs regs; memset(&regs, 0, sizeof regs); g_budget = 100; chap_dispatch_excl(&s, 0, (uint64_t)arr.data(), 8, 0, 0, 0, regs); _exit(0); }
    int st; waitpid(c, &st, 0); bool ok = WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL;
    printf("  TX %-34s -> %s  %s\n", "malformed verdict (window 0)", ok ? "SIGKILL (fail-stop)" : "not killed", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

int main()
{
    int f = 0;
    printf("-- TX burst exclusion (chap_dispatch_excl) --\n");
    f += tx_case("mixed, PMD takes all", 32, 1000, 0);
    f += tx_case("mixed, PARTIAL in window 1", 32, 5, 0);
    f += tx_case("mixed n=128, PARTIAL in window 3", 128, 40, 0);
    f += tx_case("mixed n=64, PMD takes 0", 64, 0, 0);
    f += tx_case("all drop n=64 (PMD not called)", 64, 0, 1);
    f += tx_case("all allow n=128, PARTIAL at 100", 128, 100, 2);
    f += tx_case("n=0", 0, 10, 0);
    f += malformed_case();
    printf("-- RX window compaction (chap_dispatch_rx) --\n");
    f += rx_case("mixed n=128", 128, 0, -1, false);
    f += rx_case("all drop n=128", 128, 1, -1, false);
    f += rx_case("all allow n=96", 96, 2, -1, false);
    f += rx_case("mixed n=100, window 2 fails (withheld)", 100, 0, 2, false);
    f += rx_case("legacy filter (no verdict)", 64, 0, -1, true);
    printf("\nDISPATCH_UNIT RESULT: %s (%d failing)\n", f ? "FAIL" : "PASS", f);
    return f ? 2 : 0;
}

/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#include "bpf_attach_ctx.hpp"
#if BPFTIME_HAVE_TRAP_UPROBE_ATTACH
#include "trap_uprobe_attach_impl.hpp"
#endif
#include "handler/map_handler.hpp"
#include "linux/bpf.h"
#include <algorithm>
#include <stdexcept>
#include <system_error>
#if __APPLE__
#include <cstdint>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#elif __linux__
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#endif
#ifdef BPFTIME_BUILD_WITH_LIBBPF
#include "bpf/bpf.h"
#include "bpf/libbpf_common.h"
#endif
#include "bpftime_helper_group.hpp"
#include <cerrno>
#ifdef ENABLE_BPFTIME_VERIFIER
#include "bpftime-verifier.hpp"
#endif

#include "platform_utils.hpp"
#include "spdlog/spdlog.h"
#include <map>
#include <stdio.h>
#include <stdarg.h>
#include <cstring>
#include <time.h>
#include <unistd.h>
#include <ctime>
#include <filesystem>
#include "bpftime.hpp"
#include "bpftime_shm.hpp"
#include "bpftime_internal.h"
#include "extension/userspace_xdp.h"
#include <spdlog/spdlog.h>
#include <vector>
#include <bpftime_shm_internal.hpp>
#include <chrono>
#include <thread>

#define PATH_MAX 4096

using namespace std;
bpftime::bpf_attach_ctx &get_global_attach_ctx();
__attribute__((weak)) bpftime::bpf_attach_ctx &get_global_attach_ctx()
{
	SPDLOG_WARN(
		"Calling mocked get_global_attach_ctx, this is not expected");
	throw std::runtime_error(
		"Calling mocked get_global_attach_ctx, this is not expected");
}
extern "C" {

#if __linux__ && \
	(defined(ENABLE_PROBE_READ_CHECK) || defined(ENABLE_PROBE_WRITE_CHECK))
static pid_t probe_access_pid = getpid();
static const int probe_access_atfork_status = pthread_atfork(
	nullptr, nullptr, [] { probe_access_pid = getpid(); });
#endif

uint64_t bpftime_override_return(uint64_t ctx, uint64_t value);
uint64_t bpftime_set_retval(uint64_t retval);

uint64_t bpftime_trace_printk(uint64_t fmt, uint64_t fmt_size, ...)
{
	const char *fmt_str = (const char *)fmt;
	va_list args;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wvarargs"
	va_start(args, fmt_str);
	long ret = vprintf(fmt_str, args);
#pragma GCC diagnostic pop
	va_end(args);
	return 0;
}

long bpftime_strncmp(const char *s1, uint64_t s1_sz, const char *s2)
{
	return strncmp(s1, s2, s1_sz);
}

#ifdef ENABLE_PROBE_READ_CHECK
#include <csignal>
#include <csetjmp>
#if __linux__
/* Signal-handler based fast-path for probe_read_memory() on Linux.
 *
 * bpf_probe_read_user() reads arbitrary runtime-computed userspace
 * pointers whose validity nothing can prove statically -- the same reason
 * real kernel eBPF implements this helper as a fault-safe copy_from_user()
 * rather than a raw pointer dereference. The original implementation here
 * used a real process_vm_readv() syscall for that safety, which costs a
 * full user->kernel->user round trip on every call -- unnecessary when (as
 * in bpftime's actual use case: an in-process agent) the target address is
 * in the SAME process's own memory, reachable by direct access.
 *
 * This replaces that syscall with the same fault-safety guarantee via
 * sigsetjmp/siglongjmp: install a SIGSEGV/SIGBUS handler once; on the
 * (overwhelmingly common) case where the pointer is valid, this costs a
 * sigsetjmp + memcpy, no syscall at all. On a genuine bad pointer, the
 * hardware fault is caught and returned as -EFAULT, same external
 * behavior as before, much cheaper in the common case.
 *
 * Thread safety: the recovery point and "read in progress" flag are
 * thread_local, since Linux delivers a synchronous fault (from a bad
 * memory access instruction) to the exact thread that caused it -- correct
 * even with multiple concurrently-running threads (e.g. DPDK lcore
 * workers) each doing their own probe reads.
 *
 * A genuine, unrelated SIGSEGV/SIGBUS elsewhere in the process (not from
 * an active probe_read_memory call) is NOT swallowed: this handler chains
 * to whatever handler/default action was previously installed for that
 * signal, exactly as if this code weren't here.
 */
static thread_local sigjmp_buf probe_read_jmpbuf;
static thread_local volatile sig_atomic_t probe_read_active = 0;
static struct sigaction probe_read_old_segv;
static struct sigaction probe_read_old_bus;

static void probe_read_fault_handler(int sig, siginfo_t *info, void *ucontext)
{
        if (probe_read_active) {
                siglongjmp(probe_read_jmpbuf, 1);
        }
        struct sigaction *old =
                (sig == SIGBUS) ? &probe_read_old_bus : &probe_read_old_segv;
        if ((old->sa_flags & SA_SIGINFO) && old->sa_sigaction) {
                old->sa_sigaction(sig, info, ucontext);
                return;
        }
        if (old->sa_handler && old->sa_handler != SIG_DFL &&
            old->sa_handler != SIG_IGN) {
                old->sa_handler(sig);
                return;
        }
        signal(sig, SIG_DFL);
}

static void probe_read_install_handlers_once()
{
        static const bool installed = [] {
                struct sigaction act = {};
                act.sa_sigaction = probe_read_fault_handler;
                act.sa_flags = SA_SIGINFO;
                sigemptyset(&act.sa_mask);
                sigaction(SIGSEGV, &act, &probe_read_old_segv);
                sigaction(SIGBUS, &act, &probe_read_old_bus);
                return true;
        }();
        (void)installed;
}
#endif
static bool probe_read_memory(void *dst, const void *src, size_t size)
{
        if (size == 0)
                return true;
#if __APPLE__
        mach_vm_size_t copied = 0;
        return mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)src,
                                      (mach_vm_size_t)size,
                                      (mach_vm_address_t)dst,
                                      &copied) == KERN_SUCCESS &&
               copied == size;
#elif __linux__
        probe_read_install_handlers_once();
        probe_read_active = 1;
        /* savesigs=0 (plain setjmp-equivalent): skips saving/restoring the
         * signal mask via sigprocmask, which sigsetjmp(...,1) does on every
         * single call. This is the hot path (called twice per packet) and a
         * genuine fault here should never happen for valid packet pointers,
         * so we don't pay mask save/restore cost for the common case. If a
         * real fault does occur, SIGSEGV/SIGBUS may remain blocked after
         * recovery (kernel auto-blocks the signal for the handler's duration
         * and only auto-unblocks via a normal sigreturn, which siglongjmp
         * bypasses) -- acceptable here since a genuine fault indicates a bug
         * elsewhere and the process is not relied on to keep handling faults
         * indefinitely afterward. */
        if (sigsetjmp(probe_read_jmpbuf, 0) != 0) {
                probe_read_active = 0;
                return false;
        }
        memcpy(dst, src, size);
        probe_read_active = 0;
        return true;
#else
#error "Probe memory checks are unsupported on this platform"
#endif
}
#endif

int64_t bpftime_probe_read(uint64_t dst, int64_t size, uint64_t ptr, uint64_t,
			   uint64_t)
{
	if (unlikely(size < 0)) {
		SPDLOG_ERROR("Invalid size: {}", size);
		return -EFAULT;
	}
#ifdef ENABLE_PROBE_READ_CHECK
	return probe_read_memory((void *)dst, (void *)ptr, (size_t)size) ?
		       0 :
		       -EFAULT;
#else
	memcpy((void *)dst, (void *)ptr, (size_t)size);
	return 0;
#endif
}

#if defined(ENABLE_PROBE_WRITE_CHECK) || defined(ENABLE_PROBE_READ_CHECK)
static bool probe_write_memory(void *dst, const void *src, size_t size)
{
	if (size == 0)
		return true;
#if __APPLE__
	mach_vm_size_t copied = 0;
	return mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)src,
				      (mach_vm_size_t)size,
				      (mach_vm_address_t)dst,
				      &copied) == KERN_SUCCESS &&
	       copied == size;
#elif __linux__
	struct iovec local = { const_cast<void *>(src), size };
	struct iovec remote = { dst, size };
	return syscall(SYS_process_vm_writev,
		       probe_access_atfork_status == 0 ? probe_access_pid : getpid(),
		       &local, 1, &remote, 1, 0) == (ssize_t)size;
#else
#error "Probe memory checks are unsupported on this platform"
#endif
}
#endif

int64_t bpftime_probe_write_user(uint64_t dst, uint64_t src, int64_t len,
				 uint64_t, uint64_t)
{
	if (unlikely(len < 0)) {
		SPDLOG_ERROR("Invalid len: {}", len);
		return -EFAULT;
	}
#ifdef ENABLE_PROBE_WRITE_CHECK
	return probe_write_memory((void *)dst, (void *)src, (size_t)len) ?
		       0 :
		       -EFAULT;
#else
	memcpy((void *)dst, (void *)src, (size_t)len);
	return 0;
#endif
}

uint64_t bpftime_get_prandom_u32()
{
	return (uint32_t)rand();
}

uint64_t bpftime_ktime_get_coarse_ns(uint64_t, uint64_t, uint64_t, uint64_t,
				     uint64_t)
{
	timespec spec;
#ifdef __APPLE__
	clock_gettime(CLOCK_MONOTONIC, &spec); // or CLOCK_MONOTONIC_RAW
#else
	clock_gettime(CLOCK_MONOTONIC_COARSE, &spec);
#endif
	return spec.tv_sec * (uint64_t)1000000000 + spec.tv_nsec;
}

uint64_t bpftime_ktime_get_boot_ns(uint64_t, uint64_t, uint64_t, uint64_t,
				   uint64_t)
{
	timespec spec{};
#ifdef CLOCK_BOOTTIME
	if (clock_gettime(CLOCK_BOOTTIME, &spec) == 0)
		return spec.tv_sec * (uint64_t)1000000000 + spec.tv_nsec;
#endif
	clock_gettime(CLOCK_MONOTONIC, &spec);
	return spec.tv_sec * (uint64_t)1000000000 + spec.tv_nsec;
}

// bpf_get_current_pid_tgid caches the identity so it does not pay a syscall on
// every call. The cache cannot be function-local: a forked child inherits the
// parent's cached values, and would report the parent's pid and tid. These live
// at file scope so the fork handler can refresh them in the child.
static pid_t bpftime_cached_tgid = getpid();
#if __linux__
static thread_local int bpftime_cached_tid = -1;
#elif __APPLE__
static thread_local uint64_t bpftime_cached_tid = UINT64_MAX;
#endif

static void bpftime_refresh_cached_identity_in_child()
{
	bpftime_cached_tgid = getpid();
	// tid is meaningless in the child; the next helper call refills it.
#if __linux__
	bpftime_cached_tid = -1;
#elif __APPLE__
	bpftime_cached_tid = UINT64_MAX;
#endif
}

static const int bpftime_identity_atfork_status = pthread_atfork(
	nullptr, nullptr, bpftime_refresh_cached_identity_in_child);

uint64_t bpftime_get_current_pid_tgid(uint64_t, uint64_t, uint64_t, uint64_t,
				      uint64_t)
{
	// If registering the fork handler failed, the cache is still the
	// parent's after a fork, so read the identity directly. The probe
	// access cache above falls back the same way.
	if (bpftime_identity_atfork_status != 0) {
#if __linux__
		return ((uint64_t)getpid() << 32) |
		       static_cast<uint32_t>(syscall(SYS_gettid));
#elif __APPLE__
		uint64_t tid = 0;
		pthread_threadid_np(NULL, &tid);
		return ((uint64_t)getpid() << 32) | tid;
#endif
	}
#if __linux__
	if (bpftime_cached_tid == -1) {
		bpftime_cached_tid = static_cast<int>(syscall(SYS_gettid));
	}
#elif __APPLE__
	if (bpftime_cached_tid == UINT64_MAX) {
		pthread_threadid_np(NULL, &bpftime_cached_tid);
	}
#endif
	return ((uint64_t)bpftime_cached_tgid << 32) | bpftime_cached_tid;
}

uint64_t bpf_get_current_uid_gid(uint64_t, uint64_t, uint64_t, uint64_t,
				 uint64_t)
{
	static int gid = getgid();
	return (((uint64_t)gid) << 32) | gid;
}

uint64_t bpftime_ktime_get_ns(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	auto now = std::chrono::steady_clock::now();
	auto ns = std::chrono::time_point_cast<std::chrono::nanoseconds>(now);
	return ns.time_since_epoch().count();
}

uint64_t bpftime_get_current_comm(uint64_t buf, uint64_t size, uint64_t,
				  uint64_t, uint64_t)
{
	static std::string filename_buf;

	if (unlikely(filename_buf.empty())) {
		char strbuf[PATH_MAX];

		auto len = readlink("/proc/self/exe", strbuf,
				    std::size(strbuf) - 1);
		if (len == -1)
			return 1;
		strbuf[len] = 0;
		auto str = std::string_view(strbuf);
		auto last_slash = str.find_last_of('/');

		auto filename = std::string(str.substr(last_slash + 1));
		filename_buf = filename;
	}
	strncpy((char *)(uintptr_t)buf, filename_buf.c_str(), (size_t)size);
	return 0;
}


// ===================== Chaperon Request-E item-1: IMMUTABLE ENFORCEMENT VIEW =====================
// After the trusted bootstrap, the routing the JIT'd filters use to reach their maps (map type, data base,
// geometry; kernel-array RO-mmap base; .rodata config) is copied into private pages that are made
// READ-ONLY + mlock'd and registered with the Tamper Sentinel. The selector (view ptr + sealed flag) lives
// in its own RO page. Once sealed, the map helpers resolve ONLY through this view (fail-closed for unknown
// fds) and never read the SHM handler_manager / map_handler / impl objects for these maps. Writable DATA
// buffers (per-burst pending, scratch, stats) stay writable by design; only their routing is immutable.
#include <sys/mman.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <mutex>
namespace chap_imm {
enum : uint32_t { CK_NONE = 0, CK_KARRAY = 1, CK_RODATA = 2, CK_PERCPU = 3, CK_ARRAY = 4, CK_PASSTHRU = 5 };
struct ent { uint32_t kind, value_size, max_entries, ncpu, map_type, kernel_id; uint8_t *base; };
struct view { uint64_t magic; uint32_t n; uint32_t pad; ent e[1]; };
struct rocopy { int fd; uint8_t *copy; size_t len, maplen; };
static rocopy g_ro[16];
static int g_ro_n = 0;
static std::mutex g_ro_mu;
static sigjmp_buf g_jb;
static void segv_jmp(int) { siglongjmp(g_jb, 1); }
static int write_faults(volatile unsigned char *p)
{
	struct sigaction sa, old; memset(&sa, 0, sizeof sa); sa.sa_handler = segv_jmp; sigemptyset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, &old); int f = 0;
	if (sigsetjmp(g_jb, 1) == 0) { unsigned char o = *p; *p = (unsigned char)(o ^ 0x5a); *p = o; } else f = 1;
	sigaction(SIGSEGV, &old, nullptr); return f;
}
static bool ends_with(const char *s, const char *suf)
{ size_t a = strlen(s), b = strlen(suf); return a >= b && !strcmp(s + a - b, suf); }
} // namespace chap_imm

extern "C" {
struct alignas(4096) chap_ro_page_t {
	uint64_t magic; const chap_imm::view *view; uint64_t sealed; uint64_t view_len;
	unsigned char pad[4096 - 32];
};
__attribute__((visibility("default"))) chap_ro_page_t chap_ro_page;   // one dedicated page, sealed RO
}
static_assert(sizeof(chap_ro_page_t) == 4096, "selector page must be exactly one page");

// map_val() hook: give the JIT a pointer into a PRIVATE copy of a read-only (.rodata) array instead of
// the writable SHM storage. Called only during trusted init (before seal).
extern "C" void *chap_imm_rodata_copy(int fd, const void *src, size_t len)
{
	if (!getenv("CHAP_IMM_VIEW") || !src || !len) return nullptr;
	std::lock_guard<std::mutex> lk(chap_imm::g_ro_mu);
	for (int i = 0; i < chap_imm::g_ro_n; i++)
		if (chap_imm::g_ro[i].fd == fd) return chap_imm::g_ro[i].copy;
	if (chap_imm::g_ro_n >= 16 || chap_ro_page.sealed) return nullptr;
	size_t ml = (len + 4095) & ~(size_t)4095;
	void *p = mmap(nullptr, ml, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return nullptr;
	memcpy(p, src, len);
	chap_imm::g_ro[chap_imm::g_ro_n++] = { fd, (uint8_t *)p, len, ml };
	return p;
}

extern "C" void chap_helper_addrs(uintptr_t out[3]);   // defined after the helpers (measurement)

static int chap_find_mapping(uintptr_t a, uintptr_t *s, uintptr_t *e, char perm[5])
{
	FILE *m = fopen("/proc/self/maps", "r"); if (!m) return -1; char ln[512]; int ok = -1;
	while (fgets(ln, sizeof ln, m)) { unsigned long x, y; char p[5] = { 0 };
		if (sscanf(ln, "%lx-%lx %4s", &x, &y, p) == 3 && a >= x && a < y) { *s = x; *e = y; memcpy(perm, p, 5); ok = 0; break; } }
	fclose(m); return ok;
}

// Build the immutable view from the (trusted, not-yet-tampered) bootstrap state, seal it, and publish it.
extern "C" int chap_imm_view_seal(char *err, size_t errlen, const char *ranges_path, const char *report_path)
{
	using namespace bpftime;
	using namespace chap_imm;
	auto &shm = shm_holder.global_shared_memory;
	auto *mgr = shm.get_manager();
	if (!mgr) { snprintf(err, errlen, "no_manager"); return -1; }
	if (chap_ro_page.sealed) { snprintf(err, errlen, "already_sealed"); return -1; }
	uint32_t n = (uint32_t)mgr->size();
	size_t vlen = (offsetof(view, e) + (size_t)n * sizeof(ent) + 4095) & ~(size_t)4095;
	auto *v = (view *)mmap(nullptr, vlen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (v == MAP_FAILED) { snprintf(err, errlen, "view_mmap"); return -1; }
	v->magic = 0x4348415056494557ULL; v->n = n;
	FILE *rep = report_path ? fopen(report_path, "w") : nullptr;
	FILE *rng = ranges_path ? fopen(ranges_path, "w") : nullptr;
	uint32_t zero = 0; long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	int cnt[6] = { 0 };
	for (uint32_t fd = 0; fd < n; fd++) {
		if (!shm.is_map_fd((int)fd)) continue;
		const auto &hd = std::get<bpf_map_handler>(shm.get_handler((int)fd));
		ent &e = v->e[fd];
		e.map_type = (uint32_t)hd.type; e.value_size = hd.get_value_size();
		e.max_entries = hd.get_max_entries(); e.kernel_id = hd.attr.kernel_bpf_map_id;
		const char *nm = hd.name.c_str();
		switch (hd.type) {
		case bpftime::bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
			auto *b = (uint8_t *)hd.map_lookup_elem(&zero, false);
			if (!b) { snprintf(err, errlen, "karray_uninit:%s", nm); goto fail; }
			e.kind = CK_KARRAY; e.base = b;
			uintptr_t ms, me; char perm[5];
			if (chap_find_mapping((uintptr_t)b, &ms, &me, perm) || perm[1] == 'w') { snprintf(err, errlen, "karray_not_ro:%s", nm); goto fail; }
			// writable-alias probe: upgrading the RO kernel-map mapping must be refused by the kernel
			if (mprotect((void *)ms, me - ms, PROT_READ | PROT_WRITE) == 0) {
				mprotect((void *)ms, me - ms, PROT_READ); snprintf(err, errlen, "karray_upgradable:%s", nm); goto fail; }
			int pe = errno;
			if (rep) fprintf(rep, "KARRAY_RO fd=%u name=%s map=[%#lx,%#lx) perm=%s mprotect(RW)=refused errno=%d\n", fd, nm, ms, me, perm, pe);
			if (rng) fprintf(rng, "0x%lx 0x%lx\n", ms, me);
			break; }
		case bpftime::bpf_map_type::BPF_MAP_TYPE_ARRAY: {
			bool ro = (hd.attr.flags & 0x80 /*BPF_F_RDONLY_PROG*/) || ends_with(nm, ".rodata");
			auto *b = (uint8_t *)hd.map_lookup_elem(&zero, false);
			if (!b) { snprintf(err, errlen, "array_uninit:%s", nm); goto fail; }
			if (ro) {
				size_t len = (size_t)e.value_size * e.max_entries;
				auto *c = (uint8_t *)chap_imm_rodata_copy((int)fd, b, len);
				if (!c) { snprintf(err, errlen, "rodata_copy:%s", nm); goto fail; }
				if (memcmp(c, b, len)) { snprintf(err, errlen, "rodata_changed_since_jit:%s", nm); goto fail; }
				e.kind = CK_RODATA; e.base = c;
			} else { e.kind = CK_ARRAY; e.base = b; }
			break; }
		case bpftime::bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
			auto *b = (uint8_t *)hd.map_lookup_elem(&zero, true);     // data_at(0, 0)
			auto *cur = (uint8_t *)hd.map_lookup_elem(&zero, false);  // data_at(0, cpu)
			int cpu = my_sched_getcpu();
			if (!b || !cur || cpu < 0 || ncpu <= 0 || cur != b + (size_t)cpu * e.value_size) {
				snprintf(err, errlen, "percpu_layout:%s", nm); goto fail; }
			e.kind = CK_PERCPU; e.base = b; e.ncpu = (uint32_t)ncpu;
			break; }
		default: e.kind = CK_PASSTHRU; break;   // ringbuf (event output, result unused) / unattached hash
		}
		cnt[e.kind]++;
		if (rep) fprintf(rep, "VIEW fd=%u name=%s type=%u kind=%u base=%p vs=%u max=%u ncpu=%u kid=%u\n",
				 fd, nm, e.map_type, e.kind, (void *)e.base, e.value_size, e.max_entries, e.ncpu, e.kernel_id);
	}
	// seal: view -> RO copies -> selector page (publish last)
	if (mprotect(v, vlen, PROT_READ) || mlock(v, vlen)) { snprintf(err, errlen, "view_seal"); goto fail; }
	if (rng) fprintf(rng, "0x%lx 0x%lx\n", (unsigned long)v, (unsigned long)v + vlen);
	for (int i = 0; i < g_ro_n; i++) {
		if (mprotect(g_ro[i].copy, g_ro[i].maplen, PROT_READ) || mlock(g_ro[i].copy, g_ro[i].maplen)) { snprintf(err, errlen, "rodata_seal"); goto fail; }
		if (rng) fprintf(rng, "0x%lx 0x%lx\n", (unsigned long)g_ro[i].copy, (unsigned long)g_ro[i].copy + g_ro[i].maplen);
		if (rep) fprintf(rep, "RODATA_COPY fd=%d copy=[%p,+%zu) len=%zu RO+mlock\n", g_ro[i].fd, (void *)g_ro[i].copy, g_ro[i].maplen, g_ro[i].len);
	}
	chap_ro_page.magic = 0x4348415053454cULL; chap_ro_page.view = v; chap_ro_page.view_len = vlen;
	__atomic_store_n(&chap_ro_page.sealed, 1, __ATOMIC_SEQ_CST);
	if (mprotect(&chap_ro_page, 4096, PROT_READ) || mlock(&chap_ro_page, 4096)) { snprintf(err, errlen, "selector_seal"); return -1; }
	if (rng) { fprintf(rng, "0x%lx 0x%lx\n", (unsigned long)&chap_ro_page, (unsigned long)&chap_ro_page + 4096); fclose(rng); rng = nullptr; }
	{ // self-verify: direct writes to each sealed object must fault (writes target padding, never live data)
		int f1 = write_faults((volatile unsigned char *)&chap_ro_page.pad[0]);
		int f2 = write_faults((volatile unsigned char *)&v->pad);
		int f3 = 1; for (int i = 0; i < g_ro_n; i++) f3 &= write_faults((volatile unsigned char *)(g_ro[i].copy + g_ro[i].maplen - 1));
		if (rep) fprintf(rep, "SEALCHECK selector_write=%s view_write=%s rodata_write=%s\n",
				 f1 ? "FAULTED" : "SUCCEEDED", f2 ? "FAULTED" : "SUCCEEDED", f3 ? "FAULTED" : "SUCCEEDED");
		if (!(f1 && f2 && f3)) { snprintf(err, errlen, "sealcheck"); if (rep) fclose(rep); return -1; }
	}
	if (rep) { fprintf(rep, "VIEW_SEALED n=%u karray=%d rodata=%d percpu=%d array=%d passthru=%d selector=%p view=[%p,+%zu)\n",
			 n, cnt[CK_KARRAY], cnt[CK_RODATA], cnt[CK_PERCPU], cnt[CK_ARRAY], cnt[CK_PASSTHRU], (void *)&chap_ro_page, (void *)v, vlen); fclose(rep); }
	return 0;
fail:
	if (rep) { fprintf(rep, "VIEW_FAIL %s\n", err); fclose(rep); }
	if (rng) fclose(rng);
	return -1;
}

static inline const chap_imm::ent *chap_ent(int fd)
{
	const chap_imm::view *v = chap_ro_page.view;
	if (!v || (uint32_t)fd >= v->n) return nullptr;
	const chap_imm::ent *e = &v->e[fd];
	return e->kind ? e : nullptr;
}
static inline uint8_t *chap_elem(const chap_imm::ent *e, const void *key)
{
	if (!key) return nullptr;
	uint32_t k = *(const uint32_t *)key;
	if (k >= e->max_entries) return nullptr;
	switch (e->kind) {
	case chap_imm::CK_KARRAY: case chap_imm::CK_RODATA: case chap_imm::CK_ARRAY:
		return e->base + (size_t)k * e->value_size;
	case chap_imm::CK_PERCPU: {
		int cpu = my_sched_getcpu();
		if (cpu < 0 || (uint32_t)cpu >= e->ncpu) return nullptr;
		return e->base + (size_t)k * e->value_size * e->ncpu + (size_t)cpu * e->value_size; }
	}
	return nullptr;
}
// ===================== end Chaperon immutable view =====================

uint64_t bpftime_map_lookup_elem_helper(uint64_t map, uint64_t key, uint64_t,
					uint64_t, uint64_t)
{
	if (__builtin_expect(chap_ro_page.sealed != 0, 1)) {   /* Chaperon: RO view only, fail-closed */
		const chap_imm::ent *e = chap_ent((int)map);
		if (!e) return 0;
		if (e->kind != chap_imm::CK_PASSTHRU) return (uint64_t)chap_elem(e, (const void *)key);
	}
	return (uint64_t)bpftime::shm_holder.global_shared_memory
		.bpf_map_lookup_elem((int)map, (void *)key, false);
}

uint64_t bpftime_map_update_elem_helper(uint64_t map, uint64_t key,
					uint64_t value, uint64_t flags,
					uint64_t)
{
	if (__builtin_expect(chap_ro_page.sealed != 0, 1)) {   /* Chaperon: RO view only, fail-closed */
		const chap_imm::ent *e = chap_ent((int)map);
		if (!e) return (uint64_t)(int64_t)-EINVAL;
		if (e->kind == chap_imm::CK_KARRAY || e->kind == chap_imm::CK_RODATA) return (uint64_t)(int64_t)-EPERM;
		if (e->kind != chap_imm::CK_PASSTHRU) {
			if (flags == BPF_NOEXIST) return (uint64_t)(int64_t)-EEXIST;
			uint8_t *p = chap_elem(e, (const void *)key);
			if (!p || !value) return (uint64_t)(int64_t)-ENOENT;
			memcpy(p, (const void *)value, e->value_size);
			return 0;
		}
	}
	return (uint64_t)
		bpftime::shm_holder.global_shared_memory.bpf_map_update_elem(
			(int)map, (void *)key, (void *)value, flags, false);
}

uint64_t bpftime_map_delete_elem_helper(uint64_t map, uint64_t key, uint64_t,
					uint64_t, uint64_t)
{
	if (__builtin_expect(chap_ro_page.sealed != 0, 1)) {   /* Chaperon: RO view only, fail-closed */
		const chap_imm::ent *e = chap_ent((int)map);
		if (!e) return (uint64_t)(int64_t)-EINVAL;
		if (e->kind != chap_imm::CK_PASSTHRU) return (uint64_t)(int64_t)-EINVAL;   /* arrays: no delete */
	}
	return (uint64_t)bpftime::shm_holder.global_shared_memory
		.bpf_delete_elem((int)map, (void *)key, false);
}

extern "C" void chap_helper_addrs(uintptr_t out[3])
{
	out[0] = (uintptr_t)&bpftime_map_lookup_elem_helper;
	out[1] = (uintptr_t)&bpftime_map_update_elem_helper;
	out[2] = (uintptr_t)&bpftime_map_delete_elem_helper;
}

uint64_t bpftime_map_push_elem_helper(uint64_t map, uint64_t value,
				      uint64_t flags, uint64_t, uint64_t)
{
	return (uint64_t)bpftime::shm_holder.global_shared_memory
		.bpf_map_push_elem((int)map, (void *)value, flags, false);
}

uint64_t bpftime_map_pop_elem_helper(uint64_t map, uint64_t value, uint64_t,
				     uint64_t, uint64_t)
{
	return (uint64_t)bpftime::shm_holder.global_shared_memory
		.bpf_map_pop_elem((int)map, (void *)value, false);
}

uint64_t bpftime_map_peek_elem_helper(uint64_t map, uint64_t value, uint64_t,
				      uint64_t, uint64_t)
{
	return (uint64_t)bpftime::shm_holder.global_shared_memory
		.bpf_map_peek_elem((int)map, (void *)value, false);
}

#ifdef ENABLE_PROBE_READ_CHECK
static size_t probe_page_remaining(const void *address)
{
	static const size_t page_size = []() {
		long result = sysconf(_SC_PAGESIZE);
		return result > 0 ? (size_t)result : (size_t)4096;
	}();
	return page_size - ((uintptr_t)address % page_size);
}

static void clear_probe_memory(void *dst, size_t size)
{
	static const char zeros[256] = {};
	auto output = (char *)dst;
	while (size > 0) {
		size_t chunk_size = std::min(size, sizeof(zeros));
		if (!probe_write_memory(output, zeros, chunk_size))
			return;
		output += chunk_size;
		size -= chunk_size;
	}
}
#endif

int64_t bpf_probe_read_str(uint64_t buf, uint64_t bufsz, uint64_t ptr, uint64_t,
			   uint64_t)
{
	if (bufsz == 0)
		return 0;

	auto dst = (char *)(uintptr_t)buf;
	auto src = (const char *)(uintptr_t)ptr;
#ifndef ENABLE_PROBE_READ_CHECK
	for (size_t i = 0; i < (size_t)bufsz; i++) {
		if (src[i] == '\0') {
			dst[i] = '\0';
			return (int64_t)i + 1;
		}
		if (i == (size_t)bufsz - 1) {
			dst[i] = '\0';
			return (int64_t)bufsz;
		}
		dst[i] = src[i];
	}
	return (int64_t)bufsz;
#else
	char scratch[256];
	size_t copied = 0;
	while (copied < (size_t)bufsz) {
		size_t chunk_size =
			std::min(sizeof(scratch), (size_t)bufsz - copied);
		chunk_size = std::min(chunk_size,
				      probe_page_remaining(src + copied));
		if (!probe_read_memory(scratch, src + copied, chunk_size)) {
			clear_probe_memory(dst, (size_t)bufsz);
			return -EFAULT;
		}

		auto terminator = (char *)memchr(scratch, '\0', chunk_size);
		bool complete = terminator != nullptr;
		if (complete) {
			chunk_size = (size_t)(terminator - scratch) + 1;
		} else if (chunk_size == (size_t)bufsz - copied) {
			scratch[chunk_size - 1] = '\0';
			complete = true;
		}

		if (!probe_write_memory(dst + copied, scratch, chunk_size))
			return -EFAULT;
		copied += chunk_size;
		if (complete)
			return (int64_t)copied;
	}
	return (int64_t)copied;
#endif
}

uint64_t bpf_ktime_get_coarse_ns(uint64_t, uint64_t, uint64_t, uint64_t,
				 uint64_t)
{
	struct timespec ts;
#if __APPLE__
	clock_gettime(CLOCK_MONOTONIC, &ts); // or CLOCK_MONOTONIC_RAW
#else
	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
#endif
	return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

uint64_t bpf_ringbuf_output(uint64_t rb, uint64_t data, uint64_t size,
			    uint64_t flags, uint64_t)
{
	int fd = (int)rb;
	if (flags != 0) {
		SPDLOG_WARN(
			"Currently only supports ringbuf_output with flags=0");
	}
	auto buf = bpftime_ringbuf_reserve(fd, size);
	if (!buf) {
		SPDLOG_ERROR("Failed to reserve when executing ringbuf output");
		return (uint64_t)-1;
	}
	memcpy(buf, (const void *)(uintptr_t)data, size);
	bpftime_ringbuf_submit(fd, buf, false);
	return 0;
}

uint64_t bpf_ringbuf_reserve(uint64_t rb, uint64_t size, uint64_t flags,
			     uint64_t, uint64_t)
{
	int fd = (int)rb;
	if (flags != 0) {
		SPDLOG_WARN(
			"Currently only supports ringbuf_reserve with flags=0");
	}
	return (uint64_t)(uintptr_t)bpftime_ringbuf_reserve(fd, size);
}

uint64_t bpf_ringbuf_submit(uint64_t data, uint64_t flags, uint64_t, uint64_t,
			    uint64_t)
{
	int32_t *ptr = (int32_t *)(uintptr_t)data;
	int fd = ptr[-1];
	if (flags != 0) {
		SPDLOG_WARN(
			"Currently only supports ringbuf_submit with flags=0");
	}
	bpftime_ringbuf_submit(fd, (void *)(uintptr_t)data, false);
	return 0;
}

uint64_t bpf_ringbuf_discard(uint64_t data, uint64_t flags, uint64_t, uint64_t,
			     uint64_t)
{
	int32_t *ptr = (int32_t *)(uintptr_t)data;
	int fd = ptr[-1];
	if (flags != 0) {
		SPDLOG_WARN(
			"Currently only supports ringbuf_submit with flags=0");
	}
	bpftime_ringbuf_submit(fd, (void *)(uintptr_t)data, true);
	return 0;
}

uint64_t bpf_perf_event_output(uint64_t ctx, uint64_t map, uint64_t flags,
			       uint64_t data, uint64_t size)
{
	int32_t current_cpu = my_sched_getcpu();
	if (unlikely(current_cpu == -1)) {
		SPDLOG_ERROR(
			"Unable to get current cpu when running perf event output");
		return (uint64_t)-1;
	}
	cpu_set_t mask, orig;
	CPU_ZERO(&mask);
	CPU_SET(current_cpu, &mask);
	if (sched_getaffinity(0, sizeof(orig), &orig) < 0)
		return (uint64_t)-1;
	// Bind to the current cpu
	if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
		SPDLOG_ERROR("Failed to set cpu affinity: {}", errno);
		errno = EINVAL;
		return (uint64_t)(-1);
	}
	int fd = (int)map;
	// Check map type. userspace perf event array, or shared perf event
	// array?
	bpftime::bpf_map_type map_ty;
	int ret = -1;
	if (int err = bpftime_map_get_info(fd, nullptr, nullptr, &map_ty);
	    err < 0) {
		SPDLOG_ERROR("Unable to query map type of fd {}", fd);
		goto restore_affinity;
	}
	if (map_ty == bpftime::bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
		const int32_t *val_ptr =
			(int32_t *)(uintptr_t)bpftime::shm_holder
				.global_shared_memory.bpf_map_lookup_elem(
					fd, &current_cpu, false);
		if (val_ptr == nullptr) {
			SPDLOG_ERROR("Invalid map fd for perf event output: {}",
				     fd);
			errno = EINVAL;
			goto restore_affinity;
		}
		int32_t perf_handler_fd = *val_ptr;
		ret = bpftime_perf_event_output(perf_handler_fd,
						(const void *)(uintptr_t)data,
						(size_t)size);
	}
#if __linux__ && BPFTIME_BUILD_WITH_LIBBPF
	else if (map_ty == bpftime::bpf_map_type::
				   BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY) {
		ret = bpftime_shared_perf_event_output(
			fd, (const void *)(uintptr_t)data, (size_t)size);
	}
#endif
	else {
		SPDLOG_ERROR(
			"Attempting to run perf_output on a non-perf array map");
		ret = -1;
	}

restore_affinity:
	// Cleanup must not overwrite an error from the output operation.
	const int saved_errno = errno;
	if (sched_setaffinity(0, sizeof(orig), &orig) < 0 && ret >= 0)
		return (uint64_t)-1;
	errno = saved_errno;
	return (uint64_t)ret;
}

uint64_t bpftime_tail_call(uint64_t ctx, uint64_t prog_array, uint64_t index)
{
	int fd = (int)prog_array;
	if (!bpftime_is_prog_array(fd)) {
		SPDLOG_ERROR("Expected fd {} to be a prog array fd", fd);
		return -1;
	}
	int idx = index;

	int *to_call_id_ptr = (int *)bpftime_map_lookup_elem(fd, &idx);
	if (!to_call_id_ptr) {
		SPDLOG_ERROR("Unable to lookup index {} of prog array {}", idx,
			     fd);
		return -1;
	}
	int to_call_fd = *to_call_id_ptr;
	SPDLOG_DEBUG("tail call helper: calling prog fd {}", to_call_fd);

	if (bpftime_is_prog_fd(to_call_fd)) {
		constexpr uint32_t MAX_TAIL_CALL_CNT = 32;
		static thread_local uint32_t tail_call_depth = 0;
		if (tail_call_depth >= MAX_TAIL_CALL_CNT) {
			SPDLOG_ERROR("tail call depth limit exceeded");
			return -1;
		}
		struct tail_call_depth_guard {
			uint32_t &depth;
			explicit tail_call_depth_guard(uint32_t &depth)
				: depth(depth)
			{
				depth++;
			}
			~tail_call_depth_guard()
			{
				depth--;
			}
		} guard(tail_call_depth);

		bpftime::bpftime_prog *prog = nullptr;
		try {
			prog = get_global_attach_ctx().find_instantiated_prog(
				to_call_fd);
		} catch (const std::exception &) {
		}
		std::optional<bpftime::bpftime_prog> fallback;
		if (prog == nullptr) {
			const auto &handler = std::get<bpftime::bpf_prog_handler>(
				bpftime::shm_holder.global_shared_memory.get_handler(
					to_call_fd));
			fallback.emplace(handler.insns.data(), handler.insns.size(),
					 handler.name.c_str());
			prog = &*fallback;
			if (bpftime::load_prog_and_helpers(
				    prog,
				    bpftime::bpftime_get_runtime_config()) < 0)
				return -1;
		}

		char context[64];
		if (ctx) {
			memcpy(context, (const void *)(uintptr_t)ctx,
			       sizeof(context));
		} else {
			memset(context, 0, sizeof(context));
		}
		uint64_t retval = 0;
		int err = prog->bpftime_prog_exec(context, sizeof(context),
						  &retval);
		if (err < 0) {
			SPDLOG_ERROR(
				"Failed to execute userspace tail call target fd {}",
				to_call_fd);
			return -1;
		}
		bpftime::current_thread_tail_call_ret = retval;
		return 0;
	}

#if __linux__ && defined(BPFTIME_BUILD_WITH_LIBBPF)
	char context[64];
	if (ctx) {
		memcpy(context, (const void *)(uintptr_t)ctx, 64);
	} else {
		memset(context, 0, sizeof(context));
	}
	LIBBPF_OPTS(bpf_test_run_opts, run_opts, .ctx_in = context,
		    // .ctx_out = context_out,
		    .ctx_size_in = sizeof(context),
		    // .ctx_size_out = sizeof(context_out)
	);
	int err = bpf_prog_test_run_opts(to_call_fd, &run_opts);
	if (err < 0) {
		close(to_call_fd);
		SPDLOG_ERROR("Failed to run kernel program: {}", errno);
		return -1;
	}
	close(to_call_fd);
	bpftime::current_thread_tail_call_ret = run_opts.retval;
	return 0;
#else
	SPDLOG_ERROR(
		"tail_call to kernel program fd {} requires libbpf support",
		to_call_fd);
	return -ENOTSUP;
#endif
}

uint64_t bpftime_get_attach_cookie(uint64_t ctx, uint64_t, uint64_t, uint64_t,
				   uint64_t)
{
	if (auto *signal_ctx = bpftime::attach::current_signal_callback)
		return signal_ctx->cookie.value_or(0);
	uint64_t cookie;
	if (bpftime_get_current_thread_cookie(&cookie)) {
		SPDLOG_DEBUG("Get cookie: {}", cookie);
		return cookie;
	} else {
		SPDLOG_DEBUG("Cookie doesn't exist");
		return 0;
	}
}

uint64_t bpftime_get_func_ip(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t)
{
	if (auto *ctx = bpftime::attach::current_signal_callback)
		return ctx->function_ip;
	return bpftime::attach::current_thread_attach_func_ip;
}

uint64_t bpftime_get_smp_processor_id()
{
	int cpu = my_sched_getcpu();
	if (cpu == -1) {
		SPDLOG_ERROR("sched_getcpu error");
		return 0; // unlikely
	}
	return (uint64_t)cpu;
}

// From https://github.com/microsoft/ebpf-for-windows
int64_t bpftime_csum_diff(const void *from, int from_size, const void *to,
			  int to_size, int seed)
{
	int csum_diff = -EINVAL;

	if ((from_size % 4 != 0) || (to_size % 4 != 0)) {
		// size of buffers should be a multiple of 4.
		goto Exit;
	}

	csum_diff = seed;
	if (to != NULL) {
		for (int i = 0; i < to_size / 2; i++) {
			csum_diff += (uint16_t)(*((uint16_t *)to + i));
		}
	}
	if (from != NULL) {
		for (int i = 0; i < from_size / 2; i++) {
			csum_diff += (uint16_t)(~*((uint16_t *)from + i));
		}
	}

	// Adding 16-bit unsigned integers or their one's complement will
	// produce a positive 32-bit integer, unless the length of the buffers
	// is so long, that the signed 32 bit output overflows and produces a
	// negative result.
	if (csum_diff < 0) {
		csum_diff = -EINVAL;
	}
Exit:
	return csum_diff;
}

#define ETH_HLEN 14 /* Total octets in header.	 */

long bpftime_xdp_adjust_head(struct xdp_md_userspace *xdp, int offset)
{
	// We don't use xdp meta data
	uint64_t data = xdp->data + offset;
	if (unlikely(data > xdp->data_end - ETH_HLEN) || data > xdp->buffer_end)
		return -EINVAL;
	if (data < xdp->buffer_start) {
		// move the data so the buffer can place the new header
		memmove(reinterpret_cast<void *>(xdp->buffer_start +
						 (xdp->buffer_start - data)),
			reinterpret_cast<void *>(xdp->data),
			xdp->data_end - xdp->data);
		data = xdp->buffer_start;
	}
	xdp->data = data;
	return 0;
}

long bpftime_xdp_adjust_tail(struct xdp_md_userspace *xdp_md, int delta)
{
	// We don't use xdp meta data
	uint64_t data = xdp_md->data_end + delta;
	if (data < xdp_md->data || data < xdp_md->buffer_start ||
	    data > xdp_md->buffer_end) {
		return -EINVAL;
	}
	xdp_md->data_end = data;
	return 0;
}

long bpftime_xdp_load_bytes(struct xdp_md_userspace *xdp_md, __u32 offset,
			    void *buf, __u32 len)
{
	// We don't support fragmented packets
	uint64_t data = xdp_md->data + offset;
	if (data + len > xdp_md->data_end) {
		return -EINVAL;
	}
	memcpy(buf, reinterpret_cast<void *>(data), len);
	return 0;
}
using namespace bpftime;

int64_t bpftime_get_stackid(uint64_t ctx_raw, uint64_t map_raw, uint64_t flags,
			    uint64_t, uint64_t)
{
	if (!(flags & BPF_F_USER_STACK)) {
		SPDLOG_ERROR(
			"bpftime_get_stackid only supports collect user stack!");
		return -ENOTSUP;
	}

	const int ATTACH_UPROBE = 6;

	auto &attach_ctx = get_global_attach_ctx();
	auto attach_impl =
		attach_ctx.get_attach_impl_by_attach_type(ATTACH_UPROBE);
	if (!attach_impl.has_value()) {
		SPDLOG_ERROR(
			"Unable to get stack id: frida_uprobe_attach_impl not registered");
		return -ENOTSUP;
	}
	auto raw_ptr = (*attach_impl)
			       ->call_attach_specific_function("generate_stack",
							       nullptr);
	if (raw_ptr == nullptr) {
		SPDLOG_ERROR("Unable to get stack trace");
		return -ENOENT;
	}
	std::unique_ptr<std::vector<uint64_t>> result(
		(std::vector<uint64_t> *)raw_ptr);

	auto frames_to_skip = flags & BPF_F_SKIP_FIELD_MASK;
	SPDLOG_DEBUG("Skipping {} frames", frames_to_skip);
	if (frames_to_skip >= result->size()) {
		result->resize(0);
	} else {
		std::vector<uint64_t> new_data;
		new_data.resize(result->size() - frames_to_skip);
		std::copy(result->begin() + frames_to_skip, result->end(),
			  new_data.begin());
		*result = new_data;
	}
	SPDLOG_DEBUG("After skipping, collected {} frames", result->size());
	int real_map_fd = (int)map_raw;
	auto &map_handler = std::get<bpf_map_handler>(
		shm_holder.global_shared_memory.get_handler(real_map_fd));

	bpftime_lock_guard guard(map_handler.get_raw_spin_lock());
	auto impl = *shm_holder.global_shared_memory.try_get_stack_trace_impl(
		real_map_fd);
	int ret = impl->fill_stack_trace(*result, flags & BPF_F_REUSE_STACKID,
					 flags & BPF_F_FAST_STACK_CMP);

	SPDLOG_DEBUG("Got stackid {}", ret);
	return (uint32_t)ret;
}

int64_t bpftime_get_stack(uint64_t ctx_raw, uint64_t buf, uint64_t size,
			  uint64_t flags, uint64_t)
{
	if (!(flags & BPF_F_USER_STACK)) {
		SPDLOG_ERROR(
			"bpftime_get_stack only supports collect user stack!");
		return -ENOTSUP;
	}
	if (flags & BPF_F_USER_BUILD_ID) {
		SPDLOG_ERROR("bpftime_get_stack doesn't support buildid!");
		return -ENOTSUP;
	}
	auto *buffer = reinterpret_cast<void *>(static_cast<uintptr_t>(buf));
	if (size % sizeof(uint64_t) != 0) {
		SPDLOG_ERROR(
			"bpftime_get_stack buffer size must be a multiple of {} bytes",
			sizeof(uint64_t));
		if (size > 0)
			memset(buffer, 0, size);
		return -EINVAL;
	}
	const int ATTACH_UPROBE = 6;

	auto &attach_ctx = get_global_attach_ctx();
	auto attach_impl =
		attach_ctx.get_attach_impl_by_attach_type(ATTACH_UPROBE);
	if (!attach_impl.has_value()) {
		SPDLOG_ERROR(
			"Unable to get stack id: frida_uprobe_attach_impl not registered");
		return -ENOTSUP;
	}
	auto raw_ptr = (*attach_impl)
			       ->call_attach_specific_function("generate_stack",
							       nullptr);
	if (raw_ptr == nullptr) {
		SPDLOG_ERROR("Unable to get stack trace");
		return -ENOENT;
	}
	std::unique_ptr<std::vector<uint64_t>> result(
		(std::vector<uint64_t> *)raw_ptr);

	auto frames_to_skip = flags & BPF_F_SKIP_FIELD_MASK;
	SPDLOG_DEBUG("Skipping {} frames", frames_to_skip);
	if (frames_to_skip > result->size()) {
		if (size > 0)
			memset(buffer, 0, size);
		return -EFAULT;
	}

	auto frames_to_copy =
		std::min(result->size() - frames_to_skip,
			 static_cast<size_t>(size / sizeof(uint64_t)));
	auto size_to_copy = frames_to_copy * sizeof(uint64_t);
	SPDLOG_DEBUG("Copied {} bytes of stack", size_to_copy);
	if (size_to_copy > 0)
		memcpy(buffer, result->data() + frames_to_skip, size_to_copy);
	if (size > size_to_copy)
		memset(static_cast<char *>(buffer) + size_to_copy, 0,
		       size - size_to_copy);
	return static_cast<int64_t>(size_to_copy);
}

} // extern "C"

namespace bpftime
{

bool helper_is_async_signal_safe(unsigned index, void *fn)
{
	if ((index == 173 && fn == (void *)bpftime_get_func_ip) ||
	    (index == 174 && fn == (void *)bpftime_get_attach_cookie) ||
	    (index == 58 && fn == (void *)bpftime_override_return) ||
	    (index == 187 && fn == (void *)bpftime_set_retval))
		return true;
#if BPFTIME_HAVE_TRAP_UPROBE_ATTACH
	using namespace attach::trap;
	if ((index == 183 && fn == (void *)bpftime_trap_get_func_arg) ||
	    (index == 184 && fn == (void *)bpftime_trap_get_func_ret) ||
	    (index == 186 && fn == (void *)bpftime_trap_get_retval))
		return true;
#endif
	return false;
}

// copied from kernel/include/uapi/linux/bpf.h
enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_probe_read = 4,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_skb_store_bytes = 9,
	BPF_FUNC_l3_csum_replace = 10,
	BPF_FUNC_l4_csum_replace = 11,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_clone_redirect = 13,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_get_cgroup_classid = 17,
	BPF_FUNC_skb_vlan_push = 18,
	BPF_FUNC_skb_vlan_pop = 19,
	BPF_FUNC_skb_get_tunnel_key = 20,
	BPF_FUNC_skb_set_tunnel_key = 21,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_redirect = 23,
	BPF_FUNC_get_route_realm = 24,
	BPF_FUNC_perf_event_output = 25,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_stackid = 27,
	BPF_FUNC_csum_diff = 28,
	BPF_FUNC_skb_get_tunnel_opt = 29,
	BPF_FUNC_skb_set_tunnel_opt = 30,
	BPF_FUNC_skb_change_proto = 31,
	BPF_FUNC_skb_change_type = 32,
	BPF_FUNC_skb_under_cgroup = 33,
	BPF_FUNC_get_hash_recalc = 34,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_probe_write_user = 36,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_skb_change_tail = 38,
	BPF_FUNC_skb_pull_data = 39,
	BPF_FUNC_csum_update = 40,
	BPF_FUNC_set_hash_invalid = 41,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_skb_change_head = 43,
	BPF_FUNC_xdp_adjust_head = 44,
	BPF_FUNC_probe_read_str = 45,
	BPF_FUNC_get_socket_cookie = 46,
	BPF_FUNC_get_socket_uid = 47,
	BPF_FUNC_set_hash = 48,
	BPF_FUNC_setsockopt = 49,
	BPF_FUNC_skb_adjust_room = 50,
	BPF_FUNC_redirect_map = 51,
	BPF_FUNC_sk_redirect_map = 52,
	BPF_FUNC_sock_map_update = 53,
	BPF_FUNC_xdp_adjust_meta = 54,
	BPF_FUNC_perf_event_read_value = 55,
	BPF_FUNC_perf_prog_read_value = 56,
	BPF_FUNC_getsockopt = 57,
	BPF_FUNC_override_return = 58,
	BPF_FUNC_sock_ops_cb_flags_set = 59,
	BPF_FUNC_msg_redirect_map = 60,
	BPF_FUNC_msg_apply_bytes = 61,
	BPF_FUNC_msg_cork_bytes = 62,
	BPF_FUNC_msg_pull_data = 63,
	BPF_FUNC_bind = 64,
	BPF_FUNC_xdp_adjust_tail = 65,
	BPF_FUNC_skb_get_xfrm_state = 66,
	BPF_FUNC_get_stack = 67,
	BPF_FUNC_skb_load_bytes_relative = 68,
	BPF_FUNC_fib_lookup = 69,
	BPF_FUNC_sock_hash_update = 70,
	BPF_FUNC_msg_redirect_hash = 71,
	BPF_FUNC_sk_redirect_hash = 72,
	BPF_FUNC_lwt_push_encap = 73,
	BPF_FUNC_lwt_seg6_store_bytes = 74,
	BPF_FUNC_lwt_seg6_adjust_srh = 75,
	BPF_FUNC_lwt_seg6_action = 76,
	BPF_FUNC_rc_repeat = 77,
	BPF_FUNC_rc_keydown = 78,
	BPF_FUNC_skb_cgroup_id = 79,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_get_local_storage = 81,
	BPF_FUNC_sk_select_reuseport = 82,
	BPF_FUNC_skb_ancestor_cgroup_id = 83,
	BPF_FUNC_sk_lookup_tcp = 84,
	BPF_FUNC_sk_lookup_udp = 85,
	BPF_FUNC_sk_release = 86,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_msg_push_data = 90,
	BPF_FUNC_msg_pop_data = 91,
	BPF_FUNC_rc_pointer_rel = 92,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_sk_fullsock = 95,
	BPF_FUNC_tcp_sock = 96,
	BPF_FUNC_skb_ecn_set_ce = 97,
	BPF_FUNC_get_listener_sock = 98,
	BPF_FUNC_skc_lookup_tcp = 99,
	BPF_FUNC_tcp_check_syncookie = 100,
	BPF_FUNC_sysctl_get_name = 101,
	BPF_FUNC_sysctl_get_current_value = 102,
	BPF_FUNC_sysctl_get_new_value = 103,
	BPF_FUNC_sysctl_set_new_value = 104,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_sk_storage_get = 107,
	BPF_FUNC_sk_storage_delete = 108,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_tcp_gen_syncookie = 110,
	BPF_FUNC_skb_output = 111,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_tcp_send_ack = 116,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_read_branch_records = 119,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_xdp_output = 121,
	BPF_FUNC_get_netns_cookie = 122,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_sk_assign = 124,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_seq_printf = 126,
	BPF_FUNC_seq_write = 127,
	BPF_FUNC_sk_cgroup_id = 128,
	BPF_FUNC_sk_ancestor_cgroup_id = 129,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_csum_level = 135,
	BPF_FUNC_skc_to_tcp6_sock = 136,
	BPF_FUNC_skc_to_tcp_sock = 137,
	BPF_FUNC_skc_to_tcp_timewait_sock = 138,
	BPF_FUNC_skc_to_tcp_request_sock = 139,
	BPF_FUNC_skc_to_udp6_sock = 140,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_load_hdr_opt = 142,
	BPF_FUNC_store_hdr_opt = 143,
	BPF_FUNC_reserve_hdr_opt = 144,
	BPF_FUNC_inode_storage_get = 145,
	BPF_FUNC_inode_storage_delete = 146,
	BPF_FUNC_d_path = 147,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_seq_printf_btf = 150,
	BPF_FUNC_skb_cgroup_classid = 151,
	BPF_FUNC_redirect_neigh = 152,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_redirect_peer = 155,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_bprm_opts_set = 159,
	BPF_FUNC_ktime_get_coarse_ns = 160,
	BPF_FUNC_ima_inode_hash = 161,
	BPF_FUNC_sock_from_file = 162,
	BPF_FUNC_check_mtu = 163,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_sys_bpf = 166,
	BPF_FUNC_btf_find_by_name_kind = 167,
	BPF_FUNC_sys_close = 168,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_get_func_ip = 173,
	BPF_FUNC_get_attach_cookie = 174,
	BPF_FUNC_task_pt_regs = 175,
	BPF_FUNC_get_branch_snapshot = 176,
	BPF_FUNC_trace_vprintk = 177,
	BPF_FUNC_skc_to_unix_sock = 178,
	BPF_FUNC_kallsyms_lookup_name = 179,
	BPF_FUNC_find_vma = 180,
	BPF_FUNC_loop = 181,
	BPF_FUNC_strncmp = 182,
	BPF_FUNC_get_func_arg = 183,
	BPF_FUNC_get_func_ret = 184,
	BPF_FUNC_get_func_arg_cnt = 185,
	BPF_FUNC_get_retval = 186,
	BPF_FUNC_set_retval = 187,
	BPF_FUNC_xdp_get_buff_len = 188,
	BPF_FUNC_xdp_load_bytes = 189,
	BPF_FUNC_xdp_store_bytes = 190,
	BPF_FUNC_copy_from_user_task = 191,
	BPF_FUNC_skb_set_tstamp = 192,
	BPF_FUNC_ima_file_hash = 193,
	BPF_FUNC_kptr_xchg = 194,
	BPF_FUNC_map_lookup_percpu_elem = 195,
	BPF_FUNC_skc_to_mptcp_sock = 196,
	BPF_FUNC_dynptr_from_mem = 197,
	BPF_FUNC_ringbuf_reserve_dynptr = 198,
	BPF_FUNC_ringbuf_submit_dynptr = 199,
	BPF_FUNC_ringbuf_discard_dynptr = 200,
	BPF_FUNC_dynptr_read = 201,
	BPF_FUNC_dynptr_write = 202,
	BPF_FUNC_dynptr_data = 203,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205,
	BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206,
	BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207,
	BPF_FUNC_ktime_get_tai_ns = 208,
	BPF_FUNC_user_ringbuf_drain = 209,
	BPF_FUNC_cgrp_storage_get = 210,
	BPF_FUNC_cgrp_storage_delete = 211,
	__BPF_FUNC_MAX_ID = 212,
};

int bpftime_helper_group::register_helper(const bpftime_helper_info &info)
{
	if (info.index > 999) {
		SPDLOG_ERROR("Helper id should be 0-999, found {}", info.index);
		return -1;
	}
	if (helper_map.find(info.index) == helper_map.end()) {
		helper_map[info.index] = info;
	} else {
		// found the same helper id
		if (helper_map[info.index].fn != info.fn) {
			SPDLOG_ERROR("Helper id already exists for {}",
				     info.name);
			return -1;
		}
		// else, ignore the same helper
	}
	return 0;
}

int bpftime_helper_group::append(const bpftime_helper_group &another_group)
{
	for (const auto &it : another_group.helper_map) {
		if (helper_map.find(it.first) != helper_map.end()) {
			SPDLOG_ERROR("Helper id already exists for {}",
				     it.second.name);
			return -1;
		}
	}
	helper_map.insert(another_group.helper_map.begin(),
			  another_group.helper_map.end());
	return 0;
}

int bpftime_helper_group::add_helper_group_to_prog(bpftime_prog *prog) const
{
	for (auto it : helper_map) {
		prog->bpftime_prog_register_raw_helper(it.second);
	}
	return 0;
}

std::vector<int32_t> bpftime_helper_group::get_helper_ids() const
{
	std::vector<int32_t> result;
	for (const auto &[k, _] : this->helper_map) {
		result.push_back(k);
	}
	return result;
}

// Utility function to get the UFUNC helper group
const bpftime_helper_group &bpftime_helper_group::get_ufunc_helper_group()
{
	const bpftime_helper_group &get_extension_helper_group();

	return get_extension_helper_group();
}

// Utility function to get the kernel utilities helper group
const bpftime_helper_group &
bpftime_helper_group::get_kernel_utils_helper_group()
{
	static const bpftime_helper_group kernel_helper_group = {
		{ { BPF_FUNC_probe_read,
		    bpftime_helper_info{
			    .index = BPF_FUNC_probe_read,
			    .name = "bpf_probe_read",
			    .fn = (void *)bpftime_probe_read,
		    } },
		  { BPF_FUNC_get_smp_processor_id,
		    bpftime_helper_info{
			    .index = BPF_FUNC_get_smp_processor_id,
			    .name = "bpf_get_smp_processor_id",
			    .fn = (void *)bpftime_get_smp_processor_id,
		    } },
		  { BPF_FUNC_csum_diff,
		    bpftime_helper_info{
			    .index = BPF_FUNC_csum_diff,
			    .name = "bpf_csum_diff",
			    .fn = (void *)bpftime_csum_diff,
		    } },
		  { BPF_FUNC_xdp_adjust_head,
		    bpftime_helper_info{
			    .index = BPF_FUNC_xdp_adjust_head,
			    .name = "bpf_xdp_adjust_head",
			    .fn = (void *)bpftime_xdp_adjust_head,
		    } },
		  { BPF_FUNC_xdp_adjust_tail,
		    bpftime_helper_info{
			    .index = BPF_FUNC_xdp_adjust_tail,
			    .name = "bpf_xdp_adjust_tail",
			    .fn = (void *)bpftime_xdp_adjust_tail,
		    } },
		  { BPF_FUNC_probe_read_kernel,
		    bpftime_helper_info{
			    .index = BPF_FUNC_probe_read_kernel,
			    .name = "bpf_probe_read_kernel",
			    .fn = (void *)bpftime_probe_read,
		    } },
		  { BPF_FUNC_probe_read_user,
		    bpftime_helper_info{
			    .index = BPF_FUNC_probe_read_user,
			    .name = "bpf_probe_read_user",
			    .fn = (void *)bpftime_probe_read,
		    } },
		  { BPF_FUNC_ktime_get_ns,
		    bpftime_helper_info{
			    .index = BPF_FUNC_ktime_get_ns,
			    .name = "bpf_ktime_get_ns",
			    .fn = (void *)bpftime_ktime_get_ns,
		    } },
		  { BPF_FUNC_ktime_get_boot_ns,
		    bpftime_helper_info{
			    .index = BPF_FUNC_ktime_get_boot_ns,
			    .name = "bpf_ktime_get_boot_ns",
			    .fn = (void *)bpftime_ktime_get_boot_ns,
		    } },
		  { BPF_FUNC_trace_printk,
		    bpftime_helper_info{
			    .index = BPF_FUNC_trace_printk,
			    .name = "bpf_trace_printk",
			    .fn = (void *)bpftime_trace_printk,
		    } },
		  { BPF_FUNC_get_prandom_u32,
		    bpftime_helper_info{
			    .index = BPF_FUNC_get_prandom_u32,
			    .name = "bpf_get_prandom_u32",
			    .fn = (void *)bpftime_get_prandom_u32,
		    } },
		  { BPF_FUNC_get_current_pid_tgid,
		    bpftime_helper_info{
			    .index = BPF_FUNC_get_current_pid_tgid,
			    .name = "bpf_get_current_pid_tgid",
			    .fn = (void *)bpftime_get_current_pid_tgid,
		    } },
		  { BPF_FUNC_get_current_uid_gid,
		    bpftime_helper_info{
			    .index = BPF_FUNC_get_current_uid_gid,
			    .name = "bpf_get_current_uid_gid",
			    .fn = (void *)bpf_get_current_uid_gid } },
		  { BPF_FUNC_get_current_comm,
		    bpftime_helper_info{
			    .index = BPF_FUNC_get_current_comm,
			    .name = "bpf_get_current_comm",
			    .fn = (void *)bpftime_get_current_comm,
		    } },
		  { BPF_FUNC_override_return,
		    bpftime_helper_info{
			    .index = BPF_FUNC_override_return,
			    .name = "bpf_override_return",
			    .fn = (void *)bpftime_override_return,
		    } },
		  { BPF_FUNC_strncmp,
		    bpftime_helper_info{
			    .index = BPF_FUNC_strncmp,
			    .name = "bpf_strncmp",
			    .fn = (void *)bpftime_strncmp,
		    } },
		  { BPF_FUNC_probe_write_user,
		    bpftime_helper_info{
			    .index = BPF_FUNC_probe_write_user,
			    .name = "bpf_probe_write_user",
			    .fn = (void *)bpftime_probe_write_user,
		    } },
		  { BPF_FUNC_set_retval,
		    bpftime_helper_info{
			    .index = BPF_FUNC_set_retval,
			    .name = "bpf_set_retval",
			    .fn = (void *)bpftime_set_retval,
		    } },
		  { BPF_FUNC_probe_read_user_str,
		    bpftime_helper_info{
			    .index = BPF_FUNC_probe_read_user_str,
			    .name = "bpf_probe_read_str",
			    .fn = (void *)bpf_probe_read_str,
		    } },
		  { BPF_FUNC_probe_read_str,
		    bpftime_helper_info{
			    .index = BPF_FUNC_probe_read_str,
			    .name = "bpf_probe_str",
			    .fn = (void *)bpf_probe_read_str,
		    } },
		  { BPF_FUNC_get_stack,
		    bpftime_helper_info{ .index = BPF_FUNC_get_stack,
					 .name = "bpf_get_stack",
					 .fn = (void *)bpftime_get_stack } },
		  { BPF_FUNC_get_stackid,
		    bpftime_helper_info{ .index = BPF_FUNC_get_stackid,
					 .name = "bpf_get_stackid",
					 .fn = (void *)bpftime_get_stackid } },

		  { BPF_FUNC_ktime_get_coarse_ns,
		    bpftime_helper_info{
			    .index = BPF_FUNC_ktime_get_coarse_ns,
			    .name = "bpf_ktime_get_coarse_ns",
			    .fn = (void *)bpf_ktime_get_coarse_ns } },

		  { BPF_FUNC_ringbuf_reserve,
		    bpftime_helper_info{
			    .index = BPF_FUNC_ringbuf_reserve,
			    .name = "bpf_ringbuf_reserve",
			    .fn = (void *)bpf_ringbuf_reserve,
		    } },
		  { BPF_FUNC_ringbuf_submit,
		    bpftime_helper_info{
			    .index = BPF_FUNC_ringbuf_submit,
			    .name = "bpf_ringbuf_submit",
			    .fn = (void *)bpf_ringbuf_submit,
		    } },
		  { BPF_FUNC_ringbuf_discard,
		    bpftime_helper_info{
			    .index = BPF_FUNC_ringbuf_discard,
			    .name = "bpf_ringbuf_discard",
			    .fn = (void *)bpf_ringbuf_discard,
		    } },
		  { BPF_FUNC_perf_event_output,
		    bpftime_helper_info{ .index = BPF_FUNC_perf_event_output,
					 .name = "bpf_perf_event_output",
					 .fn = (void *)bpf_perf_event_output } },
		  { BPF_FUNC_ringbuf_output,
		    bpftime_helper_info{ .index = BPF_FUNC_ringbuf_output,
					 .name = "bpf_ringbuf_output",
					 .fn = (void *)bpf_ringbuf_output } },
		  { BPF_FUNC_tail_call,
		    bpftime_helper_info{ .index = BPF_FUNC_tail_call,
					 .name = "bpf_tail_call",
					 .fn = (void *)bpftime_tail_call } },
		  { BPF_FUNC_get_attach_cookie,
		    bpftime_helper_info{
			    .index = BPF_FUNC_get_attach_cookie,
			    .name = "bpf_get_attach_cookie",
			    .fn = (void *)bpftime_get_attach_cookie } },
		  { BPF_FUNC_get_func_ip,
		    bpftime_helper_info{ .index = BPF_FUNC_get_func_ip,
					 .name = "bpf_get_func_ip",
					 .fn = (void *)bpftime_get_func_ip } } }

	};

	return kernel_helper_group;
}
const bpftime_helper_group &bpftime_helper_group::get_shm_maps_helper_group()
{
	static const bpftime_helper_group shm_maps_group = { {
		{ BPF_FUNC_map_lookup_elem,
		  bpftime_helper_info{
			  .index = BPF_FUNC_map_lookup_elem,
			  .name = "bpf_map_lookup_elem",
			  .fn = (void *)bpftime_map_lookup_elem_helper,
		  } },
		{ BPF_FUNC_map_update_elem,
		  bpftime_helper_info{
			  .index = BPF_FUNC_map_update_elem,
			  .name = "bpf_map_update_elem",
			  .fn = (void *)bpftime_map_update_elem_helper,
		  } },
		{ BPF_FUNC_map_delete_elem,
		  bpftime_helper_info{
			  .index = BPF_FUNC_map_delete_elem,
			  .name = "bpf_map_delete_elem",
			  .fn = (void *)bpftime_map_delete_elem_helper,
		  } },
		{ BPF_FUNC_map_push_elem,
		  bpftime_helper_info{
			  .index = BPF_FUNC_map_push_elem,
			  .name = "bpf_map_push_elem",
			  .fn = (void *)bpftime_map_push_elem_helper,
		  } },
		{ BPF_FUNC_map_pop_elem,
		  bpftime_helper_info{
			  .index = BPF_FUNC_map_pop_elem,
			  .name = "bpf_map_pop_elem",
			  .fn = (void *)bpftime_map_pop_elem_helper,
		  } },
		{ BPF_FUNC_map_peek_elem,
		  bpftime_helper_info{
			  .index = BPF_FUNC_map_peek_elem,
			  .name = "bpf_map_peek_elem",
			  .fn = (void *)bpftime_map_peek_elem_helper,
		  } },
	} };

	return shm_maps_group;
}

#ifdef ENABLE_BPFTIME_VERIFIER
std::map<int32_t, verifier::BpftimeHelperProrotype> get_ufunc_helper_protos()
{
	using namespace verifier;
	std::map<int32_t, BpftimeHelperProrotype> result;
	result[UFUNC_HELPER_ID_FIND_ID] = BpftimeHelperProrotype{
		.name = "__ebpf_call_find_ufunc_id",
		.return_type = EBPF_RETURN_TYPE_INTEGER,
		.argument_type = { EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
				   EBPF_ARGUMENT_TYPE_DONTCARE,
				   EBPF_ARGUMENT_TYPE_DONTCARE,
				   EBPF_ARGUMENT_TYPE_DONTCARE,
				   EBPF_ARGUMENT_TYPE_DONTCARE }
	};

	result[UFUNC_HELPER_ID_DISPATCHER] = BpftimeHelperProrotype{
		.name = "__ebpf_call_ufunc_dispatcher",
		.return_type = EBPF_RETURN_TYPE_INTEGER,
		.argument_type = { EBPF_ARGUMENT_TYPE_ANYTHING,
				   EBPF_ARGUMENT_TYPE_PTR_TO_READABLE_MEM_OR_NULL,
				   EBPF_ARGUMENT_TYPE_DONTCARE,
				   EBPF_ARGUMENT_TYPE_DONTCARE,
				   EBPF_ARGUMENT_TYPE_DONTCARE }
	};

	return result;
}
#endif

} // namespace bpftime

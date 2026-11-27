#include "include_override/bpftime_prog.hpp"   /* Chaperon: accessor first */
#include "include_override/chap_dispatch_reg.hpp"
#include "attach_private_data.hpp"
#include "bpf_attach_ctx.hpp"
#include <bpftime_shm.hpp>
#include <handler/handler_manager.hpp>
#include <handler/map_handler.hpp>
#include <variant>
#include <cstdio>
#include "bpftime_shm_internal.hpp"
#include "bpftime_ufunc.hpp"
#if BPFTIME_HAVE_FRIDA_ATTACH
#include "frida_attach_private_data.hpp"
#include "frida_uprobe_attach_impl.hpp"
#endif
#if BPFTIME_HAVE_TRAP_UPROBE_ATTACH
#include "trap_attach_private_data.hpp"
#include "trap_uprobe_attach_impl.hpp"
#endif

#include "spdlog/common.h"
#include "bpftime_config.hpp"
#include "bpftime_logger.hpp"
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <random>
#include <string_view>
#include <thread>
#include <unistd.h>
#if BPFTIME_HAVE_FRIDA_ATTACH
#include <frida-gum.h>
#else
typedef char gchar;
typedef int gboolean;
#define TRUE 1
#define FALSE 0
#endif
#include <cstdint>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <cstdarg>
#include <ctime>
#include <string>
#include <vector>
#include <setjmp.h>
#include <climits>
#include <signal.h>
#include <link.h>
#ifdef __linux__
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#endif
#include "bpftime_shm.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/cfg/env.h>
#ifdef BPFTIME_ENABLE_CUDA_ATTACH
#include "nv_attach_private_data.hpp"
#include "nv_attach_impl.hpp"
#endif

#if __linux__ && BPFTIME_BUILD_WITH_LIBBPF
#include "syscall_trace_attach_impl.hpp"
#include "syscall_trace_attach_private_data.hpp"
#endif

using namespace bpftime;
using namespace bpftime::attach;
using main_func_t = int (*)(int, char **, char **);

static main_func_t orig_main_func = nullptr;

enum agent_init_state {
	AGENT_UNINITIALIZED = 0,
	AGENT_INITIALIZING = 1,
	AGENT_READY = 2,
};
static int initialized = AGENT_UNINITIALIZED;

using agent_control_fn_t = void (*)(const gchar *);

// Whether this injected process was operated through frida?
// Defaults to true. If __libc_start_main was called, it should be set to false;
// Besides, if agent was loaded by text-transformer, this variable will be set
// by text-transformer
bool injected_with_frida = true;

static std::atomic<uint64_t> auto_refresh_epoch{ 0 };
static std::mutex auto_refresh_thread_mutex;
static std::thread auto_refresh_thread;
static std::atomic<pid_t> auto_refresh_loader_pid{ -1 };

static std::once_flag agent_ipc_once;
static std::atomic<bool> agent_ipc_stop{ false };
#ifdef __linux__
static int agent_ipc_fd = -1;
static std::thread agent_ipc_thread;
#endif

static int detach_pipe_fds[2] = { -1, -1 };
static std::atomic<bool> detach_thread_started{ false };
static std::mutex detach_mutex;
static std::atomic<bool> global_ctx_constructed{ false };

union bpf_attach_ctx_holder {
	bpf_attach_ctx ctx;
	bpf_attach_ctx_holder()
	{
	}
	~bpf_attach_ctx_holder()
	{
	}
	void destroy()
	{
		ctx.~bpf_attach_ctx();
	}
	void init()
	{
		new (&ctx) bpf_attach_ctx;
	}
};
static bpf_attach_ctx_holder ctx_holder;

/* review #1/#2: TRUSTED-bootstrap eager init + confirmation of kernel-backed ARRAY maps. */
static void chap_confirm_kernel_maps()
{
	if (!getenv("BPFTIME_KERNEL_MAP_NAMES")) return;
	auto *mgr = bpftime::shm_holder.global_shared_memory.get_manager();
	int ok = 1; char failname[64] = "";
	uint32_t zero = 0;
	if (mgr) {
		for (std::size_t fd = 0; fd < mgr->size(); fd++) {
			const auto &h = mgr->get_handler((int)fd);
			if (!std::holds_alternative<bpftime::bpf_map_handler>(h)) continue;
			const auto &mh = std::get<bpftime::bpf_map_handler>(h);
			if (mh.type != bpftime::bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY) continue;
			const void *v = bpftime_map_lookup_elem((int)fd, &zero);
			if (!v) { ok = 0; snprintf(failname, sizeof failname, "%s", mh.name.c_str()); break; }
		}
	}
	char p[80]; snprintf(p, sizeof p, "/tmp/chap_mapinit_%d", getpid());
	FILE *mf = fopen(p, "w"); if (mf) { fprintf(mf, ok ? "OK\n" : "FAIL %s\n", failname); fclose(mf); }
	SPDLOG_INFO("chap: kernel-map eager-init confirm = {} marker={}", ok ? "OK" : "FAIL", p);
}


extern "C" void *chap_ufunc_ctx_region(unsigned long *sz);
/* Chaperon item-1 (read-only sealing): at TRUSTED bootstrap, emit the init-once enforcement seal
 * targets + a MEASUREMENT of the bpftime SHM (metadata handler addr vs per-burst value storage base)
 * to /tmp/chap_seal_targets_<pid>. The esac_seal helper (fired by the Manager AFTER every Filter is
 * attached and every ufunc registered) mprotects the ufunc table RO + mlock + registers it with the
 * kernel Tamper Sentinel. The runtime does NOT mprotect here. */

/* Chaperon Request-E item-1 (identification): where does the enforcement path keep routing pointers?
 *  (a) helper-function addresses: embedded immediates inside JIT/trampoline code vs. writable slots,
 *  (b) writable memory holding pointers INTO the (pre-seal rwx) JIT/trampoline code = hook->filter routing,
 *  (c) per-map SHM handler/value addresses + handler type offset (for the backing-object alias test). */
extern "C" void chap_helper_addrs(uintptr_t out[3]);
static sigjmp_buf chap_mjb;
static void chap_mjmp(int) { siglongjmp(chap_mjb, 1); }
static std::vector<std::pair<uintptr_t, uintptr_t>> chap_extra_ranges;   /* registered at the barrier */
static void chap_add_extra(uintptr_t s, uintptr_t e)
{ for (auto &x : chap_extra_ranges) if (x.first == s && x.second == e) return; chap_extra_ranges.push_back({ s, e }); }
static void chap_measure_routing(FILE *f)
{
	struct rg { uintptr_t s, e; char perm[5]; char path[96]; bool anon; };
	std::vector<rg> all, code;
	FILE *m = fopen("/proc/self/maps", "r"); if (!m) return; char ln[512];
	while (fgets(ln, sizeof ln, m)) { rg r{}; unsigned long x, y; char p[5] = { 0 }; char path[96] = { 0 };
		int k = sscanf(ln, "%lx-%lx %4s %*s %*s %*s %95s", &x, &y, p, path);
		if (k < 3) continue; r.s = x; r.e = y; memcpy(r.perm, p, 5); r.anon = (k < 4);
		snprintf(r.path, sizeof r.path, "%s", k >= 4 ? path : "[anon]");
		if (strstr(r.path, "[vvar]") || strstr(r.path, "[vsyscall]") || strstr(r.path, "[vdso]") || strstr(r.path, "/dev/")) continue;
		all.push_back(r);
		bool rx = p[0] == 'r' && p[2] == 'x';
		if (rx && (p[1] == 'w' || r.anon)) code.push_back(r); }
	fclose(m);
	uintptr_t hp[3]; chap_helper_addrs(hp);
	const char *hn[3] = { "map_lookup_elem_helper", "map_update_elem_helper", "map_delete_elem_helper" };
	long imm[3] = { 0 }, slot_w[3] = { 0 }, slot_ro[3] = { 0 };
	long nptr = 0; std::vector<std::pair<std::string, long>> per;
	struct sigaction sa, ob, os; memset(&sa, 0, sizeof sa); sa.sa_handler = chap_mjmp; sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, &ob); sigaction(SIGSEGV, &sa, &os);
	for (auto &cr : code) fprintf(f, "MEASURE code_region %#lx-%#lx %s %s (%s)\n", cr.s, cr.e, cr.perm, cr.path, cr.perm[1] == 'w' ? "pre-seal rwx" : "anon r-x JIT");
	for (size_t ri = 0; ri < all.size(); ri++) {
		const rg &r = all[ri];
		if (r.perm[0] != 'r') continue;
		if (sigsetjmp(chap_mjb, 1)) { fprintf(f, "MEASURE skip-faulting-region %#lx %s %s\n", r.s, r.perm, r.path); continue; }
		bool wr = r.perm[1] == 'w', ex = r.perm[2] == 'x';
		bool is_code = ex && (wr || r.anon);
		if (is_code) {
			for (uintptr_t p = r.s; p + 8 <= r.e; p++)
				for (int i = 0; i < 3; i++) if (!memcmp((void *)p, &hp[i], 8)) {
					imm[i]++; fprintf(f, "MEASURE helper_imm %s at %#lx in code %s %s\n", hn[i], p, r.perm, r.path); }
			continue;
		}
		if (ex) continue;
		long c = 0;
		for (uintptr_t p = r.s; p + 8 <= r.e; p += 8) {
			uintptr_t v = *(volatile uintptr_t *)p;
			for (int i = 0; i < 3; i++) if (v == hp[i]) {
				if (wr) { slot_w[i]++; if (slot_w[i] <= 2) fprintf(f, "MEASURE helper_slot_writable %s at %#lx in %s %s\n", hn[i], p, r.perm, r.path); }
				else { slot_ro[i]++; fprintf(f, "MEASURE helper_slot_ro %s at %#lx in %#lx-%#lx %s %s\n", hn[i], p, r.s, r.e, r.perm, r.path);
				       if (r.anon) chap_add_extra(r.s, r.e); } }
			if (wr) for (auto &cr : code) if (v >= cr.s && v < cr.e) {
				c++; if (nptr + c <= 4) fprintf(f, "MEASURE code_ptr_in_writable at %#lx (%s %s) -> %#lx\n", p, r.perm, r.path, v); break; }
		}
		if (c) { nptr += c; per.push_back({ std::string(r.perm) + " " + r.path, c }); }
	}
	sigaction(SIGBUS, &ob, nullptr); sigaction(SIGSEGV, &os, nullptr);
	for (auto &cr : code) if (cr.perm[1] != 'w' && cr.anon) chap_add_extra(cr.s, cr.e);   /* finalized JIT code */
	for (int i = 0; i < 3; i++)
		fprintf(f, "MEASURE helper %s=%#lx imm_in_code=%ld ro_slots=%ld writable_slots=%ld\n", hn[i], hp[i], imm[i], slot_ro[i], slot_w[i]);
	fprintf(f, "MEASURE writable_words_pointing_into_enforcement_code=%ld (code regions=%zu)\n", nptr, code.size());
	for (auto &x : per) fprintf(f, "MEASURE   region %s : %ld\n", x.first.c_str(), x.second);
	fprintf(f, "MEASURE barrier_extra_ranges(anon r-x JIT code + anon r-- helper-slot pages)=%zu\n", chap_extra_ranges.size());
	fprintf(f, "MEASURE selector_manager_ptr_holder=%p (agent .bss; global_shared_memory object)\n", (void *)&bpftime::shm_holder);
}

static void chap_write_seal_targets()
{
	char p[96]; snprintf(p, sizeof p, "/tmp/chap_seal_targets_%d", getpid());
	FILE *f = fopen(p, "w"); if (!f) return;
	unsigned long usz = 0; void *uaddr = chap_ufunc_ctx_region(&usz);
	fprintf(f, "UFUNC %p %lu\n", uaddr, usz);                 /* (1) ufunc dispatch table (func ptrs) */
	const char *sn = getenv("BPFTIME_GLOBAL_SHM_NAME");       /* (2) SHM segment range (measurement) */
	if (sn) { FILE *m = fopen("/proc/self/maps", "r");
		if (m) { char line[512];
			while (fgets(line, sizeof line, m))
				if (strstr(line, sn) && strstr(line, "rw-s")) fprintf(f, "SHM %s", line);
			fclose(m); } }
	auto *mgr = bpftime::shm_holder.global_shared_memory.get_manager();   /* (3) per-map metadata vs value */
	uint32_t zero = 0;
	if (mgr) for (std::size_t fd = 0; fd < mgr->size(); fd++) {
		const auto &h = mgr->get_handler((int)fd);
		if (!std::holds_alternative<bpftime::bpf_map_handler>(h)) continue;
		const auto &mh = std::get<bpftime::bpf_map_handler>(h);
		const void *v = bpftime_map_lookup_elem((int)fd, &zero);
		fprintf(f, "MAP fd=%zu type=%d name=%s handler=%p value0=%p type_off=%zu attr_flags=%#lx kid=%u\n",
			fd, (int)mh.type, mh.name.c_str(), (const void *)&mh, v,
			(size_t)((const char *)&mh.type - (const char *)&mh), (unsigned long)mh.attr.flags, mh.attr.kernel_bpf_map_id);
	}
	chap_measure_routing(f);
	fclose(f);
	SPDLOG_INFO("chap: wrote seal targets -> {} (ufunc_ctx={} bytes)", p, usz);
}


bpf_attach_ctx &get_global_attach_ctx()
{
	return ctx_holder.ctx;
}

static void apply_injected_kv_overrides(const gchar *data);
static int refresh_attach_session(const gchar *data);
static int perform_detach();

static void install_agent_bootstrap_logger() noexcept
{
	if (__atomic_load_n(&initialized, __ATOMIC_SEQ_CST) !=
	    AGENT_UNINITIALIZED)
		return;
	const char *logger_target = getenv("BPFTIME_LOG_OUTPUT");
	bpftime_set_logger(logger_target == nullptr ? DEFAULT_LOGGER_OUTPUT_PATH :
						     logger_target);
}

static void reset_syscall_trace_global() noexcept
{
#if __linux__ && BPFTIME_BUILD_WITH_LIBBPF
	try {
		bpftime::attach::global_syscall_trace_attach_impl.reset();
	} catch (...) {
	}
#endif
}

extern "C" __attribute__((visibility("default"))) void
bpftime_agent_control(const gchar *data)
{
	// External control entrypoint used to avoid loading multiple agent copies
	// into the same target process (Frida typically loads via /proc/self/fd/*).
	install_agent_bootstrap_logger();
	try {
		(void)refresh_attach_session(data);
	} catch (...) {
	}
}

static void start_agent_ipc_server_once();

static agent_control_fn_t find_other_loaded_agent_control()
{
	if (auto sym = (agent_control_fn_t)dlsym(RTLD_NEXT, "bpftime_agent_control");
	    sym && sym != &bpftime_agent_control) {
		return sym;
	}

	Dl_info self_info {};
	const char *self_name = nullptr;
	if (dladdr((void *)&bpftime_agent_control, &self_info) != 0) {
		self_name = self_info.dli_fname;
	}
	struct FindCtx {
		const char *self_name;
		agent_control_fn_t found;
	} ctx{ self_name, nullptr };

	dl_iterate_phdr(
		[](struct dl_phdr_info *info, size_t, void *data) -> int {
			auto *ctx = static_cast<FindCtx *>(data);
			if (!info || !info->dlpi_name || info->dlpi_name[0] == '\0')
				return 0;
			if (ctx->self_name &&
			    strcmp(info->dlpi_name, ctx->self_name) == 0)
				return 0;
			void *h = dlopen(info->dlpi_name, RTLD_NOLOAD | RTLD_NOW);
			if (!h)
				return 0;
			auto sym = (agent_control_fn_t)dlsym(
				h, "bpftime_agent_control");
			if (sym && sym != &bpftime_agent_control) {
				ctx->found = sym;
				dlclose(h);
				return 1;
			}
			dlclose(h);
			return 0;
		},
		&ctx);

	return ctx.found;
}

#ifdef __linux__
static bool make_agent_ipc_addr(pid_t pid, sockaddr_un &addr, socklen_t &len)
{
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	std::string name = "bpftime-agent-" + std::to_string((int)pid);
	if (name.size() + 1 > sizeof(addr.sun_path))
		return false;
	addr.sun_path[0] = '\0'; // abstract namespace
	memcpy(addr.sun_path + 1, name.data(), name.size());
	len = (socklen_t)(offsetof(sockaddr_un, sun_path) + 1 + name.size());
	return true;
}

static bool try_send_agent_ipc(pid_t pid, const std::string &request,
			       std::string *response_out = nullptr)
{
	int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return false;
	sockaddr_un addr {};
	socklen_t len = 0;
	if (!make_agent_ipc_addr(pid, addr, len)) {
		::close(fd);
		return false;
	}
	if (::connect(fd, (sockaddr *)&addr, len) != 0) {
		::close(fd);
		return false;
	}
	const char *buf = request.data();
	size_t left = request.size();
	while (left > 0) {
		ssize_t n = ::send(fd, buf, left, MSG_NOSIGNAL);
		if (n < 0) {
			::close(fd);
			return false;
		}
		buf += (size_t)n;
		left -= (size_t)n;
	}
	(void)::shutdown(fd, SHUT_WR);
	if (response_out) {
		std::string resp;
		char rbuf[4096];
		for (;;) {
			ssize_t n = ::recv(fd, rbuf, sizeof(rbuf), 0);
			if (n <= 0)
				break;
			resp.append(rbuf, rbuf + n);
		}
		*response_out = std::move(resp);
	}
	::close(fd);
	return true;
}

static bool try_forward_to_existing_agent(const gchar *data)
{
	std::string req("refresh ");
	if (data != nullptr)
		req += data;
	return try_send_agent_ipc(getpid(), req);
}
#endif

static void start_agent_ipc_server_once()
{
#ifdef __linux__
	std::call_once(agent_ipc_once, []() {
		sockaddr_un addr {};
		socklen_t len = 0;
		if (!make_agent_ipc_addr(getpid(), addr, len)) {
			SPDLOG_WARN("agent ipc: unable to build socket address");
			return;
		}
		int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (fd < 0) {
			SPDLOG_WARN("agent ipc: socket() failed: {}", strerror(errno));
			return;
		}
		if (::bind(fd, (sockaddr *)&addr, len) != 0) {
			SPDLOG_WARN("agent ipc: bind() failed: {}", strerror(errno));
			::close(fd);
			return;
		}
		if (::listen(fd, 8) != 0) {
			SPDLOG_WARN("agent ipc: listen() failed: {}", strerror(errno));
			::close(fd);
			return;
		}
		agent_ipc_fd = fd;
		agent_ipc_stop.store(false, std::memory_order_release);
		try {
			agent_ipc_thread = std::thread([]() {
			for (;;) {
				if (agent_ipc_stop.load(std::memory_order_acquire))
					return;
				int cfd = ::accept4(agent_ipc_fd, nullptr, nullptr,
						    SOCK_CLOEXEC);
				if (cfd < 0) {
					if (errno == EINTR)
						continue;
					usleep(10 * 1000);
					continue;
				}
				// Basic auth: allow same uid or root.
				struct ucred cred {};
				socklen_t clen = sizeof(cred);
				if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred,
					       &clen) != 0) {
					::close(cfd);
					continue;
				}
				if (cred.uid != 0 && (uid_t)cred.uid != geteuid()) {
					::close(cfd);
					continue;
				}
				std::string req;
				char buf[4096];
				for (;;) {
					ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
					if (n <= 0)
						break;
					req.append(buf, buf + n);
					if (req.size() > (1 << 20))
						break;
				}
				// Parse: "refresh <k=v;...>" or "detach" or "status".
				auto trim = [](std::string &s) {
					while (!s.empty() &&
					       (s.back() == '\n' || s.back() == '\r' ||
						s.back() == '\0'))
						s.pop_back();
				};
				trim(req);
				if (req.rfind("refresh ", 0) == 0) {
					std::string arg = req.substr(strlen("refresh "));
					int rc = refresh_attach_session(arg.c_str());
					if (rc == 0) {
						(void)::send(cfd, "ok\n", 3,
							     MSG_NOSIGNAL);
					} else {
						std::string out =
							"err refresh " +
							std::to_string(rc) +
							"\n";
						(void)::send(cfd, out.data(),
							     out.size(),
							     MSG_NOSIGNAL);
					}
				} else if (req == "detach") {
					int rc = perform_detach();
					if (rc == 0) {
						(void)::send(cfd, "ok\n", 3,
							     MSG_NOSIGNAL);
					} else {
						std::string out =
							"err detach " +
							std::to_string(rc) +
							"\n";
						(void)::send(cfd, out.data(),
							     out.size(),
							     MSG_NOSIGNAL);
					}
				} else if (req == "status") {
					uint64_t epoch =
						shm_holder.global_shared_memory
							.read_stable_epoch_seq();
					std::string out;
					if (epoch == BPFTIME_EPOCH_SEQ_MISSING) {
						out = "epoch_seq=missing\n";
					} else if (epoch ==
						   BPFTIME_EPOCH_SEQ_UNSTABLE) {
						out = "epoch_seq=unstable\n";
					} else {
						out = "epoch_seq=" +
						      std::to_string(epoch) +
						      "\n";
					}
					(void)::send(cfd, out.data(), out.size(),
						     MSG_NOSIGNAL);
				} else {
					(void)::send(cfd, "unknown\n", 8, MSG_NOSIGNAL);
				}
				::close(cfd);
			}
			});
		} catch (...) {
			agent_ipc_stop.store(true, std::memory_order_release);
			::close(fd);
			agent_ipc_fd = -1;
			return;
		}
		std::atexit([]() {
			agent_ipc_stop.store(true, std::memory_order_release);
			if (agent_ipc_fd >= 0) {
				::close(agent_ipc_fd);
				agent_ipc_fd = -1;
			}
			if (agent_ipc_thread.joinable())
				agent_ipc_thread.detach();
		});
		try {
			SPDLOG_INFO("agent ipc: listening (abstract) for pid {}",
				    (int)getpid());
		} catch (...) {
		}
	});
#else
	(void)0;
#endif
}

static int perform_detach()
{
	std::lock_guard<std::mutex> detach_guard(detach_mutex);
	if (!global_ctx_constructed.load(std::memory_order_acquire)) {
		__atomic_store_n(&initialized, AGENT_UNINITIALIZED,
				 __ATOMIC_SEQ_CST);
		return 0;
	}
	SPDLOG_INFO("Detaching..");

	// Stop auto-refresh first to avoid racing re-instantiation with teardown.
	auto_refresh_epoch.fetch_add(1, std::memory_order_acq_rel);
	{
		std::lock_guard<std::mutex> guard(auto_refresh_thread_mutex);
		if (auto_refresh_thread.joinable())
			auto_refresh_thread.join();
	}

	// Detach all instantiated links so GPU code stops using loader-owned
	// resources (CUDA IPC buffers) before the loader exits.
	int detach_err = ctx_holder.ctx.destroy_all_attach_links();
	if (detach_err < 0) {
		SPDLOG_ERROR("Unable to detach cleanly: {}", detach_err);
	}
	// Allow re-instantiating handlers on the next session without requiring
	// destroying the whole attach context (which may block inside driver
	// teardown while kernels are still running).
	ctx_holder.ctx.reset_instantiated_state();
	if (detach_err >= 0) {
		shm_holder.global_shared_memory.remove_pid_from_alive_agent_set(
			getpid());
	}
	SPDLOG_DEBUG("Detaching done");
	bpftime_logger_flush();
	return detach_err < 0 ? detach_err : 0;
}

static void stop_auto_refresh_at_exit()
{
	auto_refresh_epoch.fetch_add(1, std::memory_order_acq_rel);
	std::lock_guard<std::mutex> guard(auto_refresh_thread_mutex);
	if (auto_refresh_thread.joinable())
		auto_refresh_thread.join();
}

static bool ensure_detach_worker_started() noexcept
{
	bool expected = false;
	if (!detach_thread_started.compare_exchange_strong(
		    expected, true, std::memory_order_acq_rel,
		    std::memory_order_acquire)) {
		return true;
	}
	int fds[2] = { -1, -1 };
	auto clear_fds = [&]() {
		for (int &fd : fds) {
			if (fd >= 0) {
				::close(fd);
				fd = -1;
			}
		}
		for (int &fd : detach_pipe_fds) {
			if (fd >= 0) {
				::close(fd);
				fd = -1;
			}
		}
		detach_thread_started.store(false, std::memory_order_release);
	};
	try {
#ifdef __linux__
		if (pipe2(fds, O_CLOEXEC) != 0) {
			SPDLOG_WARN(
				"pipe2 failed, detach by SIGUSR1 will be disabled");
			clear_fds();
			return false;
		}
#else
		if (pipe(fds) != 0) {
			SPDLOG_WARN(
				"pipe failed, detach by SIGUSR1 will be disabled");
			clear_fds();
			return false;
		}
#endif
		detach_pipe_fds[0] = fds[0];
		detach_pipe_fds[1] = fds[1];
		fds[0] = -1;
		fds[1] = -1;
		std::thread([]() {
			for (;;) {
				uint8_t buf[16];
				ssize_t n =
					read(detach_pipe_fds[0], buf, sizeof(buf));
				if (n <= 0) {
					return;
				}
				if (__atomic_load_n(&initialized,
						    __ATOMIC_SEQ_CST) !=
				    AGENT_READY) {
					continue;
				}
				perform_detach();
			}
		}).detach();
		return true;
	} catch (...) {
		clear_fds();
		return false;
	}
}

syscall_hooker_func_t orig_hooker;

extern "C" void bpftime_agent_main(const gchar *data, gboolean *stay_resident);



/* ===================== Chaperon Request-F item-1: SEALED HOOK->FILTER DISPATCH =====================
 * Frida's listener dispatch keeps every link in writable heap (per-hook GumFunctionContext, written on
 * every call; listener entries/objects; bpftime attach entries, std::function callbacks, prog->fn). At the
 * barrier each enforcement hook is moved from a Frida LISTENER to gum_interceptor_replace_fast() onto a
 * per-hook thunk in agent code. The thunk reads ONLY a dispatch table that is sealed RO + mlock'd, through a
 * selector page that is sealed RO, and runs the same programs with the same pt_regs / cookie / func-ip /
 * set_retval / override_return semantics as bpftime's listener path. Filters, maps and verdicts unchanged. */
#define CHAP_MAX_SLOTS 64
#define CHAP_MAX_PROGS 4
struct chap_disp_prog { uint64_t (*fn)(void *, uint64_t); uint64_t has_cookie, cookie; };
struct chap_disp_slot {
	uint64_t func;
	uint64_t (*orig)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
	uint32_t n_enter, n_exit, n_ovr, excl;	/* excl: 1 = TX burst exclusion (Request G), 2 = RX window exclusion (Request H) */
	uint32_t rclass, rpad;			/* Request J: resource class of the slot (0 = none: RX/TX bursts, tracing) */
	chap_disp_prog enter[CHAP_MAX_PROGS], exit[CHAP_MAX_PROGS], ovr[CHAP_MAX_PROGS];
};
struct chap_disp_table { uint64_t magic; uint32_t n, pad; chap_disp_slot s[CHAP_MAX_SLOTS]; };
struct alignas(4096) chap_disp_sel_t { uint64_t magic; const chap_disp_table *t; uint64_t sealed; unsigned char pad[4096 - 24]; };
static chap_disp_sel_t chap_disp_sel;                     /* own page in agent .bss, sealed RO */
static_assert(sizeof(chap_disp_sel_t) == 4096, "selector page");

static inline void chap_run_prog(const chap_disp_prog &p, uint64_t func, bpftime::pt_regs &regs)
{
	using namespace bpftime;
	uintptr_t prev_ip = attach::current_thread_attach_func_ip;
	attach::current_thread_attach_func_ip = (uintptr_t)func;
	if (p.has_cookie) current_thread_bpf_cookie = p.cookie; else current_thread_bpf_cookie.reset();
	bpftime_protect_disable();
	(void)p.fn((void *)&regs, sizeof(regs));
	current_thread_tail_call_ret.reset();
	bpftime_protect_enable();
	attach::current_thread_attach_func_ip = prev_ip;
}
/* Request G: TX burst exclusion. For TX slots the entry program reports, per window of at most 32 inspected
 * packets, which packets are excluded (already freed by the program). The window is stably partitioned
 * (excluded first, allowed after) and only the allowed packets are handed to the PMD. The value returned to
 * the application is excluded + sent, so pkts[0..ret) are consumed and pkts[ret..n) stay owned by the caller,
 * which is the rte_eth_tx_burst contract. A filter that does not answer gets the legacy call. */
#define CHAP_TXEXCL_ADV 0x43484150584C4344ULL
#define CHAP_TXEXCL_TAG 0xC4A9ULL
#define CHAP_TX_WINDOW 32u
static __attribute__((noinline)) uint64_t chap_dispatch_excl(const chap_disp_slot *s, uint64_t a0, uint64_t a1, uint64_t a2,
							       uint64_t a3, uint64_t a4, uint64_t a5, bpftime::pt_regs &regs)
{
	using namespace bpftime;
	void **pk = (void **)a1;
	const uint32_t n = (uint16_t)a2;			/* uint16_t nb_pkts */
	uint32_t off = 0, total = 0;
	do {
		uint64_t v = 0; bool got = false;
		regs.si = (uint64_t)(pk + off); regs.dx = n - off; regs.orig_ax = CHAP_TXEXCL_ADV;
		auto prev = std::move(attach::curr_thread_override_return_callback);
		attach::curr_thread_override_return_callback = [&](uint64_t, uint64_t x) { v = x; got = true; };
		for (uint32_t k = 0; k < s->n_enter; k++) chap_run_prog(s->enter[k], s->func, regs);
		attach::curr_thread_override_return_callback = std::move(prev);
		if (!got) {				/* filter without the exclusion contract: legacy call with the rest */
			total += (uint16_t)s->orig(a0, (uint64_t)(pk + off), n - off, a3, a4, a5);
			break;
		}
		uint32_t w = (uint32_t)(v >> 32) & 0xffffu, mask = (uint32_t)v;
		if ((v >> 48) != CHAP_TXEXCL_TAG || w == 0 || w > CHAP_TX_WINDOW || w > n - off) {
			/* malformed verdict from an exclusion-capable filter: excluded mbufs may already be freed, so
			   neither sending nor returning them is safe -> fail-stop (same outcome as a filter KILL) */
			static const char m[] = "[chap] TX exclusion verdict malformed -> SIGKILL (fail-stop)\n";
			(void)!write(2, m, sizeof m - 1);
			raise(SIGKILL);
		}
		if (w < 32) mask &= (1u << w) - 1u;
		uint32_t d = (uint32_t)__builtin_popcount(mask);
		if (d) {
			void *dv[CHAP_TX_WINDOW], *kv[CHAP_TX_WINDOW]; uint32_t nd = 0, nk = 0;
			for (uint32_t i = 0; i < w; i++) { if ((mask >> i) & 1u) dv[nd++] = pk[off + i]; else kv[nk++] = pk[off + i]; }
			for (uint32_t i = 0; i < nd; i++) pk[off + i] = dv[i];
			for (uint32_t i = 0; i < nk; i++) pk[off + nd + i] = kv[i];
		}
		uint32_t m = w - d;
		uint32_t sent = m ? (uint16_t)s->orig(a0, (uint64_t)(pk + off + d), m, a3, a4, a5) : 0u;
		total += d + sent;
		if (sent < m) break;				/* ring full: caller keeps the unsent allowed packets */
		off += w;
	} while (off < n);
	uint64_t ret = total;
	if (s->n_exit) {
		pt_regs r2 = regs; r2.ax = ret; r2.si = a1; r2.dx = a2;
		uint64_t newret = ret;
		auto prev = std::move(attach::curr_thread_override_return_callback);
		attach::curr_thread_override_return_callback = [&](uint64_t, uint64_t x) { newret = x; };
		for (uint32_t k = 0; k < s->n_exit; k++) chap_run_prog(s->exit[k], s->func, r2);
		attach::curr_thread_override_return_callback = std::move(prev);
		ret = newret;
	}
	return ret;
}
/* Request H: RX window exclusion. After the PMD returned n packets, the RX exit program inspects the burst in
 * windows of at most 32 (base passed in rsi, remaining count in rax) and reports which packets it dropped (and
 * already freed). The array is compacted here, in-process: kept packets keep their order at pkts[0..kept) and
 * kept is returned, so the caller owns exactly the packets it sees. Every packet of the burst is inspected.
 * A filter without the RX contract keeps its legacy behaviour (unchanged return or its own set_retval). */
#define CHAP_RXEXCL_ADV 0x4348415052584C44ULL
#define CHAP_RXEXCL_TAG 0xC4AAULL
#define CHAP_RX_WINDOW 32u
[[noreturn]] static void chap_excl_fatal(const char *m)
{
	(void)!write(2, m, strlen(m));
	raise(SIGKILL);
	_exit(99);
}
static __attribute__((noinline)) uint64_t chap_dispatch_rx(const chap_disp_slot *s, uint64_t a0, uint64_t a1, uint64_t a2,
							     uint64_t a3, uint64_t a4, uint64_t a5, bpftime::pt_regs &regs)
{
	using namespace bpftime;
	for (uint32_t k = 0; k < s->n_enter; k++) chap_run_prog(s->enter[k], s->func, regs);
	uint64_t ret = s->orig(a0, a1, a2, a3, a4, a5);
	const uint32_t n = (uint16_t)ret;
	if (!s->n_exit) return ret;
	if (n == 0) {						/* empty poll: unchanged exit handling */
		pt_regs r2 = regs; r2.ax = ret;
		uint64_t newret = ret;
		auto prev = std::move(attach::curr_thread_override_return_callback);
		attach::curr_thread_override_return_callback = [&](uint64_t, uint64_t x) { newret = x; };
		for (uint32_t k = 0; k < s->n_exit; k++) chap_run_prog(s->exit[k], s->func, r2);
		attach::curr_thread_override_return_callback = std::move(prev);
		return newret;
	}
	void **pk = (void **)a1;
	uint32_t off = 0, kept = 0;
	while (off < n) {
		pt_regs r2 = regs; r2.ax = n - off; r2.si = (uint64_t)(pk + off); r2.orig_ax = CHAP_RXEXCL_ADV;
		uint64_t v = 0; bool got = false;
		auto prev = std::move(attach::curr_thread_override_return_callback);
		attach::curr_thread_override_return_callback = [&](uint64_t, uint64_t x) { v = x; got = true; };
		for (uint32_t k = 0; k < s->n_exit; k++) chap_run_prog(s->exit[k], s->func, r2);
		attach::curr_thread_override_return_callback = std::move(prev);
		if (!got) {
			if (off == 0) return ret;		/* no RX contract (or filter disabled): unchanged */
			chap_excl_fatal("[chap] RX window verdict missing mid-burst -> SIGKILL (fail-stop)\n");
		}
		if ((v >> 48) != CHAP_RXEXCL_TAG) {
			if (off == 0) return (uint16_t)v;	/* legacy filter: its own in-place compaction result */
			chap_excl_fatal("[chap] RX window verdict malformed -> SIGKILL (fail-stop)\n");
		}
		uint32_t w = (uint32_t)(v >> 32) & 0xffffu, mask = (uint32_t)v;
		if (w == 0 || w > CHAP_RX_WINDOW || w > n - off)
			chap_excl_fatal("[chap] RX window verdict malformed -> SIGKILL (fail-stop)\n");
		if (w < 32) mask &= (1u << w) - 1u;
		for (uint32_t i = 0; i < w; i++)
			if (!((mask >> i) & 1u)) pk[kept++] = pk[off + i];	/* kept <= off + i: forward in-place move */
		off += w;
	}
	return kept;
}
/* Request J: kernel-observable boundary of an ADMITTED resource API call. The sealed dispatcher calls these only
 * after the Resource Agent's pre-check let the call through, immediately before (enter) and after (exit) the
 * original function. They are empty, never inlined and exported from agent.so, whose code Frida never patches, so
 * the kernel Sentinel can attach uprobes here; a uprobe on the API entry itself collides with the replace_fast jump
 * written over that entry. All arguments come from the sealed RO slot table. A SIGKILL raised at the enter probe
 * terminates the process before the original function runs. Never called for RX/TX burst slots. */
extern "C" __attribute__((noinline, used, visibility("default"))) void chap_res_gate_enter(uint64_t slot, uint64_t rclass, uint64_t func)
{ __asm__ __volatile__("" : : "r"(slot), "r"(rclass), "r"(func) : "memory"); }
extern "C" __attribute__((noinline, used, visibility("default"))) void chap_res_gate_exit(uint64_t slot, uint64_t rclass, uint64_t ret)
{ __asm__ __volatile__("nop" : : "r"(slot), "r"(rclass), "r"(ret) : "memory"); }
/* (API id << 8) | resource class, from the Resource Agent program name (BPF object names are kept to 15
 * characters). Class: 1 Memory, 2 Launch, 3 Port, 4 NIC control. The ids match the Sentinel's nesting budgets. */
static uint32_t chap_res_class(const char *n)
{
	static const struct { const char *name; uint32_t api, cls; } tab[] = {
		{ "agent_malloc", 1, 1 }, { "agent_memzone", 2, 1 }, { "agent_mempool", 3, 1 }, { "agent_pktmbuf_p", 4, 1 },
		{ "agent_mem_pass", 5, 1 }, { "agent_eal_init", 6, 2 }, { "agent_remote_la", 7, 2 },
		{ "agent_dev_confi", 8, 3 }, { "agent_rxq_setup", 9, 3 }, { "agent_txq_setup", 10, 3 },
		{ "agent_flow_crea", 11, 4 }, { "agent_flow_dest", 12, 4 }, { "agent_flow_flus", 13, 4 }, { "agent_dev_start", 14, 4 },
		{ "agent_dev_stop", 15, 4 }, { "agent_promisc_e", 16, 4 }, { "agent_promisc_d", 17, 4 }, { "agent_mc_addr", 18, 4 } };
	if (!n) return 0;
	for (auto &e : tab) if (!strncmp(n, e.name, 15)) return (e.api << 8) | e.cls;
	return 0;
}
/* System V x86-64: arguments 7.. are on the caller's stack. The thunk is entered by a jmp from the patched entry,
 * so at its entry [rsp] is the caller's return address and [rsp+8..] the stack arguments; the thunk passes that
 * address and the generic dispatcher forwards 5 stack words to the original (APIs with up to 11 integer arguments,
 * e.g. rte_mempool_create). Extra words are ignored by callees with fewer arguments. (Request J) */
typedef uint64_t (*chap_orig11)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static __attribute__((noinline)) uint64_t chap_dispatch(uint32_t i, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, const uint64_t *stk)
{
	using namespace bpftime;
	const chap_disp_table *t = chap_disp_sel.t;              /* RO selector page */
	if (__builtin_expect(!t || i >= t->n, 0)) return 0;     /* fail-closed: no packets / no flow */
	const chap_disp_slot *s = &t->s[i];
	pt_regs regs{}; regs.di = a0; regs.si = a1; regs.dx = a2; regs.cx = a3; regs.r8 = a4; regs.r9 = a5;
	regs.ip = s->func; regs.sp = (uint64_t)__builtin_frame_address(0);
	if (s->excl == 1) return chap_dispatch_excl(s, a0, a1, a2, a3, a4, a5, regs);
	if (s->excl == 2) return chap_dispatch_rx(s, a0, a1, a2, a3, a4, a5, regs);
	if (s->n_ovr) {                                          /* bpf_override_return (e.g. rte_flow_create) */
		bool did = false; uint64_t ov = 0;
		auto prev = std::move(attach::curr_thread_override_return_callback);
		attach::curr_thread_override_return_callback = [&](uint64_t, uint64_t v) { did = true; ov = v; };
		for (uint32_t k = 0; k < s->n_ovr; k++) chap_run_prog(s->ovr[k], s->func, regs);
		attach::curr_thread_override_return_callback = std::move(prev);
		if (did) return ov;
	}
	for (uint32_t k = 0; k < s->n_enter; k++) chap_run_prog(s->enter[k], s->func, regs);
	if (s->rclass) chap_res_gate_enter(i, s->rclass, s->func);   /* Request J: admitted resource call -> kernel boundary */
	uint64_t ret = ((chap_orig11)(void *)s->orig)(a0, a1, a2, a3, a4, a5, stk[0], stk[1], stk[2], stk[3], stk[4]);   /* + stack args (Request J) */
	if (s->rclass) chap_res_gate_exit(i, s->rclass, ret);
	if (s->n_exit) {                                         /* uretprobe: rax = ret; bpf_set_retval may rewrite it */
		pt_regs r2 = regs; r2.ax = ret;
		uint64_t newret = ret;
		auto prev = std::move(attach::curr_thread_override_return_callback);
		attach::curr_thread_override_return_callback = [&](uint64_t, uint64_t v) { newret = v; };
		for (uint32_t k = 0; k < s->n_exit; k++) chap_run_prog(s->exit[k], s->func, r2);
		attach::curr_thread_override_return_callback = std::move(prev);
		ret = newret;
	}
	return ret;
}
#define CHAP_T(i) extern "C" __attribute__((visibility("hidden"))) uint64_t chap_thunk_##i(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) { return chap_dispatch(i, a0, a1, a2, a3, a4, a5, (const uint64_t *)((const char *)__builtin_frame_address(0) + 16)); }
CHAP_T(0) CHAP_T(1) CHAP_T(2) CHAP_T(3) CHAP_T(4) CHAP_T(5) CHAP_T(6) CHAP_T(7) CHAP_T(8) CHAP_T(9) CHAP_T(10) CHAP_T(11) CHAP_T(12) CHAP_T(13) CHAP_T(14) CHAP_T(15) CHAP_T(16) CHAP_T(17) CHAP_T(18) CHAP_T(19) CHAP_T(20) CHAP_T(21) CHAP_T(22) CHAP_T(23) CHAP_T(24) CHAP_T(25) CHAP_T(26) CHAP_T(27) CHAP_T(28) CHAP_T(29) CHAP_T(30) CHAP_T(31) CHAP_T(32) CHAP_T(33) CHAP_T(34) CHAP_T(35) CHAP_T(36) CHAP_T(37) CHAP_T(38) CHAP_T(39) CHAP_T(40) CHAP_T(41) CHAP_T(42) CHAP_T(43) CHAP_T(44) CHAP_T(45) CHAP_T(46) CHAP_T(47) CHAP_T(48) CHAP_T(49) CHAP_T(50) CHAP_T(51) CHAP_T(52) CHAP_T(53) CHAP_T(54) CHAP_T(55) CHAP_T(56) CHAP_T(57) CHAP_T(58) CHAP_T(59) CHAP_T(60) CHAP_T(61) CHAP_T(62) CHAP_T(63)
typedef uint64_t (*chap_thunk_fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
static chap_thunk_fn const chap_thunks[CHAP_MAX_SLOTS] = { chap_thunk_0, chap_thunk_1, chap_thunk_2, chap_thunk_3, chap_thunk_4, chap_thunk_5, chap_thunk_6, chap_thunk_7, chap_thunk_8, chap_thunk_9, chap_thunk_10, chap_thunk_11, chap_thunk_12, chap_thunk_13, chap_thunk_14, chap_thunk_15, chap_thunk_16, chap_thunk_17, chap_thunk_18, chap_thunk_19, chap_thunk_20, chap_thunk_21, chap_thunk_22, chap_thunk_23, chap_thunk_24, chap_thunk_25, chap_thunk_26, chap_thunk_27, chap_thunk_28, chap_thunk_29, chap_thunk_30, chap_thunk_31, chap_thunk_32, chap_thunk_33, chap_thunk_34, chap_thunk_35, chap_thunk_36, chap_thunk_37, chap_thunk_38, chap_thunk_39, chap_thunk_40, chap_thunk_41, chap_thunk_42, chap_thunk_43, chap_thunk_44, chap_thunk_45, chap_thunk_46, chap_thunk_47, chap_thunk_48, chap_thunk_49, chap_thunk_50, chap_thunk_51, chap_thunk_52, chap_thunk_53, chap_thunk_54, chap_thunk_55, chap_thunk_56, chap_thunk_57, chap_thunk_58, chap_thunk_59, chap_thunk_60, chap_thunk_61, chap_thunk_62, chap_thunk_63 };

static int chap_seal_dispatch(char *err, size_t errlen, FILE *rep, FILE *rng)
{
	using namespace bpftime;
	std::vector<chap_link_rec> recs;
	{ std::lock_guard<std::mutex> lk(chap_link_registry_mu); recs = chap_link_registry; }
	if (recs.empty()) { snprintf(err, errlen, "no_frida_links"); return -1; }
	std::vector<uint64_t> funcs;
	for (auto &r : recs) {
		if (r.attach_type != attach::ATTACH_UPROBE && r.attach_type != attach::ATTACH_URETPROBE && r.attach_type != attach::ATTACH_UPROBE_OVERRIDE) {
			snprintf(err, errlen, "unsupported_attach_type:%d", r.attach_type); return -1; }
		if (!r.prog || !r.prog->chap_is_jitted() || !r.prog->chap_jit_fn()) { snprintf(err, errlen, "prog_not_jitted"); return -1; }
		bool seen = false; for (auto f : funcs) if (f == r.func) seen = true;
		if (!seen) funcs.push_back(r.func);
	}
	if (funcs.size() > CHAP_MAX_SLOTS) { snprintf(err, errlen, "too_many_hooks:%zu", funcs.size()); return -1; }
	size_t tlen = (sizeof(chap_disp_table) + 4095) & ~(size_t)4095;
	auto *t = (chap_disp_table *)mmap(nullptr, tlen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (t == MAP_FAILED) { snprintf(err, errlen, "table_mmap"); return -1; }
	t->magic = 0x4348415044495350ULL; t->n = (uint32_t)funcs.size();
	for (size_t i = 0; i < funcs.size(); i++) {
		chap_disp_slot &s = t->s[i]; s.func = funcs[i];
		for (auto &r : recs) {
			if (r.func != funcs[i]) continue;
			chap_disp_prog p{ (uint64_t (*)(void *, uint64_t))r.prog->chap_jit_fn(), r.has_cookie ? 1u : 0u, r.cookie };
			uint32_t *n = r.attach_type == attach::ATTACH_UPROBE ? &s.n_enter : r.attach_type == attach::ATTACH_URETPROBE ? &s.n_exit : &s.n_ovr;
			chap_disp_prog *arr = r.attach_type == attach::ATTACH_UPROBE ? s.enter : r.attach_type == attach::ATTACH_URETPROBE ? s.exit : s.ovr;
			if (*n >= CHAP_MAX_PROGS) { snprintf(err, errlen, "too_many_progs"); return -1; }
			arr[(*n)++] = p;
			if (r.attach_type == attach::ATTACH_UPROBE && r.prog->prog_name() && strcmp(r.prog->prog_name(), "uprobe_tx_burst") == 0) s.excl = 1;
			if (r.attach_type == attach::ATTACH_URETPROBE && r.prog->prog_name() && strncmp(r.prog->prog_name(), "uretprobe_rx_burst_drv", 15) == 0) s.excl = 2;	/* prog names are kept to 15 chars (BPF_OBJ_NAME_LEN) */
			if (r.attach_type == attach::ATTACH_UPROBE_OVERRIDE) { uint32_t c = chap_res_class(r.prog->prog_name()); if (c) s.rclass = c; }	/* Request J */
		}
	}
	/* move every link off Frida's listener/replace dispatch (bpftime's own detach), then fast-replace */
	auto &actx = get_global_attach_ctx();
	for (auto &r : recs) { int e = actx.destroy_instantiated_attach_link(r.link_id); if (e < 0) { snprintf(err, errlen, "detach_link:%d:%d", r.link_id, e); return -1; } }
	GumInterceptor *ic = gum_interceptor_obtain();
	gum_interceptor_begin_transaction(ic);
	for (size_t i = 0; i < funcs.size(); i++) {
		gpointer orig = nullptr;
		GumReplaceReturn rr = gum_interceptor_replace_fast(ic, (gpointer)funcs[i], (gpointer)chap_thunks[i], &orig);
		if (rr != GUM_REPLACE_OK || !orig) { gum_interceptor_end_transaction(ic); snprintf(err, errlen, "replace_fast:%#lx:%d", (unsigned long)funcs[i], (int)rr); return -1; }
		t->s[i].orig = (uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))orig;
	}
	gum_interceptor_end_transaction(ic);
	if (mprotect(t, tlen, PROT_READ) || mlock(t, tlen)) { snprintf(err, errlen, "table_seal"); return -1; }
	chap_disp_sel.magic = 0x4348415053454c32ULL; chap_disp_sel.t = t;
	__atomic_store_n(&chap_disp_sel.sealed, 1, __ATOMIC_SEQ_CST);
	if (mprotect(&chap_disp_sel, 4096, PROT_READ) || mlock(&chap_disp_sel, 4096)) { snprintf(err, errlen, "selector_seal"); return -1; }
	{	/* direct writes to the sealed dispatch table and its selector page must fault */
		auto probe = [](volatile unsigned char *p) -> int {
			struct sigaction sa, old; memset(&sa, 0, sizeof sa); sa.sa_handler = chap_mjmp; sigemptyset(&sa.sa_mask);
			sigaction(SIGSEGV, &sa, &old); int f = 0;
			if (sigsetjmp(chap_mjb, 1) == 0) { unsigned char v = *p; *p = (unsigned char)(v ^ 0x5a); *p = v; } else f = 1;
			sigaction(SIGSEGV, &old, nullptr); return f; };
		int f1 = probe((volatile unsigned char *)&t->pad), f2 = probe((volatile unsigned char *)&chap_disp_sel.pad[0]);
		if (rep) fprintf(rep, "DISPATCH_SEALCHECK table_write=%s selector_write=%s\n", f1 ? "FAULTED" : "SUCCEEDED", f2 ? "FAULTED" : "SUCCEEDED");
		if (!(f1 && f2)) { snprintf(err, errlen, "dispatch_sealcheck"); return -1; }
	}
	if (rng) { fprintf(rng, "0x%lx 0x%lx\n", (unsigned long)t, (unsigned long)t + tlen);
		   fprintf(rng, "0x%lx 0x%lx\n", (unsigned long)&chap_disp_sel, (unsigned long)&chap_disp_sel + 4096); }
	if (rep) {
		for (size_t i = 0; i < funcs.size(); i++) {
			const chap_disp_slot &s = t->s[i]; const unsigned char *pc = (const unsigned char *)s.func;
			uintptr_t tgt = 0, slot = 0; if (pc[0] == 0xE9) tgt = s.func + 5 + *(const int32_t *)(pc + 1);
			if (pc[0] == 0xFF && pc[1] == 0x25) { slot = s.func + 6 + *(const int32_t *)(pc + 2); tgt = *(const uintptr_t *)slot; }
			if (slot) fprintf(rep, "DISPATCH_ENTRY slot=%zu jmp[rip] target_qword_at=%#lx (inside the patched function text) -> %#lx %s\n", i,
					  (unsigned long)slot, (unsigned long)tgt, tgt == (uintptr_t)chap_thunks[i] ? "== thunk" : "!= thunk");
			fprintf(rep, "DISPATCH slot=%zu func=%#lx enter=%u exit=%u ovr=%u excl=%u rclass=%u addr=%p orig=%p thunk=%p entry_bytes=%02x%02x%02x%02x%02x jmp_target=%#lx%s\n",
				i, (unsigned long)s.func, s.n_enter, s.n_exit, s.n_ovr, s.excl, s.rclass, (const void *)&s, (void *)s.orig, (void *)chap_thunks[i], pc[0], pc[1], pc[2], pc[3], pc[4],
				(unsigned long)tgt, tgt == (uintptr_t)chap_thunks[i] ? " (direct->thunk)" : "");
		}
		fprintf(rep, "DISPATCH_SEALED hooks=%zu links=%zu table=[%p,+%zu) selector=%p\n", funcs.size(), recs.size(), (void *)t, tlen, (void *)&chap_disp_sel);
	}
	return 0;
}

/* TEST-ONLY (Request F verification): emulate a tenant overwriting the heap dispatch pointer that bpftime's
 * listener path calls (bpftime_prog::fn) with a function that returns 0. Agent handler on SIGRTMIN+11. */
static uint64_t chap_atk_ret0(void *, uint64_t) { return 0; }
extern "C" __attribute__((visibility("default"))) long chap_atk_progfn(void)
{
	using namespace bpftime;
	const char *ta = getenv("CHAP_TEST_ATK");
	if (!ta || strcmp(ta, "1") != 0) return -2;	/* inert unless the Manager launched a test run */
	std::vector<chap_link_rec> recs;
	{ std::lock_guard<std::mutex> lk(chap_link_registry_mu); recs = chap_link_registry; }
	long hit = 0; std::vector<const void *> done;
	for (auto &r : recs) {
		if (!r.prog) continue;
		bool seen = false; for (auto p : done) if (p == (const void *)r.prog) seen = true;
		if (seen) continue; done.push_back((const void *)r.prog);
		uintptr_t fn = (uintptr_t)r.prog->chap_jit_fn();
		volatile uintptr_t *w = (volatile uintptr_t *)r.prog;
		for (int k = 0; k < 64; k++) if (w[k] == fn) { w[k] = (uintptr_t)&chap_atk_ret0; hit++; break; }
	}
	return hit;
}

static void chap_atk_sig(int)
{
	long n = chap_atk_progfn(); char b[96];
	int l = snprintf(b, sizeof b, "ATK_PROGFN heap prog->fn overwritten=%ld\n", n);
	if (l > 0) (void)!write(2, b, (size_t)l);
}

/* Agent / Chaperon / engine code + RO data (incl. full-RELRO GOT) registered with the Tamper Sentinel. */
static void chap_add_code_ranges(FILE *rng, FILE *rep)
{
	Dl_info di; const char *agent = nullptr, *seal = nullptr, *prov = nullptr;
	if (dladdr((void *)&chap_dispatch, &di) && di.dli_fname) agent = di.dli_fname;
	void *s1 = dlsym(RTLD_DEFAULT, "esac_seal_now"); Dl_info d2; if (s1 && dladdr(s1, &d2) && d2.dli_fname) seal = d2.dli_fname;
	void *s2 = dlsym(RTLD_DEFAULT, "esac_hs_scan");  Dl_info d3; if (s2 && dladdr(s2, &d3) && d3.dli_fname) prov = d3.dli_fname;
	FILE *m = fopen("/proc/self/maps", "r"); if (!m) return; char ln[512]; int n = 0;
	while (fgets(ln, sizeof ln, m)) {
		unsigned long x, y; char p[5] = { 0 }, path[400] = { 0 };
		int k = sscanf(ln, "%lx-%lx %4s %*s %*s %*s %399s", &x, &y, p, path);
		if (k < 4 || p[0] != 'r' || p[1] == 'w') continue;
		bool want = (agent && !strcmp(path, agent)) || (seal && !strcmp(path, seal)) || (prov && !strcmp(path, prov)) ||
			    strstr(path, "/libhs.so") || strstr(path, "/libc.so.6") || strstr(path, "/libstdc++.so") || !strcmp(path, "[vdso]");
		if (!want) continue;
		if (rng) fprintf(rng, "0x%lx 0x%lx\n", x, y);
		if (rep) fprintf(rep, "CODE_RANGE %#lx-%#lx %s %s\n", x, y, p, path);
		n++;
	}
	fclose(m);
	if (rep) fprintf(rep, "CODE_RANGES registered=%d (agent, esac_seal, hs provider, libhs, libc, libstdc++, vdso; non-writable segments)\n", n);
}

/* Post-seal: writable words that still point into anonymous executable code (JIT + Frida slices). */
static void chap_post_seal_scan(FILE *rep)
{
	struct rg { uintptr_t s, e; char perm[5]; bool anon; char path[96]; };
	std::vector<rg> all, code; FILE *m = fopen("/proc/self/maps", "r"); if (!m) return; char ln[512];
	while (fgets(ln, sizeof ln, m)) { rg r{}; unsigned long x, y; char p[5] = { 0 }, path[96] = { 0 };
		int k = sscanf(ln, "%lx-%lx %4s %*s %*s %*s %95s", &x, &y, p, path); if (k < 3) continue;
		r.s = x; r.e = y; memcpy(r.perm, p, 5); r.anon = k < 4; snprintf(r.path, sizeof r.path, "%s", k >= 4 ? path : "[anon]");
		if (strstr(r.path, "[vvar]") || strstr(r.path, "[vsyscall]") || strstr(r.path, "/dev/")) continue;
		all.push_back(r); if (r.anon && p[0] == 'r' && p[2] == 'x') code.push_back(r); }
	fclose(m);
	long total = 0, tw = 0;
	struct sigaction sa, ob, os; memset(&sa, 0, sizeof sa); sa.sa_handler = chap_mjmp; sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, &ob); sigaction(SIGSEGV, &sa, &os);
	for (size_t ri = 0; ri < all.size(); ri++) { const rg &r = all[ri];
		if (r.perm[0] != 'r' || r.perm[1] != 'w') continue;
		if (sigsetjmp(chap_mjb, 1)) continue;
		long c = 0; for (uintptr_t p = r.s; p + 8 <= r.e; p += 8) { uintptr_t v = *(volatile uintptr_t *)p;
			for (auto &cr : code) if (v >= cr.s && v < cr.e) { c++; break; } }
		if (c) { total += c; if (rep) fprintf(rep, "POSTSEAL writable_code_ptrs %s %s : %ld\n", r.perm, r.path, c); }
		if (c && r.path[0] != '[') tw += c; }
	sigaction(SIGBUS, &ob, nullptr); sigaction(SIGSEGV, &os, nullptr);
	if (rep) fprintf(rep, "POSTSEAL total_writable_words_pointing_into_anon_exec=%ld (dispatch path no longer reads them when sealed dispatch is on)\n", total);
}

/* ===================== Chaperon Request-E item-2: LAUNCH BARRIER (execution gate) =====================
 * Runs inside the trusted bootstrap, called from the __libc_start_main hook BEFORE the original
 * __libc_start_main runs the executable's DT_INIT_ARRAY (679 constructors in static testpmd) and main
 * (EAL init, NIC probe, Resource API). It returns ONLY after: required kernel maps verified by NAME + ID +
 * init, no bpf-map fd left, their mappings RO and non-upgradable, (optional) L7 provider initialized, the
 * immutable view + .rodata + selector sealed, code W^X + ufunc table sealed, and the Manager — after
 * independently verifying /proc state and registering ALL ranges with the Tamper Sentinel — has written a
 * root-owned GO token in a root-owned, non-g/o-writable CHAP_GO_DIR (default /var/lib/chap_gate). Any failure never returns (untrusted code never runs). */
extern "C" int chap_imm_view_seal(char *err, size_t errlen, const char *ranges_path, const char *report_path);
static uint64_t chap_mono_ns()
{ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec; }
static void chap_trace(const char *fmt, ...)
{
	char b[768]; va_list ap; va_start(ap, fmt); int n = vsnprintf(b, sizeof b, fmt, ap); va_end(ap); if (n < 0) return;
	char line[900]; int m = snprintf(line, sizeof line, "[chap-boot pid=%d t=%llu] %s\n", (int)getpid(), (unsigned long long)chap_mono_ns(), b);
	if (m > (int)sizeof line) m = (int)sizeof line;
	(void)!write(2, line, (size_t)m);
	char p[80]; snprintf(p, sizeof p, "/tmp/chap_boot_%d", (int)getpid());
	int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644); if (fd >= 0) { (void)!write(fd, line, (size_t)m); close(fd); }
}
[[noreturn]] static void chap_barrier_fail(const char *why)
{
	chap_trace("BARRIER_FAIL reason=%s -> untrusted application code NOT entered; holding for Manager refuse", why);
	uint64_t t0 = chap_mono_ns();
	while (chap_mono_ns() - t0 < 120ull * 1000000000ull) { struct timespec ts{ 0, 50000000 }; nanosleep(&ts, nullptr); }
	_exit(97);
}
static bool chap_go_present(char *tok, size_t tl)
{
	const char *gd = getenv("CHAP_GO_DIR"); if (!gd || gd[0] != '/') gd = "/var/lib/chap_gate";
	char rd[PATH_MAX]; if (!realpath(gd, rd)) return false;
	struct stat ds; if (stat(rd, &ds) != 0 || !S_ISDIR(ds.st_mode) || ds.st_uid != 0 || (ds.st_mode & 022)) return false;
	char par[PATH_MAX + 8]; snprintf(par, sizeof par, "%s/..", rd);   /* parent must also be root-owned, not g/o-writable */
	struct stat ps; if (stat(par, &ps) != 0 || ps.st_uid != 0 || (ps.st_mode & 022)) return false;
	char p[PATH_MAX + 32]; snprintf(p, sizeof p, "%s/go_%d", rd, (int)getpid());
	int fd = open(p, O_RDONLY | O_NOFOLLOW); if (fd < 0) return false;
	struct stat fs; bool ok = fstat(fd, &fs) == 0 && S_ISREG(fs.st_mode) && fs.st_uid == 0 && !(fs.st_mode & 022);
	char b[64] = { 0 }; ssize_t r = ok ? read(fd, b, sizeof b - 1) : -1; close(fd);
	if (!ok || r < 2 || strncmp(b, "GO", 2) != 0) return false;
	for (char *q = b; *q; q++) if (*q == '\n') *q = 0;
	snprintf(tok, tl, "%s", b); return true;
}
static void chap_launch_barrier()
{
	chap_trace("BARRIER_ENTER trusted bootstrap done; executable init_array + main NOT yet run");
	if (__atomic_load_n(&initialized, __ATOMIC_SEQ_CST) != AGENT_READY) chap_barrier_fail("agent_init");
	const char *names = getenv("BPFTIME_KERNEL_MAP_NAMES");
	if (!names || !*names) chap_barrier_fail("required_map_list_empty");
	auto *mgr = bpftime::shm_holder.global_shared_memory.get_manager();
	if (!mgr) chap_barrier_fail("no_manager");
	std::string ids, all(names); int need = 0, got = 0; uint32_t zero = 0; size_t pos = 0;
	while (pos <= all.size()) {
		size_t c = all.find(',', pos);
		std::string nm = all.substr(pos, c == std::string::npos ? std::string::npos : c - pos);
		if (!nm.empty()) {
			need++; bool found = false;
			for (std::size_t fd = 0; fd < mgr->size(); fd++) {
				const auto &hv = mgr->get_handler((int)fd);
				if (!std::holds_alternative<bpftime::bpf_map_handler>(hv)) continue;
				const auto &mh = std::get<bpftime::bpf_map_handler>(hv);
				if (mh.type != bpftime::bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY || nm != mh.name.c_str()) continue;
				found = true;
				if (!bpftime_map_lookup_elem((int)fd, &zero)) { std::string w = "map_init:" + nm; chap_barrier_fail(w.c_str()); }
				if (!mh.attr.kernel_bpf_map_id) { std::string w = "map_no_kernel_id:" + nm; chap_barrier_fail(w.c_str()); }
				ids += nm + ":" + std::to_string(mh.attr.kernel_bpf_map_id) + ","; got++; break;
			}
			if (!found) { std::string w = "map_missing:" + nm; chap_barrier_fail(w.c_str()); }
		}
		if (c == std::string::npos) break; pos = c + 1;
	}
	if (need == 0 || got != need) chap_barrier_fail("required_map_count");
	chap_trace("STEP2a MAPS_RO_INIT_OK required=%d maps=%s", need, ids.c_str());
	int bpffd = 0; DIR *d = opendir("/proc/self/fd");
	if (d) { struct dirent *de; while ((de = readdir(d))) { char lp[300], tg[256]; snprintf(lp, sizeof lp, "/proc/self/fd/%s", de->d_name);
		ssize_t r = readlink(lp, tg, sizeof tg - 1); if (r > 0) { tg[r] = 0; if (strstr(tg, "bpf-map")) bpffd++; } } closedir(d); }
	if (bpffd) chap_barrier_fail("bpf_map_fd_present");
	int rom = 0, rwm = 0; FILE *mf = fopen("/proc/self/maps", "r"); char ln[512];
	if (mf) { while (fgets(ln, sizeof ln, mf)) if (strstr(ln, "bpf-map")) { char pm[8] = { 0 }; sscanf(ln, "%*s %7s", pm); if (pm[1] == 'w') rwm++; else rom++; } fclose(mf); }
	if (rwm || rom < need) chap_barrier_fail("bpf_map_mapping_not_ro");
	chap_trace("STEP2b FD_REMOVED bpf_map_fds=0 ro_map_mappings=%d writable_map_mappings=0", rom);
	if (getenv("CHAP_L7_REQUIRED")) { auto okf = (int (*)(void))dlsym(RTLD_DEFAULT, "esac_hs_init_ok"); if (!okf || okf() != 1) chap_barrier_fail("l7_init"); }
	char err[192] = "", rp[96], vp[96];
	snprintf(rp, sizeof rp, "/tmp/chap_imm_ranges_%d", (int)getpid()); snprintf(vp, sizeof vp, "/tmp/chap_imm_view_%d", (int)getpid());
	char dp[96]; snprintf(dp, sizeof dp, "/tmp/chap_dispatch_%d", (int)getpid());
	FILE *drep = fopen(dp, "w");
	if (getenv("CHAP_SEALED_DISPATCH")) {
		FILE *rf0 = fopen(rp, "w");
		if (chap_seal_dispatch(err, sizeof err, drep, rf0) != 0) { if (rf0) fclose(rf0); if (drep) fclose(drep); std::string w = std::string("sealed_dispatch:") + err; chap_barrier_fail(w.c_str()); }
		if (rf0) fclose(rf0);
		chap_trace("STEP3a DISPATCH_SEALED hook->filter dispatch moved to sealed thunk table (Frida listeners detached)");
	}
	if (getenv("CHAP_IMM_VIEW")) { if (chap_imm_view_seal(err, sizeof err, getenv("CHAP_SEALED_DISPATCH") ? (std::string(rp) + ".view").c_str() : rp, vp) != 0) { std::string w = std::string("imm_view:") + err; chap_barrier_fail(w.c_str()); } }
	if (getenv("CHAP_SEALED_DISPATCH")) {   /* append view ranges after the dispatch ranges */
		std::string vr = std::string(rp) + ".view"; FILE *in = fopen(vr.c_str(), "r"), *out = fopen(rp, "a"); char b[256];
		if (in && out) while (fgets(b, sizeof b, in)) fputs(b, out);
		if (in) fclose(in); if (out) fclose(out); unlink(vr.c_str()); }
	chap_trace("STEP3b VIEW_SEALED SHM routing view + .rodata + selector RO");
	{ FILE *rf2 = fopen(rp, "a"); chap_add_code_ranges(rf2, drep); if (rf2) fclose(rf2); }
	auto dbr = (void (*)(void **, unsigned long *))dlsym(RTLD_DEFAULT, "esac_hs_db_region");
	auto spr = (void (*)(void **, unsigned long *))dlsym(RTLD_DEFAULT, "esac_hs_state_region");
	{ FILE *rf = fopen(rp, "a"); if (rf) { void *ra = nullptr; unsigned long rl = 0;
		if (dbr) { dbr(&ra, &rl); if (ra && rl) { fprintf(rf, "0x%lx 0x%lx\n", (unsigned long)ra, (unsigned long)ra + rl); if (drep) fprintf(drep, "TARGET hs_db %#lx %#lx\n", (unsigned long)ra, (unsigned long)ra + rl); } }
		ra = nullptr; rl = 0; if (spr) { spr(&ra, &rl); if (ra && rl) { fprintf(rf, "0x%lx 0x%lx\n", (unsigned long)ra, (unsigned long)ra + rl); if (drep) fprintf(drep, "TARGET hs_state %#lx %#lx\n", (unsigned long)ra, (unsigned long)ra + rl); } }
		fclose(rf); } }
	{ FILE *rf = fopen(rp, "a"); int nx = 0;           /* JIT code + JIT GOT pages: registered, mlock'd */
	  for (auto &x : chap_extra_ranges) { (void)mlock((void *)x.first, x.second - x.first); if (rf) { fprintf(rf, "0x%lx 0x%lx\n", (unsigned long)x.first, (unsigned long)x.second); nx++; } if (drep) fprintf(drep, "TARGET jit %#lx %#lx\n", (unsigned long)x.first, (unsigned long)x.second); }
	  if (rf) fclose(rf); chap_trace("JIT_RANGES registered_candidates=%d (anon r-x JIT code + anon r-- helper-slot pages)", nx); }
	auto seal_now = (int (*)(int *, int *))dlsym(RTLD_DEFAULT, "esac_seal_now");
	int sealed = 0, sfail = 1;
	if (!seal_now || seal_now(&sealed, &sfail) != 0 || sealed < 1 || sfail != 0) chap_barrier_fail("code_seal");
	chap_trace("STEP3c CODE_SEALED W^X=%d ufunc-table RO; agent/JIT/engine code ranges queued for registration", sealed);
	chap_post_seal_scan(drep);
	{ const char *ta = getenv("CHAP_TEST_ATK");
	  if (ta && strcmp(ta, "1") == 0) { struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = chap_atk_sig; sa.sa_flags = SA_RESTART;	/* do not break the app CLI read() */
		sigemptyset(&sa.sa_mask); sigaction(SIGRTMIN + 11, &sa, nullptr); } }
	if (drep) fclose(drep);
	chap_trace("BARRIER_OK maps=%s bpf_map_fds=0 ro_map_mappings=%d wx_sealed=%d imm_ranges=%s", ids.c_str(), rom, sealed, rp);
	char tok[64]; uint64_t t0 = chap_mono_ns(); const char *tos = getenv("CHAP_GO_TIMEOUT_S");
	uint64_t to = (tos ? strtoull(tos, nullptr, 10) : 120ull) * 1000000000ull;
	while (!chap_go_present(tok, sizeof tok)) {
		if (chap_mono_ns() - t0 > to) { chap_trace("BARRIER_TIMEOUT no root GO -> exit; untrusted code never ran"); _exit(98); }
		struct timespec ts{ 0, 20000000 }; nanosleep(&ts, nullptr);
	}
	chap_trace("GO_RECEIVED token=%s -> releasing to untrusted application (executable init_array, then main)", tok);
}

extern "C" int bpftime_hooked_main(int argc, char **argv, char **envp)
{
	int stay_resident = 0;
	injected_with_frida = false;
	bpftime_agent_main("", &stay_resident);
	int ret = orig_main_func(argc, argv, envp);
	return ret;
}

extern "C" int __libc_start_main(int (*main)(int, char **, char **), int argc,
				 char **argv,
				 int (*init)(int, char **, char **),
				 void (*fini)(void), void (*rtld_fini)(void),
				 void *stack_end)
{
	orig_main_func = main;
	using this_func_t = decltype(&__libc_start_main);
	this_func_t orig = (this_func_t)dlsym(RTLD_NEXT, "__libc_start_main");
	if (getenv("CHAP_GATED_LAUNCH")) {
		/* Chaperon Request-E item-2: bootstrap + barrier BEFORE the original __libc_start_main runs the
		   executable's DT_INIT_ARRAY (app constructors) and main. */
		chap_trace("BOOT_START in __libc_start_main hook, before executable init_array (%s)", (argv && argv[0]) ? argv[0] : "?");
		int stay_resident = 0;
		injected_with_frida = false;
		bpftime_agent_main("", &stay_resident);
		chap_launch_barrier();
		return orig(main, argc, argv, init, fini, rtld_fini, stack_end);
	}

	return orig(bpftime_hooked_main, argc, argv, init, fini, rtld_fini,
		    stack_end);
}
static void sig_handler_sigusr1_detach(int sig)
{
	(void)sig;
	// Async-signal-safe: do not call spdlog / malloc / locks here.
	auto_refresh_epoch.fetch_add(1, std::memory_order_acq_rel);
	int fd = detach_pipe_fds[1];
	if (fd >= 0) {
		uint8_t one = 1;
		ssize_t ignored = write(fd, &one, 1);
		(void)ignored;
	}
}

static int parse_auto_refresh_ms(const gchar *data)
{
	if (data == nullptr || data[0] == '\0')
		return 0;
	std::string_view sv(data);
	// Simple "k=v" pairs separated by ';' or whitespace.
	for (size_t pos = 0; pos < sv.size();) {
		while (pos < sv.size() &&
		       (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == ';'))
			pos++;
		if (pos >= sv.size())
			break;
		size_t end = pos;
		while (end < sv.size() && sv[end] != ';' && sv[end] != ' ' &&
		       sv[end] != '\t')
			end++;
		auto item = sv.substr(pos, end - pos);
		pos = end;
		auto eq = item.find('=');
		if (eq == std::string_view::npos)
			continue;
		auto key = item.substr(0, eq);
		auto val = item.substr(eq + 1);
		if (key != "auto_refresh_ms")
			continue;
		int out = 0;
		try {
			out = std::stoi(std::string(val));
		} catch (...) {
			return 0;
		}
		if (out < 0)
			return 0;
		return out;
	}
	return 0;
}

static pid_t parse_loader_pid(const gchar *data)
{
	if (data == nullptr || data[0] == '\0')
		return -1;
	std::string_view sv(data);
	// Simple "k=v" pairs separated by ';' or whitespace.
	for (size_t pos = 0; pos < sv.size();) {
		while (pos < sv.size() &&
		       (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == ';'))
			pos++;
		if (pos >= sv.size())
			break;
		size_t end = pos;
		while (end < sv.size() && sv[end] != ';' && sv[end] != ' ' &&
		       sv[end] != '\t')
			end++;
		auto item = sv.substr(pos, end - pos);
		pos = end;
		auto eq = item.find('=');
		if (eq == std::string_view::npos)
			continue;
		auto key = item.substr(0, eq);
		auto val = item.substr(eq + 1);
		if (key != "loader_pid")
			continue;
		try {
			long long out = std::stoll(std::string(val));
			if (out <= 0)
				return -1;
			if (out > std::numeric_limits<pid_t>::max())
				return -1;
			return (pid_t)out;
		} catch (...) {
			return -1;
		}
	}
	return -1;
}

static bool parse_force_reinit(const gchar *data)
{
	if (data == nullptr || data[0] == '\0')
		return false;
	std::string_view sv(data);
	for (size_t pos = 0; pos < sv.size();) {
		while (pos < sv.size() &&
		       (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == ';'))
			pos++;
		if (pos >= sv.size())
			break;
		size_t end = pos;
		while (end < sv.size() && sv[end] != ';' && sv[end] != ' ' &&
		       sv[end] != '\t')
			end++;
		auto item = sv.substr(pos, end - pos);
		pos = end;
		auto eq = item.find('=');
		if (eq == std::string_view::npos)
			continue;
		auto key = item.substr(0, eq);
		auto val = item.substr(eq + 1);
		if (key != "force_reinit")
			continue;
		return val == "1" || val == "true" || val == "yes";
	}
	return false;
}

static int refresh_attach_session(const gchar *data)
{
	if (__atomic_load_n(&initialized, __ATOMIC_SEQ_CST) != AGENT_READY) {
		SPDLOG_WARN("agent_control: agent not initialized");
		return -EINVAL;
	}
	if (!global_ctx_constructed.load(std::memory_order_acquire)) {
		SPDLOG_WARN("agent_control: global ctx not constructed");
		return -EINVAL;
	}

	std::lock_guard<std::mutex> guard(detach_mutex);
	apply_injected_kv_overrides(data);
	auto_refresh_epoch.fetch_add(1, std::memory_order_acq_rel);
	{
		std::lock_guard<std::mutex> tguard(auto_refresh_thread_mutex);
		if (auto_refresh_thread.joinable())
			auto_refresh_thread.join();
	}
	(void)ctx_holder.ctx.destroy_all_attach_links();
	ctx_holder.ctx.reset_instantiated_state();

	int res =
		ctx_holder.ctx.init_attach_ctx_from_handlers(bpftime_get_runtime_config());
	if (res != 0) {
		SPDLOG_ERROR(
			"agent_control: init_attach_ctx_from_handlers failed: {}",
			res);
		return res < 0 ? res : -EINVAL;
	}
	if (!shm_holder.global_shared_memory.add_pid_into_alive_agent_set(
		    getpid())) {
		SPDLOG_ERROR("agent_control: unable to record alive agent pid");
		(void)ctx_holder.ctx.destroy_all_attach_links();
		ctx_holder.ctx.reset_instantiated_state();
		return -EAGAIN;
	}

	int auto_refresh_ms = parse_auto_refresh_ms(data);
	pid_t loader_pid = parse_loader_pid(data);
	if (auto_refresh_ms > 0) {
		auto_refresh_loader_pid.store(loader_pid,
					      std::memory_order_release);
		SPDLOG_INFO("Starting auto-refresh thread ({} ms, loader_pid={})",
			    auto_refresh_ms, (int)loader_pid);
		uint64_t epoch =
			auto_refresh_epoch.fetch_add(1, std::memory_order_acq_rel) + 1;
		std::lock_guard<std::mutex> tguard(auto_refresh_thread_mutex);
		if (auto_refresh_thread.joinable())
			auto_refresh_thread.join();
		auto_refresh_thread = std::thread([auto_refresh_ms, epoch]() {
			for (;;) {
				if (auto_refresh_epoch.load(
					    std::memory_order_acquire) != epoch) {
					return;
				}
#if __linux__
				pid_t lp = auto_refresh_loader_pid.load(
					std::memory_order_acquire);
				if (lp > 0) {
					if (::kill(lp, 0) != 0 &&
					    errno == ESRCH) {
						SPDLOG_INFO(
							"Auto-refresh: loader pid {} is gone; stopping",
							(int)lp);
						return;
					}
				}
#endif
				std::this_thread::sleep_for(
					std::chrono::milliseconds(auto_refresh_ms));
				try {
					ctx_holder.ctx.init_attach_ctx_from_handlers(
						bpftime_get_runtime_config());
				} catch (const std::exception &ex) {
					SPDLOG_DEBUG(
						"Auto-refresh: init_attach_ctx_from_handlers failed: {}",
						ex.what());
				}
			}
		});
		std::atexit(stop_auto_refresh_at_exit);
	}

	chap_confirm_kernel_maps();
	chap_write_seal_targets();
	SPDLOG_INFO("Attach successfully");
	start_agent_ipc_server_once();
	return 0;
}

static void apply_injected_kv_overrides(const gchar *data)
{
	if (data == nullptr || data[0] == '\0')
		return;
	std::string_view sv(data);
	for (size_t pos = 0; pos < sv.size();) {
		while (pos < sv.size() &&
		       (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == ';'))
			pos++;
		if (pos >= sv.size())
			break;
		size_t end = pos;
		while (end < sv.size() && sv[end] != ';' && sv[end] != ' ' &&
		       sv[end] != '\t')
			end++;
		auto item = sv.substr(pos, end - pos);
		pos = end;
		auto eq = item.find('=');
		if (eq == std::string_view::npos)
			continue;
		auto key = item.substr(0, eq);
		auto val = item.substr(eq + 1);
		if (key == "cuda_late_ptx_dir") {
			std::string v(val);
			setenv("BPFTIME_CUDA_LATE_PTX_DIR", v.c_str(), 1);
			SPDLOG_INFO("bpftime-agent: BPFTIME_CUDA_LATE_PTX_DIR={}",
				    v);
		} else if (key == "cuda_disable_cuobjdump") {
			std::string v(val);
			setenv("BPFTIME_CUDA_DISABLE_CUOBJDUMP", v.c_str(), 1);
			SPDLOG_INFO(
				"bpftime-agent: BPFTIME_CUDA_DISABLE_CUOBJDUMP={}",
				v);
		}
	}
}

#ifdef BPFTIME_ENABLE_CUDA_ATTACH
namespace bpftime::vm::compat
{
namespace llvm
{
void register_llvm_vm_factory();
} // namespace llvm
} // namespace bpftime::vm::compat
void **(*original___cudaRegisterFatBinary)(void *) = nullptr;

extern "C" void **__cudaRegisterFatBinary(void *fatbin)
{
	try {
		auto orig = try_get_original_func("__cudaRegisterFatBinary",
						 original___cudaRegisterFatBinary);
		if (orig == nullptr)
			return nullptr;
		// We have to register llvmbpf manually, since this function
		// (__cudaRegisterFatBinary) might be called before llvm is registered
		bpftime::vm::compat::llvm::register_llvm_vm_factory();
		return orig(fatbin);
	} catch (...) {
		if (original___cudaRegisterFatBinary != nullptr)
			return original___cudaRegisterFatBinary(fatbin);
	}
	return nullptr;
}
#endif
extern "C" void bpftime_agent_main(const gchar *data, gboolean *stay_resident)
{
	install_agent_bootstrap_logger();
	bool force_reinit = false;
	bool recorded_alive_pid = false;
	bool ctx_constructed = false;
	bool claimed_initialization = false;
	auto init_fail = [&]() noexcept {
		if (!claimed_initialization)
			return;
		try {
			reset_syscall_trace_global();
		} catch (...) {
		}
		try {
			auto_refresh_epoch.fetch_add(1, std::memory_order_acq_rel);
			std::lock_guard<std::mutex> guard(
				auto_refresh_thread_mutex);
			if (auto_refresh_thread.joinable())
				auto_refresh_thread.join();
		} catch (...) {
		}
		for (int &fd : detach_pipe_fds) {
			if (fd >= 0) {
				::close(fd);
				fd = -1;
			}
		}
		detach_thread_started.store(false, std::memory_order_release);
		if (ctx_constructed) {
			try {
				ctx_holder.destroy();
			} catch (...) {
			}
			ctx_constructed = false;
		}
		global_ctx_constructed.store(false, std::memory_order_release);
		if (recorded_alive_pid) {
			try {
				shm_holder.global_shared_memory
					.remove_pid_from_alive_agent_set(
						getpid());
			} catch (...) {
			}
			recorded_alive_pid = false;
		}
		__atomic_store_n(&initialized, AGENT_UNINITIALIZED,
				 __ATOMIC_SEQ_CST);
	};
	try {
#ifdef __linux__
			// If an agent IPC server is already present in this process,
			// refresh it instead of initializing a new copy.
			if (try_forward_to_existing_agent(data)) {
				*stay_resident = FALSE;
				return;
			}
#endif
			// If another copy of the agent is already present in this
			// process (Frida commonly loads via anonymous fd paths), delegate
			// to it instead of initializing a new copy.
			if (auto existing = find_other_loaded_agent_control();
			    existing) {
				existing(data);
				*stay_resident = FALSE;
				return;
			}

			force_reinit = parse_force_reinit(data);
			{
				int expected = AGENT_UNINITIALIZED;
				if (!__atomic_compare_exchange_n(
					    &initialized, &expected,
					    AGENT_INITIALIZING, false,
					    __ATOMIC_SEQ_CST,
					    __ATOMIC_SEQ_CST)) {
					if (expected != AGENT_READY) {
						*stay_resident = FALSE;
						return;
					}
					if (!force_reinit) {
						SPDLOG_INFO(
							"Agent already initialized, skipping re-initializing..");
						start_agent_ipc_server_once();
						return;
					}
					SPDLOG_INFO(
						"Agent already initialized; force_reinit=1, refreshing attach session..");
					(void)refresh_attach_session(data);
					*stay_resident = TRUE;
					return;
				}
				claimed_initialization = true;
			}

			SPDLOG_DEBUG("Entered bpftime_agent_main");

			// SHM can race with the loader process; retry a bit to avoid
			// flakiness in "spawn loader then inject agent" workflows.
			std::string last_err;
			bool shm_ok = false;
			std::unique_ptr<shm_lifecycle_lock> shm_lock;
			for (int attempt = 0; attempt < 60; attempt++) {
				try {
					shm_lock =
						std::make_unique<shm_lifecycle_lock>(
							get_global_shm_name());
					bpftime_initialize_global_shm(
						shm_open_type::SHM_OPEN_ONLY);
					shm_ok = true;
					break;
				} catch (const std::exception &ex) {
					last_err = ex.what();
					shm_lock.reset();
					std::this_thread::sleep_for(
						std::chrono::milliseconds(
							50));
				}
			}
			if (!shm_ok) {
				SPDLOG_ERROR(
					"Unable to initialize shared memory: {}",
					last_err);
				init_fail();
				return;
			}
			auto &runtime_config = bpftime_get_runtime_config();
			bpftime_set_logger(std::string(
				runtime_config.get_logger_output_path()));
			apply_injected_kv_overrides(data);
			ctx_holder.init();
			ctx_constructed = true;
			global_ctx_constructed.store(
				true, std::memory_order_release);
#if __linux__ && BPFTIME_BUILD_WITH_LIBBPF
			// Register syscall trace impl
			auto syscall_trace_impl =
				std::make_unique<syscall_trace_attach_impl>();
			syscall_trace_impl->set_original_syscall_function(
				orig_hooker);
			auto *syscall_trace_impl_ptr = syscall_trace_impl.get();
			ctx_holder.ctx.register_attach_impl(
				{ ATTACH_SYSCALL_TRACE },
				std::move(syscall_trace_impl),
				[](const std::string_view &sv, int &err) {
					std::unique_ptr<attach_private_data>
						priv_data =
							std::make_unique<
								syscall_trace_attach_private_data>();
					if (int e =
						    priv_data->initialize_from_string(
							    sv);
					    e < 0) {
						err = e;
						return std::unique_ptr<
							attach_private_data>();
					}
					return priv_data;
				});
#endif
			// Register uprobe attach impl
#if BPFTIME_HAVE_TRAP_UPROBE_ATTACH
			SPDLOG_INFO("Using the trap (breakpoint) uprobe backend");
			ctx_holder.ctx.register_attach_impl(
				{ trap::ATTACH_UPROBE,
				  trap::ATTACH_URETPROBE,
				  trap::ATTACH_UPROBE_OVERRIDE,
				  trap::ATTACH_UREPLACE },
				std::make_unique<trap::trap_attach_impl>(),
				[](const std::string_view &sv, int &err)
					-> std::unique_ptr<attach_private_data> {
					auto priv_data = std::make_unique<
						trap::trap_attach_private_data>();
					if (int e =
						    priv_data->initialize_from_string(
							    sv);
					    e < 0) {
						err = e;
						return std::unique_ptr<
							attach_private_data>();
					}
					return priv_data;
				});
#elif BPFTIME_HAVE_FRIDA_ATTACH
			ctx_holder.ctx.register_attach_impl(
				{ ATTACH_UPROBE, ATTACH_URETPROBE,
				  ATTACH_UPROBE_OVERRIDE, ATTACH_UREPLACE },
				std::make_unique<attach::frida_attach_impl>(
					runtime_config.enable_frida_fuzzy_backtracer),
				[](const std::string_view &sv, int &err)
					-> std::unique_ptr<attach_private_data> {
					auto priv_data = std::make_unique<
						frida_attach_private_data>();
					if (int e =
						    priv_data->initialize_from_string(
							    sv);
					    e < 0) {
						err = e;
						return std::unique_ptr<
							attach_private_data>();
					}
					return priv_data;
				});
#else
			SPDLOG_WARN("No uprobe attach backend available");
#endif

#ifdef BPFTIME_ENABLE_CUDA_ATTACH
			// Register cuda attach impl
			ctx_holder.ctx.register_attach_impl(
				{ ATTACH_CUDA_PROBE, ATTACH_CUDA_RETPROBE },
				std::make_unique<attach::nv_attach_impl>(),
				[](const std::string_view &sv, int &err) {
					std::unique_ptr<attach_private_data>
						priv_data =
							std::make_unique<
								nv_attach_private_data>();
					if (int e =
						    priv_data->initialize_from_string(
							    sv);
					    e < 0) {
						err = e;
						return std::unique_ptr<
							attach_private_data>();
					}
					return priv_data;
				});
#endif
#if __linux__ && BPFTIME_BUILD_WITH_LIBBPF
			syscall_trace_impl_ptr->set_to_global();
#endif
			SPDLOG_INFO("Initializing agent..");
			// eSAC: register the Hyperscan L7 matcher (esac_hs_scan) ufunc BEFORE attach. Its
			// provider .so (esac_*_ufunc.so) is LD_PRELOAD'd, so the symbol is globally
			// resolvable at agent-init (unlike the tenant's own rte_pktmbuf_free_bulk). Only
			// attempt when the provider is present (L7 tenants); if present but unresolvable,
			// SAFE-STOP the agent (init_fail) rather than silently running with L7 disabled.
			if (dlsym(RTLD_DEFAULT, "esac_hs_scan")) {
				ebpf_ufunc_func_info hs = {};
				std::strncpy(hs.name, "esac_hs_scan", sizeof(hs.name) - 1);
				hs.num_args = 2;
				hs.arg_types[0] = UFUNC_TYPE_POINTER;
				hs.arg_types[1] = UFUNC_TYPE_UINT32;
				hs.ret_type = UFUNC_TYPE_UINT64;
				if (bpftime_ufunc_resolve_from_info(
					    hs, [](const char *name) {
						return dlsym(RTLD_DEFAULT, name);
					    }) != 0) {
					SPDLOG_ERROR("eSAC hyperscan ufunc unavailable");
					init_fail();
					return;
				}
				SPDLOG_INFO("eSAC: registered esac_hs_scan ufunc (pre-attach)");
			}
			// Chaperon Request I: native EAL-argument parser for the resource Agent's rte_eal_init check
			if (dlsym(RTLD_DEFAULT, "chap_eal_args")) {
				ebpf_ufunc_func_info ea = {};
				std::strncpy(ea.name, "chap_eal_args", sizeof(ea.name) - 1);
				ea.num_args = 3;
				ea.arg_types[0] = UFUNC_TYPE_UINT64;
				ea.arg_types[1] = UFUNC_TYPE_POINTER;
				ea.arg_types[2] = UFUNC_TYPE_POINTER;
				ea.ret_type = UFUNC_TYPE_UINT64;
				if (bpftime_ufunc_resolve_from_info(ea, [](const char *name) { return dlsym(RTLD_DEFAULT, name); }) != 0) {
					SPDLOG_ERROR("Chaperon chap_eal_args ufunc unavailable");
					init_fail();
					return;
				}
			}

			try {
				int res = ctx_holder.ctx
						  .init_attach_ctx_from_handlers(
							  runtime_config);
				if (res != 0) {
					SPDLOG_INFO(
						"Failed to initialize attach context, exiting..");
					init_fail();
					return;
				}
			} catch (const std::exception &ex) {
				SPDLOG_ERROR(
					"Unable to instantiate handlers: {}",
					ex.what());
				init_fail();
				return;
			}
			// eSAC: register the tenant's DPDK bulk-free AFTER attach. At agent-init the
			// tenant's statically-linked rte_pktmbuf_free_bulk is not yet globally
			// resolvable via dlsym(RTLD_DEFAULT); by post-attach it is. A short retry
			// covers late symbol settling. Non-fatal: if still unresolved the comm gate
			// safely fail-closes (ACT_KILL), preserving the prior behaviour.
			{
				void *fb = nullptr;
				for (int attempt = 0; attempt < 50 && !fb; attempt++) {
					fb = dlsym(RTLD_DEFAULT, "rte_pktmbuf_free_bulk");
					if (!fb) usleep(1000);
				}
				if (fb) {
					ebpf_ufunc_func_info free_bulk = {};
					std::strncpy(free_bulk.name, "rte_pktmbuf_free_bulk",
						    sizeof(free_bulk.name) - 1);
					free_bulk.num_args = 2;
					free_bulk.arg_types[0] = UFUNC_TYPE_POINTER;
					free_bulk.arg_types[1] = UFUNC_TYPE_UINT32;
					free_bulk.ret_type = UFUNC_TYPE_VOID;
					if (bpftime_ufunc_resolve_from_info(
						    free_bulk, [](const char *name) {
							return dlsym(RTLD_DEFAULT, name);
						    }) != 0)
						SPDLOG_WARN("eSAC: rte_pktmbuf_free_bulk resolve failed post-attach; L7 drop -> fail-close");
					else
						SPDLOG_INFO("eSAC: registered rte_pktmbuf_free_bulk ufunc (post-attach)");
				} else {
					SPDLOG_WARN("eSAC: rte_pktmbuf_free_bulk unresolvable post-attach; L7 drop -> fail-close");
				}
			}
			srand(std::random_device()());

			int auto_refresh_ms = parse_auto_refresh_ms(data);
			pid_t loader_pid = parse_loader_pid(data);
			if (auto_refresh_ms > 0) {
				auto_refresh_loader_pid.store(
					loader_pid,
					std::memory_order_release);
				SPDLOG_INFO(
					"Starting auto-refresh thread ({} ms, loader_pid={})",
					auto_refresh_ms, (int)loader_pid);
				uint64_t epoch =
					auto_refresh_epoch.fetch_add(
						1, std::memory_order_acq_rel) +
					1;
				std::lock_guard<std::mutex> guard(
					auto_refresh_thread_mutex);
				if (auto_refresh_thread.joinable())
					auto_refresh_thread.join();
				auto_refresh_thread = std::thread(
					[auto_refresh_ms, epoch]() {
						for (;;) {
							if (auto_refresh_epoch.load(
								    std::memory_order_acquire) !=
							    epoch) {
								return;
							}
#if __linux__
							pid_t lp =
								auto_refresh_loader_pid.load(
									std::memory_order_acquire);
							if (lp > 0) {
								if (::kill(lp, 0) != 0 &&
								    errno == ESRCH) {
									SPDLOG_INFO(
										"Auto-refresh: loader pid {} is gone; stopping",
										(int)lp);
									return;
								}
							}
#endif
							std::this_thread::sleep_for(
								std::chrono::milliseconds(
									auto_refresh_ms));
							try {
								ctx_holder.ctx
									.init_attach_ctx_from_handlers(
										bpftime_get_runtime_config());
							} catch (const std::exception &ex) {
								SPDLOG_DEBUG(
									"Auto-refresh: init_attach_ctx_from_handlers failed: {}",
									ex.what());
							}
						}
					});
				std::atexit(stop_auto_refresh_at_exit);
			}

			if (!shm_holder.global_shared_memory
				     .add_pid_into_alive_agent_set(getpid())) {
				SPDLOG_ERROR("Unable to record alive agent pid");
				init_fail();
				return;
			}
			recorded_alive_pid = true;
			shm_lock.reset();
			try {
				SPDLOG_DEBUG("Registering signal handler");
			} catch (...) {
			}
			// We use SIGUSR1 to indicate the detaching.
			if (!ensure_detach_worker_started()) {
				init_fail();
				return;
			}
			// Start IPC control plane for repeat attach/refresh (used by
			// `bpftime trace`).
			start_agent_ipc_server_once();
			signal(SIGUSR1, sig_handler_sigusr1_detach);
			/* We don't want our library to be unloaded after we return. */
			*stay_resident = TRUE;
			setenv("BPFTIME_USED", "1", 0);
			__atomic_store_n(&initialized, AGENT_READY,
					 __ATOMIC_SEQ_CST);
			try {
				SPDLOG_DEBUG("Set environment variable BPFTIME_USED");
			} catch (...) {
			}
			try {
				chap_confirm_kernel_maps();
				chap_write_seal_targets();
				SPDLOG_INFO("Attach successfully");
			} catch (...) {
			}
		} catch (const std::exception &) {
			init_fail();
		} catch (...) {
			init_fail();
		}
}

// using definition for libbpf for syscall issues
// maybe should separate libbpf and kernel features separately
#if __linux__ && BPFTIME_BUILD_WITH_LIBBPF
extern "C" int64_t syscall_callback(int64_t sys_nr, int64_t arg1, int64_t arg2,
				    int64_t arg3, int64_t arg4, int64_t arg5,
				    int64_t arg6)
{
	try {
		auto impl = bpftime::attach::global_syscall_trace_attach_impl;
		if (impl.has_value() && impl.value() != nullptr) {
			return impl.value()->dispatch_syscall(
				sys_nr, arg1, arg2, arg3, arg4, arg5, arg6);
		}
	} catch (...) {
	}
	if (orig_hooker != nullptr)
		return orig_hooker(sys_nr, arg1, arg2, arg3, arg4, arg5, arg6);
	return -ENOSYS;
}

extern "C" void
_bpftime__setup_syscall_trace_callback(syscall_hooker_func_t *hooker)
{
	if (hooker == nullptr)
		return;
	orig_hooker = *hooker;
	*hooker = &syscall_callback;
	gboolean val = FALSE;
	try {
		bpftime_agent_main("", &val);
		SPDLOG_INFO("Agent syscall trace setup exiting..");
	} catch (...) {
	}
}
#endif

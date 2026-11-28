# Chaperon — Version Manifest

## Current release (use only these components)

| Item | Value |
|---|---|
| Release | Request Q: the Request J implementation plus the Sealed-Process NIC gate (Request P) and its security hardening (Request Q): dedicated tenant account with `NO_NEW_PRIVS`, minimal capabilities and an I/O-port seccomp filter, tenant network namespace, VF-level device restriction, multithreaded lifecycle. The commit on `main` that last changed this file (`git log -1 -- VERSION_MANIFEST.md`). |
| Previous release | `297d361` (organized sources of the Request J frozen commit `3f8bd75`; components in "Previous release" below). Kept in the history for reproducibility of results obtained with it. |
| Legacy prototype | eSAC, branch `legacy/esac` (commit `9546857`). Not for Chaperon builds or evaluations. |

### Components

Hashes are sha256 (first 8 hex digits) of the artifacts used for the functional verification of the release.
Paths are relative to the repository root; `$CHAP_RUNTIME_DIR` is set in `manager/chap_env.sh` (see
[docs/RUN.md](docs/RUN.md)).

| Component | Source | Artifact used by the launcher | sha256 |
|---|---|---|---|
| Agent runtime | `agent/` (bpftime `edcc8ec` + `agent/patches/` + `agent/src/`) | `$CHAP_RUNTIME_DIR/libbpftime-agent.so` | `1495de2b` |
| bpftime syscall-server (loader side) | same | `$CHAP_RUNTIME_DIR/libbpftime-syscall-server.so` | `077464c5` |
| Loader | `manager/chaperon_loader.c` | `manager/chaperon_loader` | `268151eb` |
| Admission gate | `manager/chap_admit.sh` | (script) | `b7f24b32` |
| Attach-point resolver | `manager/chap_res_offsets.py` | (script) | `de798c32` |
| Tenant launch helper (dedicated account, `CAP_NET_RAW`+`CAP_SYS_RAWIO`, `NO_NEW_PRIVS`, iopl/ioperm seccomp) | `manager/tools/amblaunch.c` | `manager/tools/amblaunch` | `b83b2643` |
| Tenant namespace wrapper (network namespace, `/proc/bus/pci` mask) | `manager/tools/tenant_ns_exec.sh` | (script) | `255bb691` |
| Launcher | `manager/run_3plane_F.sh` (+ verification blocks `manager/req*_block.sh`) | (scripts) | — |
| Communication Filter (L4 64 mask-probe + L7 + RX/TX windows) | `communication/hs_gate_excl.bpf.c` (+ `chap_lookup64.h`, `policy_table_opt.h`, `chap_pmask.h`, `include/`) | `communication/combo/c_filter_hs_gate_excl.bpf.o` | `4032064e` |
| Hyperscan provider | `communication/esac_hs_ufunc_enforce.chap.c` | `communication/esac_hs_fullscan_enforce.chap.so` | `8d042426` |
| Communication policy writer | `communication/chap_policy_flip.c` | `communication/chap_policy_flip` | `7edb72f7` |
| Resource Agent | `resource/agent/r_precheck_agent.bpf.c` | `resource/agent/r_precheck_agent.bpf.o` | `0cdd4b63` |
| FD broker | `resource/agent/fd_broker_multi.c` | `resource/agent/fd_broker_multi` | `49a48b33` |
| Resource Sentinel | `resource/kernel/resource_sentinel.bpf.c` | `resource/kernel/resource_sentinel.bpf.o` | `470da08a` |
| Resource Sentinel loader | `resource/kernel/rs_sentinel_reuse.c` | `resource/kernel/rs_sentinel_reuse` | `d1ea5b68` |
| Resource policy tool | `resource/manager/chap_res_policy.c` | `resource/manager/chap_res_policy` | `15ee81e2` |
| Tamper Sentinel + NIC gate (Sealed-Process registry, per-device rule) | `integrity/kernel/integrity_sentinel.bpf.c` | `integrity/kernel/integrity_sentinel.bpf.o` | `6b50e6f3` |
| Tamper Sentinel loader (static libbpf 1.7) / range tool | `integrity/kernel/integ_sentinel_run.c`, `integ_setranges.c` | `integrity/kernel/integ_sentinel_run`, `integ_setranges` | `81410bfc`, `46a538fc` |
| NIC-gate / Sealed-Process registry tool (Manager) | `integrity/kernel/chap_nicgate.c` | `integrity/kernel/chap_nicgate` | `63b6fe22` |
| Seal helper | `integrity/esac_seal.c` | `integrity/esac_seal.so` | `1068509c` |
| TEST-ONLY memory-API driver | `tests/reqJ/chap_memapi_test.c` | `tests/reqJ/chap_memapi_test.so` (preloaded only in `MEMJ=…` tests) | `41c315c2` |
| TEST-ONLY NIC-gate / lifecycle driver | `tests/reqP/chap_nicgate_test.c` | `tests/reqP/chap_nicgate_test.so` (preloaded only in `NICJ=…`/`NICQ=…` tests) | `df45d446` |
| TEST-ONLY RDMA probe | `tests/reqP/nicprobe.c` | `tests/reqP/nicprobe` | `d40f9a8d` |
| TEST-ONLY network-path probe (permission checks only) | `tests/reqQ/netpath_probe.c` | `tests/reqQ/netpath_probe` | `452788bf` |

Host requirement: a dedicated tenant account (`CHAP_TENANT_USER` in `manager/chap_env.sh`, no sudo rights, no
administrative group); see [docs/RUN.md](docs/RUN.md).

### Previous release `297d361` (Request J)

Same components as above except: Tamper Sentinel `8d42d82e` (no NIC gate), its loader `775aa3ea` (shared libbpf),
tenant launch helper `32a86a1f` (fixed uid 1003, `CAP_NET_RAW`+`CAP_NET_ADMIN`+`CAP_SYS_RAWIO`, no `NO_NEW_PRIVS`),
legacy exec block always on, no `chap_nicgate`, no tenant network namespace. Use it only to reproduce results that
were obtained with it.

### Reproducibility notes

- The userspace tools above (loader, broker, Sentinel loaders, policy tools, seal helper, `amblaunch`, `chap_nicgate`,
  test drivers) rebuild bit-identically from these sources with the commands in [docs/BUILD.md](docs/BUILD.md) on the
  reference toolchain (Ubuntu 22.04, gcc 11.4, libbpf.so.0, static libbpf 1.7 for `integ_sentinel_run`, libcap,
  Hyperscan 5.4).
- The BPF objects are built with `-g`; their debug information records the build directory, so a rebuild in another
  directory has a different file hash with identical program code.
- The Agent runtime embeds source file paths (logging macros), so a rebuild in another directory has a different hash.
  `agent/build_runtime.sh` reproduces the build procedure of the frozen runtime.

### Superseded components (never use)

| Component | Why |
|---|---|
| Tamper Sentinel `68cf5857`, `chap_nicgate` `35b4d8ef` (first NIC-gate build) | any uverbs device allowed to a sealed process, tenant device usable outside the tenant cgroup, status removed when the thread-group leader exits first |
| Resource Sentinel `e06ffe8c` (first Request J object) | false exemption path: a forged or hijacked outer call exempted memory-API calls without a token |
| Agent runtimes of earlier development stages, filters `e0cfcfe5` / `bf201aeb`, loaders other than `268151eb` | replaced by the components above |
| Any eSAC component (`legacy/esac`) | different architecture (no sealed dispatch, launch barrier, kernel-backed resource accounting) |
| `communication/combo/c_filter_hs_gate_excl_TESTFAILRX2.bpf.o` | test-only fail build (`FAIL_INJECT=rx_window_fail`) |

## External dependencies (reference host)

| Dependency | Version | Obtain |
|---|---|---|
| bpftime | upstream commit `edcc8ec`, submodule `vm/llvm-jit` at `8fc0cee`, plus `agent/patches/` | https://github.com/eunomia-bpf/bpftime |
| DPDK (tenant, `dpdk-testpmd`) | 22.11.0 | https://www.dpdk.org |
| DPDK (traffic generator `tests/gen/esac_l47gen`) | distribution DPDK, ABI 22 | distribution packages |
| Hyperscan | 5.4.0 | distribution package `libhyperscan-dev` |
| Linux kernel | 6.8 (eBPF, BTF, cgroup v2, fmod_ret on LSM hooks) | — |
| clang (BPF) / gcc | 14.0 / 11.4 | distribution |
| libbpf / libelf / libcap | libbpf.so.0 (headers 0.5); libbpf 1.x static (Tamper Sentinel object and loader); distribution libelf, libcap | distribution / bpftime build |
| rdma-core (`libibverbs`) | the one the tenant DPDK links (test programs only) | distribution or source |
| NIC | NVIDIA/Mellanox mlx5 (ConnectX), SR-IOV with switchdev | — |

## Release changes relative to the Request J frozen source commit

- Directory layout: Agent runtime sources under `agent/` (development tree: separate runtime source directory);
  headers previously taken from the eSAC tree are vendored (`communication/include/`, `manager/include/`); the
  test-bed fabric script and mbuf offsets (`manager/fabric/`), `manager/tools/amblaunch.c` and the traffic generator
  (`tests/gen/esac_l47gen.c`) are included.
- Paths: absolute host paths in scripts and three `#include` lines of the runtime sources were replaced by
  repository-relative paths and the host-local configuration `manager/chap_env.sh`.
- Request P/Q (functional changes): Sealed-Process registry and NIC gate in the Tamper Sentinel, `chap_nicgate`,
  launcher arming/registration steps, exec allowed by default (`BLOCK_EXEC=1` restores the exec block), dedicated
  tenant account and privilege restrictions in `amblaunch`, tenant network namespace (`tenant_ns_exec.sh`),
  per-device NIC rule, last-thread exit, `madvise` DONTFORK/WIPEONFORK on protected ranges as violations.
- No change to the Agent runtime, Communication Filter, Resource Agent, Resource Sentinel, policy/usage map formats,
  lookup order or optimizations.

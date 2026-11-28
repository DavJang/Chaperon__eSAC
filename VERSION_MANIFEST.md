# Chaperon — Version Manifest

## Current release (use only these components)

| Item | Value |
|---|---|
| Frozen source commit | `3f8bd75` in the development repository (Request J: kernel-side memory-API rate hard limit). The sources in this repository are taken from that commit; only directory layout, include/script paths and documentation differ (see "Release changes" below). |
| Repository organization commit | The commit on `main` that introduced this file (`git log --diff-filter=A -- VERSION_MANIFEST.md`). |
| Legacy prototype | eSAC, branch `legacy/esac` (commit `9546857`). Not for Chaperon builds or evaluations. |

### Components

Hashes are sha256 (first 8 hex digits) of the frozen artifacts used for the functional verification of the release.
Paths are relative to the repository root; `$CHAP_RUNTIME_DIR` is set in `manager/chap_env.sh` (see
[docs/RUN.md](docs/RUN.md)).

| Component | Source | Artifact used by the launcher | sha256 |
|---|---|---|---|
| Agent runtime | `agent/` (bpftime `edcc8ec` + `agent/patches/` + `agent/src/`) | `$CHAP_RUNTIME_DIR/libbpftime-agent.so` | `1495de2b` |
| bpftime syscall-server (loader side) | same | `$CHAP_RUNTIME_DIR/libbpftime-syscall-server.so` | `077464c5` |
| Loader | `manager/chaperon_loader.c` | `manager/chaperon_loader` | `268151eb` |
| Admission gate | `manager/chap_admit.sh` | (script) | `b7f24b32` |
| Attach-point resolver | `manager/chap_res_offsets.py` | (script) | `de798c32` |
| Tenant launch helper | `manager/tools/amblaunch.c` | `manager/tools/amblaunch` | `32a86a1f` |
| Communication Filter (L4 64 mask-probe + L7 + RX/TX windows) | `communication/hs_gate_excl.bpf.c` (+ `chap_lookup64.h`, `policy_table_opt.h`, `chap_pmask.h`, `include/`) | `communication/combo/c_filter_hs_gate_excl.bpf.o` | `4032064e` |
| Hyperscan provider | `communication/esac_hs_ufunc_enforce.chap.c` | `communication/esac_hs_fullscan_enforce.chap.so` | `8d042426` |
| Communication policy writer | `communication/chap_policy_flip.c` | `communication/chap_policy_flip` | `7edb72f7` |
| Resource Agent | `resource/agent/r_precheck_agent.bpf.c` | `resource/agent/r_precheck_agent.bpf.o` | `0cdd4b63` |
| FD broker | `resource/agent/fd_broker_multi.c` | `resource/agent/fd_broker_multi` | `49a48b33` |
| Resource Sentinel | `resource/kernel/resource_sentinel.bpf.c` | `resource/kernel/resource_sentinel.bpf.o` | `470da08a` |
| Resource Sentinel loader | `resource/kernel/rs_sentinel_reuse.c` | `resource/kernel/rs_sentinel_reuse` | `d1ea5b68` |
| Resource policy tool | `resource/manager/chap_res_policy.c` | `resource/manager/chap_res_policy` | `15ee81e2` |
| Tamper Sentinel | `integrity/kernel/integrity_sentinel.bpf.c` | `integrity/kernel/integrity_sentinel.bpf.o` | `8d42d82e` |
| Tamper Sentinel loader / range tool | `integrity/kernel/integ_sentinel_run.c`, `integ_setranges.c` | `integrity/kernel/integ_sentinel_run`, `integ_setranges` | `775aa3ea`, `46a538fc` |
| Seal helper | `integrity/esac_seal.c` | `integrity/esac_seal.so` | `1068509c` |
| TEST-ONLY memory-API driver | `tests/reqJ/chap_memapi_test.c` | `tests/reqJ/chap_memapi_test.so` (preloaded only in `MEMJ=…` tests) | `41c315c2` |

### Request P: Sealed-Process NIC gate (branch `feat/reqP-nic-seal-gate`, not on `main` until approved)

Changed or added artifacts; every other component above is unchanged and used as is.

| Component | Source | Artifact | sha256 |
|---|---|---|---|
| Tamper Sentinel + NIC gate (replaces `8d42d82e` on this branch) | `integrity/kernel/integrity_sentinel.bpf.c` | `integrity/kernel/integrity_sentinel.bpf.o` | `68cf5857` |
| Tamper Sentinel loader (replaces `775aa3ea`; static libbpf 1.7) | `integrity/kernel/integ_sentinel_run.c` | `integrity/kernel/integ_sentinel_run` | `81410bfc` |
| NIC-gate / Sealed-Process registry tool (Manager) | `integrity/kernel/chap_nicgate.c` | `integrity/kernel/chap_nicgate` | `35b4d8ef` |
| Launcher | `manager/run_3plane_F.sh` (+ `manager/reqP_nicgate_block.sh` for `NICJ=…`) | (scripts) | — |
| TEST-ONLY NIC driver | `tests/reqP/chap_nicgate_test.c` | `tests/reqP/chap_nicgate_test.so` (preloaded only in `NICJ=…` tests) | `0662676f` |
| TEST-ONLY RDMA probe | `tests/reqP/nicprobe.c` | `tests/reqP/nicprobe` | `6981178f` |

`integ_setranges` (`46a538fc`), the Agent runtime (`1495de2b`), the Resource Sentinel (`470da08a`) and all other
components are the frozen ones.

### Request Q: security hardening of Request P (branch `feat/reqQ-security-hardening`, not on `main` until approved)

Changed or added artifacts relative to the Request P table above; everything else is unchanged.

| Component | Source | Artifact | sha256 |
|---|---|---|---|
| Tamper Sentinel + NIC gate (per-device rule, last-thread exit) | `integrity/kernel/integrity_sentinel.bpf.c` | `integrity/kernel/integrity_sentinel.bpf.o` | `6b50e6f3` |
| Tamper Sentinel loader (unchanged since Request P) | `integrity/kernel/integ_sentinel_run.c` | `integrity/kernel/integ_sentinel_run` | `81410bfc` |
| NIC-gate / registry tool (selected device) | `integrity/kernel/chap_nicgate.c` | `integrity/kernel/chap_nicgate` | `63b6fe22` |
| Tenant launch helper (dedicated account, CAP_NET_RAW+CAP_SYS_RAWIO, NO_NEW_PRIVS, iopl/ioperm seccomp) | `manager/tools/amblaunch.c` | `manager/tools/amblaunch` | `b83b2643` |
| Tenant namespace wrapper (netns + /proc/bus/pci mask) | `manager/tools/tenant_ns_exec.sh` | (script) | `255bb691` |
| Launcher | `manager/run_3plane_F.sh` (+ `reqP_nicgate_block.sh`, `reqQ_nicgate_block.sh`) | (scripts) | — |
| TEST-ONLY tenant driver | `tests/reqP/chap_nicgate_test.c` | `tests/reqP/chap_nicgate_test.so` | `df45d446` |
| TEST-ONLY RDMA probe | `tests/reqP/nicprobe.c` | `tests/reqP/nicprobe` | `d40f9a8d` |
| TEST-ONLY network-path probe (permission checks only) | `tests/reqQ/netpath_probe.c` | `tests/reqQ/netpath_probe` | `452788bf` |

Host requirement: a dedicated tenant account (`CHAP_TENANT_USER` in `manager/chap_env.sh`, no sudo rights, no
administrative group); see [docs/RUN.md](docs/RUN.md).

### Reproducibility notes

- The userspace tools above (loader, broker, Sentinel loaders, policy tools, seal helper, `amblaunch`, test driver)
  rebuild bit-identically from these sources with the commands in [docs/BUILD.md](docs/BUILD.md) on the reference
  toolchain (Ubuntu 22.04, gcc 11.4, libbpf.so.0, libcap, Hyperscan 5.4).
- The BPF objects are built with `-g`; their debug information records the build directory, so a rebuild in another
  directory has a different file hash with identical program code.
- The Agent runtime embeds source file paths (logging macros), so a rebuild in another directory has a different hash.
  `agent/build_runtime.sh` reproduces the build procedure of the frozen runtime.

### Superseded components (never use)

| Component | Why |
|---|---|
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
| Linux kernel | 6.8 (eBPF, BTF, cgroup v2) | — |
| clang (BPF) / gcc | 14.0 / 11.4 | distribution |
| libbpf / libelf / libcap | libbpf.so.0 (headers 0.5), distribution libelf, libcap | distribution |
| NIC | NVIDIA/Mellanox mlx5 (ConnectX), SR-IOV with switchdev | — |

## Release changes relative to the frozen source commit

- Directory layout: Agent runtime sources under `agent/` (development tree: separate runtime source directory);
  headers previously taken from the eSAC tree are vendored (`communication/include/`, `manager/include/`); the
  test-bed fabric script and mbuf offsets (`manager/fabric/`), `manager/tools/amblaunch.c` and the traffic generator
  (`tests/gen/esac_l47gen.c`) are included.
- Paths: absolute host paths in scripts and three `#include` lines of the runtime sources were replaced by
  repository-relative paths and the host-local configuration `manager/chap_env.sh`.
- No change to program logic, symbols, BPF program or map names, attach targets, shared layouts, dispatcher
  semantics, policy/usage map formats, lookup order or optimizations.

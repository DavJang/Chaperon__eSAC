# Build

## Requirements

| Item | Reference host |
|---|---|
| OS / kernel | Ubuntu 22.04, Linux 6.8 with eBPF, BTF, uprobes, `bpf_send_signal`, cgroup v2 |
| Compilers | clang 14 (BPF objects), gcc 11.4 / g++ (userspace tools, runtime) |
| Libraries | libbpf (`libbpf.so.0`, headers 0.5), libelf, libcap, Hyperscan 5.4 (`libhs`); libbpf ≥ 1.x as a static library + headers (`$LIBBPF1`, reference: libbpf 1.7 from the bpftime build) for the Tamper Sentinel object and loader; rdma-core `libibverbs` (the one the tenant DPDK links) for the Request P test programs |
| DPDK | 22.11.0 with the mlx5 PMD for the tenant (`dpdk-testpmd` in `PATH`); a DPDK for the traffic generator |
| bpftime | upstream commit `edcc8ec` + `agent/patches/` (see [../agent/README.md](../agent/README.md)) |
| Verification tools | `bpftool`, `bpftrace`, `strace`, `python3` |
| NIC | NVIDIA/Mellanox mlx5 with SR-IOV; PF in switchdev mode (see [RUN.md](RUN.md)) |

## Components

Run each block from the repository root. The output paths are the ones the launcher uses.

```sh
# Agent runtime (bpftime-based); see agent/README.md for preparing BPFTIME_SRC / BPFTIME_BUILD
BPFTIME_SRC=/path/to/bpftime BPFTIME_BUILD=/path/to/bpftime/build OUT=/path/to/chaperon-runtime bash agent/build_runtime.sh

# Manager: loader and tenant launch helper
(cd manager && gcc -O2 -o chaperon_loader chaperon_loader.c -Iinclude -lbpf)
(cd manager/tools && gcc -O2 -o amblaunch amblaunch.c -lcap)    # tenant launcher (caps, NO_NEW_PRIVS, seccomp)

# Communication: Filter (L4/L7, 64 mask-probe, RX/TX windows), Hyperscan provider, policy writer
(cd communication && mkdir -p combo && clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I include -I /usr/include \
    -c hs_gate_excl.bpf.c -o combo/c_filter_hs_gate_excl.bpf.o)
(cd communication && gcc -shared -fPIC -O2 -Wl,-z,now -Wl,-z,relro -o esac_hs_fullscan_enforce.chap.so \
    esac_hs_ufunc_enforce.chap.c -lhs)
(cd communication && gcc -O2 -o chap_policy_flip chap_policy_flip.c)

# Resource: Agent pre-check program, FD broker, Sentinel, Sentinel loader, policy tool
(cd resource/agent && clang -O2 -g -target bpf -mcpu=v3 -D__TARGET_ARCH_x86_64 -I. -I../kernel \
    -I../../communication/include -c r_precheck_agent.bpf.c)
(cd resource/agent && gcc -O2 -o fd_broker_multi fd_broker_multi.c -lbpf)
(cd resource/kernel && clang -O2 -g -target bpf -mcpu=v3 -D__TARGET_ARCH_x86_64 -I. -c resource_sentinel.bpf.c)
(cd resource/kernel && gcc -O2 -o rs_sentinel_reuse rs_sentinel_reuse.c -lbpf -lelf)
(cd resource/manager && gcc -O2 -o chap_res_policy chap_res_policy.c -lbpf)

# Integrity: Tamper Sentinel (with the Sealed-Process NIC gate), its loader, range tool, NIC-gate tool, seal helper.
# The Sentinel uses fmod_ret / tp_btf programs and CO-RE: compile it with libbpf >= 1.x headers and link its loader
# statically against libbpf >= 1.x (libbpf 0.5 cannot parse the Linux 6.8 kernel BTF). LIBBPF1 = directory holding
# libbpf.a and the bpf/ header directory (reference host: the libbpf 1.7 built inside the bpftime build tree).
(cd integrity/kernel && clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I$LIBBPF1 -c integrity_sentinel.bpf.c)
(cd integrity/kernel && gcc -O2 -I$LIBBPF1 -o integ_sentinel_run integ_sentinel_run.c $LIBBPF1/libbpf.a -lelf -lz)
(cd integrity/kernel && gcc -O2 -o integ_setranges integ_setranges.c -lbpf)
(cd integrity/kernel && gcc -O2 -o chap_nicgate chap_nicgate.c -lbpf)
(cd integrity && gcc -shared -fPIC -O2 -Wl,-z,now -Wl,-z,relro -o esac_seal.so esac_seal.c)
```

Test components (used only by the verification modes and tests):

```sh
(cd integrity/kernel && gcc -O2 -o tamper_child tamper_child.c)                       # TAMPER=1
(cd tests/reqJ && gcc -shared -fPIC -O2 -Wall -o chap_memapi_test.so chap_memapi_test.c -ldl -lpthread)   # MEMJ=...
(cd communication && clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -DCHAP_TEST_FAIL_RX_WINDOW2 -I include -I /usr/include \
    -c hs_gate_excl.bpf.c -o combo/c_filter_hs_gate_excl_TESTFAILRX2.bpf.o)          # FAIL_INJECT=rx_window_fail only
(cd resource/kernel && gcc -O2 -o rs_concurrency_test rs_concurrency_test.c -lbpf -lelf -lpthread \
    && gcc -shared -fPIC -O2 -o libstub_flow.so stub_flow.c)
(cd tests/gen && gcc -O2 -o esac_l47gen esac_l47gen.c $(pkg-config --cflags --libs libdpdk))  # traffic generator
# Request P (NIC gate) tests; IBV = prefix of the rdma-core the tenant DPDK links (reference host: /usr/local)
(cd tests/reqP && gcc -O2 -I$IBV/include -o nicprobe nicprobe.c -L$IBV/lib -Wl,-rpath,$IBV/lib -libverbs)       # NICJ, reqP_unit.sh
(cd tests/reqP && gcc -O2 -fPIC -shared -I$IBV/include -o chap_nicgate_test.so chap_nicgate_test.c \
    -L$IBV/lib -Wl,-rpath,$IBV/lib -libverbs -lpthread)                                                    # NICJ=..., NICQ=...
(cd tests/reqQ && gcc -O2 -o netpath_probe netpath_probe.c)                                            # NICQ=all (permission checks only)
```

Unit tests: see [../tests/README.md](../tests/README.md).

## Verifying a build

Compare `sha256sum` of the artifacts with [../VERSION_MANIFEST.md](../VERSION_MANIFEST.md). The userspace tools
are bit-identical on the reference toolchain. BPF objects carry the build directory in their debug information, and
the runtime embeds source paths, so their hashes differ when built in another directory. Before any measurement,
record the hashes of the artifacts the launcher actually copied (the run directory holds the copies; the launcher
prints them in the `components_in_use` check).

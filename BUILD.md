# Building eSAC

eSAC was validated on Ubuntu with **DPDK 22.11 / 23 (Mellanox OFED build)**, clang/LLVM 14,
and libbpf. The prebuilt loaders and `.bpf.o` in this repo are linked for that rig; rebuild them
against your own DPDK/libbpf.

## 1. Prerequisites

| Need | For | Install / source |
|---|---|---|
| **DPDK** (22.11+) with your NIC's PMD | the tenant app + loaders' `--lib` | distro `dpdk-dev`, or Mellanox OFED, or build from dpdk.org |
| **libbpf** + headers, libelf, zlib | the loaders (`-lbpf -lelf -lz`) | `apt install libbpf-dev libelf-dev zlib1g-dev` |
| **clang/LLVM 14** | compiling the eBPF objects | `apt install clang-14 llvm-14` |
| **Hyperscan** (`-lhs`) | the L7 ufunc provider | `apt install libhyperscan-dev` |
| **bpftime** | the injected Agent runtime (the big `.so`, not in this repo) | build from source, below |
| **bpftrace** | the Tamper Sentinel | `apt install bpftrace` |

## 2. bpftime runtime (the excluded `.so`)

The Agent runtime files — `libbpftime-agent.so`, `libbpftime-agent-hs.so`,
`libbpftime-syscall-server.so`, `libbpftime-agent-transformer.so` — are the upstream
**bpftime** build (each ~100 MB, over GitHub's limit). Build them:

```sh
git clone --recursive https://github.com/eunomia-bpf/bpftime
cd bpftime && make build        # produces the agent + syscall-server shared objects
# copy/symlink the results into:
#   bpftime_Agent/Frida/libbpftime-agent.so
#   bpftime_Agent/Frida/libbpftime-agent-transformer.so
#   bpftime_Agent/ufunc/libbpftime-agent-hs.so   (Hyperscan-enabled agent build)
#   bpftime_Loader/libbpftime-syscall-server.so
```

## 3. Build the host loaders

```sh
# comm-plane loader (injects C_Filter; RX+TX)
gcc bpftime_Loader/src/c_loader.c            -o bpftime_Loader/c_loader        -lbpf -lelf -lz
# resource-plane loaders
gcc Resource_Bank/src/r_loader.c             -o Resource_Bank/r_loader         -lbpf -lelf -lz
gcc Resource_Bank/src/r_loader_rate.c        -o Resource_Bank/r_loader_rate    -lbpf -lelf -lz
```

The loader sources `#include` small headers shipped next to them (`bpftime_Loader/src/ebpf/…`,
`Resource_Bank/ebpf/common.h`), so the commands above build as-is from the repo root. The loaders
find the BPF `.rodata` map by trying the known object-prefixed names, so a `.bpf.o` rename does not
break policy injection (libbpf derives that map's name from the object/filename).

## 4. Build the eBPF filter objects

```sh
BPF="clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I bpftime_Agent/C_Filter"
# comm-plane (L4 mask-probe; + L7 gate variant)
$BPF -c bpftime_Agent/C_Filter/c_filter.bpf.c          -o bpftime_Agent/C_Filter/c_filter.bpf.o
$BPF -c bpftime_Agent/C_Filter/c_filter_hs_gate.bpf.c  -o bpftime_Agent/C_Filter/c_filter_hs_gate.bpf.o
# resource-plane (override + quota + rate + monitor)
$BPF -c bpftime_Agent/R_Filter/r_filter.bpf.c          -o bpftime_Agent/R_Filter/r_filter.bpf.o
$BPF -c bpftime_Agent/R_Filter/r_filter_quota.bpf.c    -o bpftime_Agent/R_Filter/r_filter_quota.bpf.o
$BPF -c bpftime_Agent/R_Filter/r_filter_rate.bpf.c     -o bpftime_Agent/R_Filter/r_filter_rate.bpf.o
```

The loaders resolve BPF **program/section names** (e.g. `rl_flow_create`, `q_rte_malloc`,
`cp_rate_ptr`, `mem_quota_ptr`) by name — do not rename those inside the sources.

## 5. Build the L7 ufunc provider

```sh
gcc -shared -fPIC -O2 bpftime_Agent/ufunc/src/esac_hs_ufunc.c \
    -o bpftime_Agent/ufunc/esac_hs_ufunc.so -lhs
```
The runtime entry symbol is `esac_hs_scan`, resolved by bpftime at run time via
`ufunc_find_func_id("esac_hs_scan")`.

## 6. Tamper Sentinel

No build needed — the canonical sentinel is the bpftrace script
`Tamper_Sentinel/tamper_sentinel_event.sh`. (The optional compiled C++ variants build from
`Tamper_Sentinel/src/tamper_sentinel.cpp`; they are large and excluded from this repo.)

## 7. `offsets.json`

`demos/offsets.json` holds the mbuf field offsets the loader reads (`buf_addr`, `data_off`,
`pkt_len`, `data_len`). These are DPDK-ABI-common; regenerate only if your DPDK changes the
`rte_mbuf` layout.

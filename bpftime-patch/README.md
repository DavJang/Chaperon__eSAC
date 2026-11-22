# eSAC bpftime patch

eSAC runs its security logic inside the upstream **bpftime** userspace-eBPF runtime
([`eunomia-bpf/bpftime`](https://github.com/eunomia-bpf/bpftime)). The runtime itself is **not
vendored** in this repository — the built `.so` files each exceed GitHub's file-size limit (see
[../BUILD.md](../BUILD.md)). This directory holds the small set of eSAC changes to the bpftime
**agent** as a reproducible patch, so the runtime can be rebuilt from upstream.

## Base commit

Upstream `eunomia-bpf/bpftime` commit **`edcc8ec`**, built with **LLVM 15** and the **Frida**
attach backend. The patch applies cleanly on a fresh `edcc8ec` checkout.

## What the patch changes (`esac-bpftime-edcc8ec.patch`)

| File | Change |
|---|---|
| `runtime/agent/agent.cpp` | Register the two ufuncs the L7 selective-DROP path needs: **`esac_hs_scan`** (the Hyperscan matcher) **pre-attach**, and **`rte_pktmbuf_free_bulk`** (mbuf bulk-free) **post-attach**, once the tenant's statically-linked symbol is globally resolvable. This lets the L7 gate (`../bpftime_Agent/C_Filter/c_filter_hs_gate.bpf.c`) free individual malicious mbufs instead of killing the tenant. |
| `attach/frida_uprobe_attach_impl/src/frida_internal_attach_entry.cpp` | Driver-level RX empty/short-burst handling for the burst hook. |
| `runtime/src/bpf_helper.cpp`, `runtime/src/bpf_map/userspace/per_cpu_hash_map.hpp` | Small runtime fixes the eSAC agent relies on. |
| `attach/frida_uprobe_attach_impl/test/test_uprobe_uretprobe.cpp` | Corresponding test. |

## Apply and build

```sh
git clone --recursive https://github.com/eunomia-bpf/bpftime && cd bpftime
git checkout edcc8ec
git apply /path/to/eSAC/bpftime-patch/esac-bpftime-edcc8ec.patch

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=/usr/lib/llvm-15/lib/cmake/llvm \
  -DBPFTIME_ENABLE_FRIDA=ON -DBPFTIME_BUILD_WITH_LIBBPF=ON
make -C build bpftime-agent bpftime-syscall-server -j

# install the resulting agent + syscall-server .so as described in ../BUILD.md §2
```

> The original build tree that produced the validated runtime was lost; this patch is a
> reconstruction, verified to match the deployed agent's ufunc-registration behavior (`esac_hs_scan`
> + `rte_pktmbuf_free_bulk`, same argument encoding) and validated live on the rig.

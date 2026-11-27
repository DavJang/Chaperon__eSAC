# Attribution and Upstream Components

Chaperon is built on third-party open-source components. This file records what is upstream (not authored by
Chaperon), the version used on the reference host, and where to obtain it.

> The project-wide license for Chaperon's own code is not decided in this file. Do not infer a license from file
> names. Each upstream project's own `LICENSE`/`NOTICE` must be preserved when redistributing its files or binaries.

## Upstream components

| Component | Role in Chaperon | Version (reference host) | Source |
|---|---|---|---|
| bpftime (`eunomia-bpf/bpftime`) | userspace eBPF runtime: Agent and syscall-server libraries, LLVM JIT, maps, Frida-based attach | commit `edcc8ec` (+ `agent/patches/`) | https://github.com/eunomia-bpf/bpftime |
| Frida-Gum | bpftime's inline-hook backend (PMD burst hooks, resource API hooks) | as fetched by the bpftime build | https://github.com/frida/frida-gum |
| Hyperscan | L7 multi-pattern matching in the Hyperscan provider | 5.4.0 | https://github.com/intel/hyperscan |
| DPDK | target dataplane (unmodified tenant application, `dpdk-testpmd`) | 22.11.0 | https://www.dpdk.org |
| libbpf | BPF object loading in the Manager-side tools | distribution | https://github.com/libbpf/libbpf |

Licenses must be confirmed against each upstream release before redistribution.

## Files derived from upstream bpftime

`agent/src/agent.cpp`, `array_map_kernel_user.cpp`, `ufunc.cpp`, `bpf_helper.cpp`, `bpftime_shm.cpp`,
`bpf_attach_ctx.cpp` and `agent/src/include_override/bpftime_prog.hpp` are modified copies of bpftime source files;
`agent/patches/` contains changes to the bpftime tree itself. They remain subject to bpftime's license.

## Chaperon-authored code

- `manager/` — admission gate, loader, protected launch, verification blocks
- `communication/` — Communication Filter (L4/L7), policy table and writer, Hyperscan provider
- `resource/` — Resource Agent, Resource Sentinel, policy/usage layout, policy tool, FD broker
- `integrity/` — Tamper Sentinel and seal helper
- `agent/src/include_override/chap_dispatch_reg.hpp` and the Chaperon changes in the derived files above
- `tests/` — functional, regression and unit tests

Some files keep `esac` in their names from the earlier eSAC prototype; the names are kept unchanged.

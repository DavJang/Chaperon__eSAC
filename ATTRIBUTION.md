# Attribution & Upstream Components

eSAC is built on third-party open-source components. This file records what is **upstream** (not
authored by eSAC), the version observed on the build/validation host, and its license.

> **The project-wide license for eSAC's own code is intentionally left undecided here.** Do not
> infer a license from file names. The repository owner must choose and add a top-level `LICENSE`
> before publishing, and must preserve each upstream project's own `LICENSE`/`NOTICE` when
> redistributing any of its files or binaries.

## Upstream components (NOT authored by eSAC)

| Component | Role in eSAC | Version (observed) | License | Source |
|---|---|---|---|---|
| **bpftime** (`eunomia-bpf/bpftime`) | injected userspace eBPF runtime: Agent + syscall-server `.so`, LLVM-JIT, shared-memory maps | ⚠️ verify — no git checkout found on the build host | ⚠️ verify at upstream | https://github.com/eunomia-bpf/bpftime |
| **Frida / Frida-Gum** | bpftime's uprobe / inline-hook backend (installs the PMD RX/TX burst hooks) | 16.1.2 (prior audit — verify) | ⚠️ verify at upstream | https://github.com/frida/frida |
| **Hyperscan** | L7 multi-pattern matching engine used by `H_matcher` | 5.4.0 (`libhyperscan-dev`, Debian) | ⚠️ verify at upstream | https://github.com/intel/hyperscan |
| **DPDK** | target dataplane (eSAC runs inside unmodified DPDK apps) | 24.11 (rig) | ⚠️ verify at upstream | https://www.dpdk.org |
| **libbpf** | ELF/BPF loading in the host loaders | distro | ⚠️ verify at upstream | https://github.com/libbpf/libbpf |

Every license above is marked ⚠️ **verify** on purpose: it must be confirmed against the actual
upstream release used, from that project's own repository, before distribution. The values are not
asserted here.

## eSAC-authored code (this repository's contribution)

Security logic layered on top of bpftime — these are eSAC's own implementation:

- `bpftime_Agent/R_Filter/` — resource-plane eBPF (override + rate throttle)
- `bpftime_Agent/C_Filter/` — communication-plane eBPF (L4 5-tuple + L7 gate)
- `bpftime_Agent/H_matcher/` — L7 Hyperscan matcher (DNS-aware QNAME matching ufunc provider)
- `bpftime_Loader/` — host loaders (`c_loader*`, `r_loader*`) + injection
- `Policy_Maps/`, `Resource_Bank/`, `Tamper_Sentinel/` — policy, admission, integrity
- `demos/`, `benchmarks/` — demonstration and measurement scripts

Each `bpftime_Agent` module carries its own `README.md` describing its boundary with upstream
bpftime.

## bpftime relationship

eSAC **uses bpftime as a dependency; it is not a fork**. The large runtime `.so` files
(`libbpftime-agent*.so`, `libbpftime-syscall-server.so`) are produced from upstream bpftime's own
source (see `BUILD.md`) and are **not** redistributed in this repository. Frida-Gum is bpftime's
hooking backend and is likewise upstream.

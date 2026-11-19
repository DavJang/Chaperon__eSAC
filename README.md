# eSAC

**eSAC** (eBPF-enforced Security Access Control for multi-tenant DPDK) is an **in-process**
security layer for DPDK tenants. From inside an *unmodified* DPDK application — and with **no
kernel transition on the packet hot path** — it enforces three planes, organized here as
**five components**.

```
eSAC/
├── Resource_Bank/     host: resource admission gate (quota screen, pre-exec)
├── bpftime_Loader/    host: ALL host loaders (c_loader + r_loader/r_loader_rate) + syscall-server; inject Agent + load BPF
├── Policy_Maps/       host: per-tenant RO policy (L4 + resource), generated + loaded into shm
├── Tamper_Sentinel/   host: root bpftrace, 2-vector (mprotect, openat /proc/self/mem) -> SIGKILL
└── bpftime_Agent/     tenant (injected): Frida + R_Filter + C_Filter + ufunc
    ├── Frida/         installs PMD RX/TX burst hooks + rte_* uprobes
    ├── R_Filter/      resource-plane BPF: override (NULL/-EAGAIN) + rate throttle
    ├── C_Filter/      comm-plane L4 mask-probe hash + L7 gate (LLVM-JIT)
    └── ufunc/         L7 Hyperscan provider + its RO pattern/payload DBs
```

Convention: **host loaders live under `bpftime_Loader`** (comm `c_loader*` + resource `r_loader*`);
the **BPF program each injects lives under the Agent submodule that runs it** (`R_Filter`, `C_Filter`);
admission/policy stays with its plane (`Resource_Bank/esac_admit.sh`).

## The three planes

- **Communication control** — per-tenant **L4** (5-tuple, mask-probe hash, `cgroup_id`-keyed)
  and **L7** (DNS/redis verb, Hyperscan) policy on the driver PMD RX/TX burst. Actions **ALLOW / DROP**.
  Runs in userspace via **bpftime** (Frida hooks + LLVM-JIT), so DPDK's poll-mode loop never
  traps into the kernel.
- **Resource control (all-block)** — per-tenant quotas on EAL/resource APIs, enforced by
  *blocking* not killing: the host **screens the request at admission** (over-quota ⇒ never
  started), **overrides** an over-quota runtime call to a failure value (`NULL`/`-EAGAIN`), and
  **token-bucket throttles** the shared NIC-control / hugepage APIs a tenant can *churn*
  (`rte_flow_create/destroy`, `rte_malloc`/`rte_free`, …). Termination is only a backstop.
- **Integrity** — the Frida-patched PMD prologue, the JIT pages, and the whole policy table are
  mapped **read-only** in the tenant; a root-owned **Tamper Sentinel** SIGKILLs the tenant on the
  only two syscalls that can restore write access: `mprotect(PROT_WRITE)` and `openat(/proc/self/mem)`.

Enforcement is installed while the tenant is held **stopped** before its EAL/PMD begins polling,
then released (the **STOP/CONT start-gate**) — fail-closed: no packet flows until every hook and
integrity mechanism is in place.

## Resources eSAC guards (SR-IOV blind spots)

| Tenant attacks | via | mode | defense |
|---|---|---|---|
| Host **hugepage** memory | `rte_malloc`/`rte_zmalloc`/`rte_memzone_reserve` | hold | override → NULL |
| Host **hugepage allocator** | `rte_malloc`/`rte_free` | rate (churn) | throttle (token-bucket) |
| NIC **flow-table** entries | `rte_flow_create` | hold | override → NULL |
| NIC **firmware / steering** | `rte_flow_*` | rate (churn) | throttle (token-bucket) |
| Host **lcore / mempool** | `rte_eal_init` / `rte_eal_remote_launch` / `rte_mempool_create` | launch | admission (refuse exec) |

per-VF resources (RX/TX queues, the VF's own port) are already isolated by SR-IOV and are **not**
eSAC's concern — it guards only the **PF-shared NIC** and **host** resources SR-IOV cannot isolate.

## Getting started

- **[BUILD.md](BUILD.md)** — prerequisites (DPDK, bpftime, Hyperscan, libbpf) and how to build
  each component. The large third-party **bpftime** runtime `.so` files are **not** in this repo
  (they exceed GitHub's file-size limit); BUILD.md shows how to produce them.
- **[RUN.md](RUN.md)** — runnable demos. Two run on **any Linux host** (Tamper-Sentinel KILL,
  resource admission DENY); the datapath DROP / throttle demos need a DPDK-capable NIC
  (validated on Mellanox ConnectX-6 Dx, mlx5 switchdev VF-to-VF).

## What is prebuilt here vs. built by you

Shipped prebuilt (small, but linked for the validation rig's DPDK — rebuild for your own):
`c_loader`, `c_loader_rx` (RX-only datapath loader), `c_loader_tx`, `r_loader`, `r_loader_rate`, the `*.bpf.o` eBPF objects,
`ufunc/esac_hs_ufunc.so`, and the L7 Hyperscan-DB builders `ufunc/hsdb_ctl/{esac_hs_ctl_rx, esac_dom_ctl_bulk}`. **Not shipped** (build per BUILD.md): the bpftime runtime
(`libbpftime-agent*.so`, `libbpftime-syscall-server.so`) and the optional compiled
Tamper-Sentinel C++ binaries (the canonical sentinel is the bpftrace script
`Tamper_Sentinel/tamper_sentinel_event.sh`, which needs no build).

## Attaching to stripped stock DPDK apps (auto debug-symbol discovery)

`c_loader`'s driver-level RX/TX hooks resolve the PMD burst symbols (e.g. `mlx5_rx_burst*`)
by file offset. When the target app links a **stripped** DPDK (as distro packages do), those
symbols are absent from the loaded `.so`. If a matching separate debug file is installed
(`/usr/lib/debug/.build-id/XX/YYY.debug`, e.g. from a distro `-dbg`/`dbgsym` package),
`c_loader` now **auto-discovers it via the .so's GNU build-id**, resolves the offsets from the
debug file, and attaches the uprobe to the real loaded `.so`. No manual `--pmd-debug-lib` is
needed (pass it only to override); when the symbols are already visible (non-stripped build),
discovery is skipped.

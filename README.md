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
└── bpftime_Agent/     tenant (injected): Frida + R_Filter + C_Filter + H_matcher
    ├── Frida/         installs PMD RX/TX burst hooks + rte_* uprobes
    ├── R_Filter/      resource-plane BPF: override (NULL/-EAGAIN) + rate throttle
    ├── C_Filter/      comm-plane L4 mask-probe hash + L7 gate (LLVM-JIT)
    └── H_matcher/     L7 Hyperscan matcher (uses bpftime ufunc provider) + its RO pattern/payload DBs
```

Convention: **host loaders live under `bpftime_Loader`** (comm `c_loader*` + resource `r_loader*`);
the **BPF program each injects lives under the Agent submodule that runs it** (`R_Filter`, `C_Filter`);
admission/policy stays with its plane (`Resource_Bank/esac_admit.sh`).

## The three planes

### 1 · Communication control — *who a tenant may talk to*

**Guards.** Per-tenant network policy on the DPDK datapath: which **5-tuples (L4)** and which
**application-layer requests** (**L7** — DNS qname, redis verb) a tenant's traffic may carry.
Actions: **ALLOW / DROP**.

**Where it runs.** On the driver PMD's RX/TX **burst** function, *inside* the tenant process via
**bpftime** — Frida installs the hook, the policy BPF runs on bpftime's LLVM-JIT. Executing in
userspace next to DPDK's poll-mode loop, **the packet hot path never traps into the kernel** (no
per-packet syscall or context switch).

**How.**
- **L4 (`C_Filter`).** A 5-tuple policy keyed by `cgroup_id` (per-tenant), resolved with a
  **mask-probe hash** whose cost is **independent of the policy count** — 2 rules or 16,384 rules
  scan at the same rate, so a large table does not slow the datapath.
- **L7 (`C_Filter` gate + `H_matcher`).** For inspectable payloads (DNS / TLS ClientHello /
  HTTP / redis) the gate content-prescans the burst and hands candidate payloads to
  **`H_matcher`**, which runs **Hyperscan once per burst (batched)** over the *real* payload bytes.
  Cost is **byte-bound**, not ruleset-bound: a realistic ~17 K-pattern DB inspects every packet at
  a small, bounded overhead.

**Validated** (mlx5 ConnectX-6 Dx, intra VF-to-VF and host-to-host 40 GbE): with a 17,000-pattern
Hyperscan DB fully scanning every payload, eSAC sustains **≈ 89–96 % of the no-inspection
baseline** (the residual cost is masked by link rate at large payloads), while a conventional IPS
on the same traffic runs **1–2 orders of magnitude slower per core** — one eSAC core ≈ ~20 IPS
cores.

### 2 · Resource control (all-block) — *what a tenant may consume*

**Guards.** The **PF-shared NIC and host resources SR-IOV does *not* isolate**. SR-IOV partitions
each VF's queues and port, but **not** the hugepage pool, the host allocator, or the NIC's shared
eSwitch flow-table / firmware steering. One tenant can starve its neighbours two ways:
- **hold** — grab all of a shared resource (e.g. exhaust the hugepage pool), or
- **churn** — hammer a control API fast enough that the shared datapath never settles (e.g.
  create/destroy flow rules so the eSwitch is perpetually rebuilding → a co-tenant's datapath
  goes to zero).

**How — block, don't kill** (termination is only a backstop):
- **Admission** (`Resource_Bank/esac_admit.sh`) — before EAL starts, the host screens the
  requested lcores / mempools / memory against the tenant's quota; over-quota ⇒ the process is
  **never exec'd**.
- **Runtime override** (`R_Filter`) — an over-quota call that passes admission is **rewritten to a
  failure value** at the API boundary: `rte_malloc`/`rte_zmalloc`/`rte_memzone_reserve` and
  `rte_flow_create` → **`NULL`**, others → **`-EAGAIN`**; the allocation fails for the offender only.
- **Churn throttle** (`R_Filter`, token-bucket) — the *rate* of calls to the shared
  NIC-control / hugepage-allocator APIs (`rte_flow_create/destroy`, `rte_malloc`/`rte_free`, …) is
  token-bucketed. This is the defense against the subtle attack above: not *holding* a resource,
  but re-churning it to keep the shared subsystem permanently rebuilding.

The **blind-spot table** below maps each attack → API → mode → defense.

### 3 · Integrity — *keeping the enforcement un-removable*

**Guards.** The enforcement itself. L4/L7 and resource control only mean something if the tenant
cannot **peel them off from inside its own process** — it owns its address space and could try to
rewrite the Frida-patched PMD prologue, the JIT'd policy code, or the policy table.

**How.**
- **Read-only mapping** (`Policy_Maps` + loader / `H_matcher` hardening) — the patched burst
  prologue, the bpftime JIT pages, and the **entire** per-tenant policy table (empty slots and the
  Hyperscan DB included) are `mprotect`'d **read-only** after install; a direct write faults.
- **Tamper Sentinel** (root `bpftrace`, 2-vector) — the only two syscalls that can *restore* write
  access to a read-only mapping are `mprotect(PROT_WRITE)` and `openat("/proc/self/mem")`; a
  **root-owned** sentinel watches exactly these and **`SIGKILL`s** the tenant on attempt. It runs
  as root, off the tenant's path, so the tenant cannot disable it.
- **Cross-process tampering also fails** — `process_vm_writev` honors the RO protection
  (`EFAULT`), `/dev/mem` is root-only under `STRICT_DEVMEM`, and `ptrace` is gated by
  `yama ptrace_scope=1` (a process may attach only to its own descendants; the host-launched
  tenant is not the attacker's). Verified on the rig, including a **non-root** attacker.
- **Fail-closed start-gate (STOP/CONT)** — all hooks and all three integrity mechanisms are
  installed **while the tenant is held stopped**, before its EAL/PMD begins polling, and only then
  is it released. No packet flows until every hook and RO mapping is in place — there is no window
  in which the tenant runs un-enforced.

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
`H_matcher/esac_hs_ufunc.so`, and the L7 Hyperscan-DB builders `H_matcher/hsdb_ctl/{esac_hs_ctl_rx, esac_dom_ctl_bulk}`. **Not shipped** (build per BUILD.md): the bpftime runtime
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

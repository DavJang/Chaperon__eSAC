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

### Upstream bpftime vs. eSAC code

eSAC is **built on, not a fork of, bpftime** (`eunomia-bpf/bpftime`). The large injected runtime —
`bpftime_Agent/Frida/libbpftime-agent*.so` and `bpftime_Loader/libbpftime-syscall-server.so` — is
**upstream bpftime**, built from its own source (not in this repo; see BUILD.md) and used as a
dependency; **Frida-Gum** is bpftime's uprobe backend, also upstream. The **eSAC-authored** code is
the security logic layered on top: the `R_Filter` / `C_Filter` eBPF programs, the `H_matcher` L7
matcher, the host `c_loader*` / `r_loader*` loaders, and `Policy_Maps` / `Resource_Bank` /
`Tamper_Sentinel`. Each eSAC Agent module carries its own `README.md`; upstream components,
versions and licenses are listed in **[ATTRIBUTION.md](ATTRIBUTION.md)**.

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
  **`H_matcher`**. For **DNS**, `H_matcher` **parses the query name (QNAME) out of the wire
  format**, lowercases it, and matches the **parsed domain** — **case-insensitively and anchored to
  label boundaries** (`(^|\.)domain$`, i.e. the domain and its subdomains, not an arbitrary
  substring) — against the pattern DB with **Hyperscan (batched, once per burst)**. This is the
  same detection semantics as a DNS IDS. Malformed or compressed DNS falls back to a raw-payload
  scan (see limitations). Cost is **byte-bound**, not ruleset-bound: a realistic ~17 K-pattern DB
  inspects every packet at a small, bounded overhead.

**Validated** (mlx5 ConnectX-6 Dx, intra VF-to-VF and host-to-host 40 GbE). Two things are kept
distinct — *detection correctness* and *throughput*:

- **Detection correctness — DNS-aware v2 (current code):** verified by unit test against the
  17,197-pattern DB: case-insensitive match, label-boundary (domain + subdomain) matching, no
  substring false-positives, bounds-checked QNAME parse. See **DNS inspection — scope &
  limitations** below.
- **Throughput:** with the DB inspecting every packet, eSAC sustains a large fraction of the
  no-inspection baseline. **Re-measured with v2** (DNS-aware) on the inter-host payload sweep:
  **≈ 83–101 % of baseline**. ⚠️ The **intra / cc / ka / lcore sweeps and the Suricata comparison
  were measured with the *previous raw-payload-scan* provider** (historically ≈ 89–96 % of
  baseline, and **≈ 7.5× a DPDK-IPS/Suricata baseline at 4 matched worker cores**, 9–17× at one
  core); these are **pending re-measurement against v2** and must not be cited as v2 numbers.

> We report only measured, matched-core ratios; we do **not** extrapolate a fixed
> "N IPS cores = 1 eSAC core" — the IPS scales sub-linearly (0.39 → 0.73 → 1.11 Mpps at 1/2/4
> cores), so any single-number core-equivalence projection is unsound.

#### L7 DNS inspection — scope & limitations

`H_matcher`'s DNS path (v2) parses and normalizes the QNAME before matching:
- **Case:** case-insensitive (`HS_FLAG_CASELESS`) — `EXAMPLE.COM` ≡ `example.com`.
- **Label boundaries:** anchored `(^|\.)domain$` — matches the domain and its subdomains
  (`evil.ru`, `a.b.evil.ru`), never an unrelated substring (`xevil.ru.com` does **not** match).
- **Parse:** QNAME read with bounds checks (`dns_sane` / `dns_clean` / `dns_qname`); trailing bytes
  after the question (EDNS / padding) are allowed; only the first question's QNAME is parsed.
- **Limitations (explicit):**
  - **DNS name compression is not decompressed.** A QNAME containing a `0xC0` compression pointer
    is treated as not-clean and the packet **falls back to a raw-payload Hyperscan scan**. This
    fallback is **not** equivalent to proper DNS decompression — a blocked domain whose labels are
    split across a compression pointer can be missed. (Query QNAMEs are normally uncompressed; this
    affects only crafted/unusual packets.)
  - Non-DNS or malformed payloads also take the raw-scan fallback.

#### L7 enforcement — selective per-packet DROP (ALLOW detection vs DROP paths)

eSAC's L7 runs in **two distinct provider paths**; keep them separate when reading results:

| Path | Provider (`.so`) | Patterns | What it does |
|---|---|---|---|
| **Detection / ALLOW throughput** | `esac_hs_ufunc.so` (raw / full DNS-aware scan) | **17,197** (`hs_compile_multi`, no cap) | returns a match count; inspects every packet; the ALLOW-throughput + Suricata benchmarks use this path |
| **Selective per-packet DROP (enforcement)** | `esac_suricata_dns_ufunc.so` | **≤ 256** (`ESAC_HS_MAXPAT`, shm `pat_action[256]`) | sets a per-packet action; the gate drops only matching (malicious) packets |

- **Selective DROP mechanism.** Per burst, the gate inspects each packet, **compacts the benign
  (ALLOW) mbufs to the front and frees only the malicious ones** via `rte_pktmbuf_free_bulk`,
  returning the kept count. Benign traffic is forwarded; the tenant keeps running (no kill).
- **bpftime agent dependency.** Selective DROP needs the injected bpftime **agent** to register two
  ufuncs: `esac_hs_scan` (the matcher, registered **pre-attach**) and `rte_pktmbuf_free_bulk` (mbuf
  free, registered **post-attach**, once the tenant symbol is globally resolvable). These live in
  the bpftime source, not this repo — see `~/old/bpftime` branch `esac-l7-free-bulk` (reconstruction
  commit; the original build tree was lost). `c_filter_hs_gate.bpf.c` here depends on that agent.
- **Rule-count limit.** The DROP path is capped at **256** patterns by the shared-memory action
  table; the **17,197**-pattern figure is the **detection / raw-scan** path and does **not** apply
  to selective DROP.
- **Burst cap (availability).** The gate inspects at most **128 packets per RX burst** (static
  `item[128]`/`dropped_ptrs[128]` arrays + a manually-unrolled loop; bpftime has no `bpf_loop`).
  When the driver returns a burst **larger than 128**, the un-inspected tail is **safe-dropped**
  (freed, never forwarded) and the tenant survives — it is **not** killed. An earlier version
  hard-`ACT_KILL`ed oversized bursts, which ended ~50 % of multicore reps under saturating load;
  the safe-drop is the current behavior. **Fail-closed invariant:** an un-inspectable packet is
  never forwarded, and if `free_bulk` is unavailable the gate falls back to the original
  drop-all + kill fail-close.
- **Verified / unresolved (selective DROP).** 1/2/4-core: benign ALLOW + malicious-only DROP +
  memory safety (no double-free / UAF / mbuf leak), un-inspected-forwarded = 0 — all verified.
  The oversized-burst **safe-drop** replaces the kill (availability fix): **offline-verified**
  (compiles; minimal straight-line change, no new loops); **live NIC re-validation pending**.

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

## What is built vs. committed

This repository commits **source, build scripts, and config only** — compiled artifacts are **not**
tracked in git (they are rebuilt with [BUILD.md](BUILD.md)). This covers the loaders
(`c_loader`, `c_loader_rx`, `r_loader`, `r_loader_rate`), the `*.bpf.o` eBPF objects, the L7
`H_matcher/esac_hs_ufunc.so` + `esac_suricata_dns_ufunc.so`, and the Hyperscan-DB builders
`H_matcher/hsdb_ctl/{esac_hs_ctl_rx, esac_dom_ctl_bulk}`. The large third-party bpftime runtime
(`libbpftime-agent*.so`, `libbpftime-syscall-server.so`) and the optional compiled Tamper-Sentinel
C++ binaries are likewise not committed (the canonical sentinel is the bpftrace script
`Tamper_Sentinel/tamper_sentinel_event.sh`, which needs no build).

> Two binaries are **still tracked** because their source is not yet in the repo and no rebuild
> recipe exists: `bpftime_Loader/c_loader_tx` (an egress-TX loader applied as a binary patch) and
> `bpftime_Agent/R_Filter/r_filter_monitor.bpf.o`. These are flagged to be sourced or dropped
> before a clean source-only release.

## Attaching to stripped stock DPDK apps (auto debug-symbol discovery)

`c_loader`'s driver-level RX/TX hooks resolve the PMD burst symbols (e.g. `mlx5_rx_burst*`)
by file offset. When the target app links a **stripped** DPDK (as distro packages do), those
symbols are absent from the loaded `.so`. If a matching separate debug file is installed
(`/usr/lib/debug/.build-id/XX/YYY.debug`, e.g. from a distro `-dbg`/`dbgsym` package),
`c_loader` now **auto-discovers it via the .so's GNU build-id**, resolves the offsets from the
debug file, and attaches the uprobe to the real loaded `.so`. No manual `--pmd-debug-lib` is
needed (pass it only to override); when the symbols are already visible (non-stripped build),
discovery is skipped.

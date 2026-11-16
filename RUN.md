# Running eSAC demos

Each demo names what it proves and what hardware it needs. Two run on **any Linux host**;
the datapath demos need a **DPDK-capable NIC** (validated on Mellanox ConnectX-6 Dx, mlx5
switchdev VF-to-VF — adapt the device/addresses for your NIC).

Run everything from the repo root. Root is required (bpftrace, uprobe attach, hugepages, VFIO).

---

## Demo 1 — Integrity: Tamper-Sentinel KILL  *(any Linux host, needs `bpftrace`)*

Proves the root sentinel SIGKILLs a tenant the instant it tries to regain write access to the
RO policy / JIT pages, via either of the two in-scope syscalls.

```sh
sudo bash demos/demo_tamper.sh
```

Expected: the selftest tenant that calls `mprotect(PROT_WRITE)` is **KILLED**; the one that
calls `openat(/proc/self/mem)` is **KILLED**; a benign tenant **survives** (negative control).
`ptrace` / `process_vm_writev` are out of the 2-vector self-tamper model and survive by design.

---

## Demo 2 — Resource: admission DENY  *(any Linux host)*

Proves the launcher refuses to `exec` a tenant whose EAL resource request exceeds its quota —
the attacker's repeated over-size launches are blocked **before** any kernel/NIC resource is touched.

```sh
bash demos/demo_admission.sh
```

Expected: a request of `-m 9999 -l 0,1,2,3,4` against quota `{socket_mem 128, lcores 2}` prints
`[ADMIT] DENY (no exec)` and never starts; a within-quota request prints `[ADMIT] OK` and execs.

---

## Demo 3 — Communication: L4 DROP  *(mlx5 NIC + dpdk-testpmd)*

Proves `c_loader` + `c_filter.bpf.o` drop a matching 5-tuple on the PMD RX burst **before the
tenant app sees it**. Deterministic: a `dpdk-testpmd` tenant on the server VF receives UDP from a
`txonly` generator on the client VF; an ALLOW policy passes all, a DROP policy drops all.

```sh
sudo PF1=0000:3b:00.1 IF1=enp59s0f1np1 bash demos/l4_drop.sh
```

It brings up the fabric itself (`demos/setup_mlx5_fabric.sh` — edit `PF1`/`IF1` for your NIC,
`SCORES`/`GCORES` for your NUMA), attaches the loader with the STOP/CONT start-gate and a pinned
bpftime shm, then generates traffic. Verified on the rig (ConnectX-6 Dx):

```
[allow] action=ALLOW attach=YES ACT_DROP_events=0  total_dropped=0
[drop]  action=DROP  attach=YES ACT_DROP_events=20 total_dropped=... 
[comm] ACT_DROP sample: dir=RX tuple=198.18.x.11:9 -> 198.18.0.2:9 proto=17 burst=32 dropped=32
VERDICT: PASS -- L4 DROP enforced
```

`dropped=32` of a 32-packet burst = every matching packet dropped at RX before the tenant. (The
NIC's own RX counter sits *before* the hook, so it keeps counting — that is expected; the
enforcement signal is the loader's `ACT_DROP … dropped=N`.)

---

## Demo 4 — Communication: L7 DROP  *(DPDK NIC)*

Proves the Hyperscan ufunc drops by **payload content** at the same 5-tuple that L4 allows
(e.g. redis `SET` dropped, `GET` allowed). Same attach pattern as Demo 3 but with
`--bpf bpftime_Agent/C_Filter/c_filter_hs_gate.bpf.o` and the ufunc provider
`bpftime_Agent/ufunc/esac_hs_ufunc.so` preloaded; the policy carries a Hyperscan pattern
(e.g. `SET:drop`). The L7 match runs in the agent via `ufunc_find_func_id("esac_hs_scan")`.

---

## Demo 5 — Resource: override & throttle  *(DPDK NIC)*

Proves an over-quota runtime `rte_malloc`/`rte_flow_create` is forced to `NULL` (override), and
that high-rate churn is rate-limited (throttle). Both use `r_loader_rate`, which attaches the
BPF programs to exported DPDK symbols as `BPF_MODIFY_RETURN` (so `bpf_override_return()` fires):

```sh
# config: one hook per line  <lib_path> <offset_hex> <prog_name>   (offset from: nm -D <lib>)
printf '%s %s q_rte_malloc\n'  "$EAL" "$(nm -D "$EAL"|awk '/ rte_malloc@/{print $1;exit}')"  > cfg
sudo env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD=bpftime_Loader/libbpftime-syscall-server.so \
  Resource_Bank/r_loader_rate bpftime_Agent/R_Filter/r_filter_quota.bpf.o <tenant-pid> cfg
# throttle instead: use r_filter_rate.bpf.o with prog cp_rate_ptr / cp_rate_int.
```

The churn tenant holds a live DPDK port (the control APIs need one), launched like the comm-plane
tenant (Agent preloaded, pinned shm, STOP/CONT). Verified on the rig: with a 1 MiB per-call
ceiling, a quota-tightened build forced the tenant's EAL-init `rte_malloc` to `NULL`, so the
tenant failed closed —

```
[gov] q_rte_malloc  -> librte_eal.so.23@0x27b30  (attached, BPF_MODIFY_RETURN)
tenant: EAL: error allocating rte services array / rte_service_init() failed
```

— i.e. the over-ceiling allocation returned `NULL`. A within-ceiling allocation returns normally
(`malloc=OK`), so legitimate tenants are unaffected. (`r_loader_rate` prints `ready: 0/N` due to a
counter that expects attach rc==0 while bpftime returns a positive fd; the hooks are attached.)

---

## Status of validation

All four enforcement types verified end-to-end on the mlx5 rig (ConnectX-6 Dx, switchdev VF-to-VF):
Tamper KILL (5/5 vectors), admission DENY, L4 DROP (`ACT_DROP dir=RX dropped=32/32`), and resource
override (over-ceiling `rte_malloc` → `NULL`). Demos 1–2 run on any Linux host; Demos 3–5 depend
on your NIC, DPDK build, hugepages, and core/NUMA layout — set `PF1`/`IF1`/`SCORES`/`GCORES`.

Note: a file rename once broke enforcement because libbpf derives the auto `.rodata` map name from
the `.bpf.o` **filename** (`<objname[0:8]>.rodata`); the loaders now resolve it by trying the known
names, so renaming a `.bpf.o` no longer breaks the policy injection.

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

## Demo 3 — Communication: L4 DROP  *(DPDK NIC; mlx5 switchdev here)*

Proves `c_loader` + `c_filter.bpf.o` drop a matching 5-tuple on the PMD RX burst **before the
tenant app sees it**. The enforcement signal is the loader's `ACT_DROP … dropped=N` accounting
(the NIC's own RX counter sits *before* the hook, so it keeps counting — that is expected).

Pattern (STOP/CONT start-gate, pinned bpftime shm — the sequence that attaches cleanly):

```sh
SHM=esac_$(date +%s%N)
# 1. tenant, stopped before exec, Agent preloaded, pinned shm, scalar RX so the vector path
#    doesn't bypass the hook:
sudo setsid bash -c "echo \$\$>/tmp/tpid; kill -STOP \$\$; exec \
  env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD=bpftime_Agent/Frida/libbpftime-agent.so \
  <tenant-app> -a <SVF>,rx_vec_en=0 -- --forward-mode=rxonly" &
PID=$(cat /tmp/tpid)
# 2. scope it in a cgroup and key the policy on that cgroup_id (DROP dst 198.18.0.2:9/udp):
#    { "rules":[{"layer":"L2","cgroup_id":<CGID>,"dst_ip":"198.18.0.2","proto":17,
#                "dst_port":9,"action":"DROP"}] }
# 3. attach the loader (same pinned shm), wait for "attach summary: RX=OK TX=OK", then CONT:
sudo env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD=bpftime_Loader/libbpftime-syscall-server.so \
  bpftime_Loader/c_loader --max-burst-inspect 128 --bpf bpftime_Agent/C_Filter/c_filter.bpf.o \
  --lib <tenant-app> --pmd-lib <tenant-app> --offsets demos/offsets.json \
  --policy /tmp/pol.json --no-pin --enforcement --attach-pid $PID -v
sudo kill -CONT $PID
# 4. blast matching traffic from a second VF toward dst 198.18.0.2:9 → loader logs ACT_DROP.
```

Expected: an ALLOW policy → no drops; a DROP policy → `ACT_DROP dir=… dropped=…` in the loader
log. Validated on this rig with both a `dpdk-testpmd` tenant and an f-stack Redis tenant;
adapt the device BDF, cores/NUMA, and tenant app to your own NIC.

---

## Demo 4 — Communication: L7 DROP  *(DPDK NIC)*

Proves the Hyperscan ufunc drops by **payload content** at the same 5-tuple that L4 allows
(e.g. redis `SET` dropped, `GET` allowed). Same attach pattern as Demo 3 but with
`--bpf bpftime_Agent/C_Filter/c_filter_hs_gate.bpf.o` and the ufunc provider
`bpftime_Agent/ufunc/esac_hs_ufunc.so` preloaded; the policy carries a Hyperscan pattern
(e.g. `SET:drop`). The L7 match runs in the agent via `ufunc_find_func_id("esac_hs_scan")`.

---

## Demo 5 — Resource: override & throttle  *(DPDK NIC)*

Proves an over-quota runtime `rte_malloc` / `rte_flow_create` is forced to `NULL` (override), and
that high-rate churn is rate-limited (throttle), via `r_loader` + `r_filter*.bpf.o`.

```sh
# override / kill-backstop:
sudo Resource_Bank/r_loader --bpf bpftime_Agent/R_Filter/r_filter_quota.bpf.o \
  --lib <librte_eal.so> --policy demos/quota.json --attach-pid <tenant-pid> -v      # -v = block
#   add --json to escalate a persistent violator to SIGKILL (backstop).
# throttle (token-bucket rate-limit on churn):
sudo Resource_Bank/r_loader_rate bpftime_Agent/R_Filter/r_filter_rate.bpf.o <tenant-pid> <config>
```

The churn tenant must hold a live DPDK port (the control APIs need one), so this demo needs the
NIC bound to DPDK. Expected: churn output flips `malloc=OK`→`malloc=NULL` (override) or
`ALLOW×N → DENY` (throttle).

---

## Status of validation

Verified end-to-end on the mlx5 rig: Tamper KILL, admission DENY, `c_loader` RX/TX attach +
`ACT_DROP`, `r_loader` uprobe attach + override. The datapath demos depend on your NIC, DPDK
build, hugepages, and core/NUMA layout — treat the commands above as a template to adapt.

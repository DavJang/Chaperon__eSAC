# Performance evaluation setup

Performance numbers for Chaperon must come from the components listed in
[../VERSION_MANIFEST.md](../VERSION_MANIFEST.md), launched by `manager/run_3plane_F.sh`. Builds of the earlier eSAC
prototype dispatch hooks through Frida listeners and have no launch barrier, immutable view, burst exclusion or
kernel-backed resource accounting, so they do not measure Chaperon.

No performance results are published in this repository yet.

## 1. Harness

| Aspect | Chaperon harness |
|---|---|
| Tenant preloads | `LD_PRELOAD=<agent runtime>:<esac_seal.so>:<hsprov.so>`, copied by the launcher into a root-owned 0755 run directory |
| Loader | `chaperon_loader --max-burst-inspect 128 --enforcement --frag-drop --malformed-drop --nonip-drop --bpf c_filter_hs_gate_excl.bpf.o …` with the syscall-server preloaded; Resource Agent object and Table API attach points (`chap_res_offsets.py`) passed by the launcher |
| Policy state | kernel maps `comm_policy` (16384 hash slots + 1 active-combination header), `resource_usage`, `resource_policy`; the tenant gets read-only mappings through `fd_broker_multi` |
| Sentinels | Resource Sentinel (`rs_sentinel_reuse`, internal attach points + `rs_gate_enter/exit` on the Agent library + `sched_process_exit`); Tamper Sentinel (`integ_sentinel_run`); tenant cgroup `cpuset.cpus` = admitted lcores, `hugetlb.2MB.{max,rsvd.max}` = hugepage quota |
| Launch | gated (`CHAP_GATED_LAUNCH=1 CHAP_IMM_VIEW=1 CHAP_SEALED_DISPATCH=1`), admission by `chap_admit.sh` |
| L7 | `CHAP_L7_REQUIRED=1`, `ESAC_HS_PATTERNS=<rules>`, `ESAC_MATCH_ACT=2` |

Simplest correct path: reuse `run_3plane_F.sh` up to "tenant application initialized after GO" and replace the
functional phases with the workload, as `manager/reqI_perf1_block.sh` (`PERF1=1`) does; keep the launch order and
the refusal logic.

Baseline (no Chaperon): the same `dpdk-testpmd` command line (lcores, VF, devargs, `--in-memory`, mbuf count) as
the tenant, without the preloads, loader and Sentinels.

## 2. Disable for performance runs (verification-only)

| Item | Where | Setting |
|---|---|---|
| `LD_DEBUG=files` (launch-order evidence) | tenant environment in the launcher | remove |
| `strace` (`comm_zero_bpf_syscall`), `bpftrace` (`RX_TEST`, `run_3plane_F_hl.sh`) | launcher | do not attach |
| spdlog INFO | `SPDLOG_LEVEL` | `warn` |
| Hyperscan provider statistics | `ESAC_HS_STATS` | unset |
| test-only tamper triggers | `CHAP_TEST_ATK` | 0 |
| test modes `RESAPI`, `RESP`, `WILD`, `UNCLASS_TEST`, `RESLAUNCH`, `RES_OMIT`, `RES_PASS`, `MEMJ`, `RXSLOT_PROBE`, `PERF1` | launcher | off (`PERF1` is the one-sample template) |
| loader `-v` event printing | loader | own pinned core, or drop `-v` |

## 3. Packet-path behaviour

- **L4 lookup**: one hash probe per active wildcard combination (up to 64), lowest first, until the first match. The
  active-combination mask is read once per burst from the policy map header. Keep the active combinations of the
  evaluated policy fixed and report them (the loader prints `64-probe active-combo mask=…`). An exact-only policy
  probes once per packet.
- **L7**: Hyperscan is called once per window of up to 32 packets that contains candidates (DNS/TLS/HTTP/RESP shapes,
  plus every payload when `--l7-allowlist` is set). Without allow-listed services the UDP RX path is unchanged.
- **Windows of 32**: both directions inspect in verdict windows of 32 packets; bursts of any size are fully
  inspected; compaction (RX) and partitioning (TX) happen in the sealed dispatcher; no syscall on either path.
- **Unclassifiable packets** (non-IPv4, fragments, malformed) are dropped by default; a workload with ARP/IPv6 on the
  tenant VF needs `UNCLASS_ALLOW=1`.
- **cgroup cpuset**: the tenant cgroup is restricted to the admitted lcores; EAL control threads share the main
  lcore. Pin the generator and the loader outside this set.
- **Resource Sentinel on the packet path**: none for mempool mbuf get/put. A memory API call crosses into the kernel at
  the admitted-call boundary (2 uprobes) and in the allocator (`malloc_heap_alloc` entry/return, `rte_free`), so a
  workload must not allocate heap memory per packet.
- **Memory-API rate**: one token per request (per outermost memory API call, and per call of another resource API at
  its first allocation); nested calls are free within a bound. `dpdk-testpmd` takes about 500 tokens at start-up
  (about 480 from `rte_eth_dev_callback_register(RTE_ETH_ALL, …)`), so a memory-rate policy needs a burst of at least
  about 500 for it; or leave the memory rate unset for packet-path runs.
- **RX burst variant**: the mlx5 PMD calls `mlx5_rx_burst_vec` with `rx_vec_en=1` and `mlx5_rx_burst` with
  `rx_vec_en=0` (launcher devarg `rx_vec_en=${RXVEC:-0}`); both are functionally verified. For another application or
  PMD configuration, run `RXSLOT_PROBE=1` before measuring.
- **`DISPATCH_ATK`** is not a perf or regression test (the broad test-only overwrite stalls the tenant).

## 4. Optimizations in the evaluated build

- Policy table: kernel ARRAY, read-only mmap, open addressing, word-wise hash with avalanche finalizer, per-slot
  seqlock, in-place compare; fail-closed (an unreadable header means no probe and DROP).
- Probe skipping by a Manager-maintained 64-bit active-combination mask in the policy map.
- PERCPU scratch maps, one-shot mbuf-pointer prefetch, content-gated Hyperscan batch ufunc, RX compaction / TX
  exclusion in the sealed dispatcher, `probe_read_user` fast path.

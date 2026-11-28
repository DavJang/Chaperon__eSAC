# Running Chaperon

The reference launcher is `manager/run_3plane_F.sh`. It is run as root on a trusted host and launches one
non-root DPDK tenant (`dpdk-testpmd` on an mlx5 VF) under the Manager, Agent and Sentinel, then runs the selected
checks. Every run uses a new directory `/var/tmp/chap_3pu_<RUN_ID>/` (artifact copies, logs, `run/CHECKS.tsv`) and
never overwrites another run.

## Host setup

- mlx5 PF with SR-IOV in switchdev mode, two VFs and a tc hairpin between them: `manager/fabric/setup_mlx5_fabric.sh`
  (idempotent; set `PF1`/`IF1` for your NIC; called by the launcher). The tenant uses the server VF, the
  generator/peer the client VF.
- Hugepages, `/sys/fs/bpf` mounted, cgroup v2, root via `sudo -n`.
- Tenant account: a dedicated system account without sudo rights and without administrative groups, e.g.
  `useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --user-group chaptenant`, named
  in `manager/chap_env.sh` (`CHAP_TENANT_USER`). The launcher refuses to start otherwise (`tenant_account`).
  `manager/tools/amblaunch` drops to it with `CAP_NET_RAW` + `CAP_SYS_RAWIO` as ambient capabilities (needed by the mlx5
  PMD), `PR_SET_NO_NEW_PRIVS` and a seccomp filter that fails `iopl`/`ioperm`; the launcher reads these attributes
  back from `/proc` at the barrier (`tenant_privileges`).
- Tenant network namespace (default, `TNETNS=1`): the launcher creates a namespace holding only `lo` and the tenant VF
  netdev (kept DOWN) and starts the tenant through `manager/tools/tenant_ns_exec.sh`, which also masks `/proc/bus/pci`
  in the tenant mount namespace (`tenant_netns`). The PF, the representors and the host interfaces are not visible to
  the tenant.
- Build all components ([BUILD.md](BUILD.md)) and create `manager/chap_env.sh` from `manager/chap_env.example.sh`
  (`CHAP_RUNTIME_DIR`, `CHAP_DPDK_RUNDIR`, `CHAP_DPDK_LIBDIR`, `CHAP_TENANT_USER`). `sudo` drops the caller's
  environment; the launcher reads these values from the file.
- The launcher contains fixed offsets for the reference `dpdk-testpmd` build (`FC_OFF`, `CC_OFF`, `DC_OFF`);
  the Table API attach points are resolved by symbol (`manager/chap_res_offsets.py`). Another testpmd build needs
  new fixed offsets.

## Launch

```sh
cd manager
sudo -n rm -f /sys/fs/bpf/chap/*        # pinned maps of a previous run
sudo -n bash run_3plane_F.sh            # default: gated launch + communication/resource/integrity checks
```

Launch order (all fail-closed; a failed step refuses the launch): admission (`chap_admit.sh`), fabric, root-owned run
directory with artifact copies, library trust check, tenant started stopped, cgroup, Communication Filter and
Resource Agent loaded into kernel-backed maps (`chaperon_loader`), FD broker, Resource Sentinel
(`rs_sentinel_reuse`), resource policy (`chap_res_policy`), Tamper Sentinel (`integ_sentinel_run`), NIC gate armed
(`chap_nicgate cfg`), seal and range registration, Sealed-Process registration (`chap_nicgate seal`, after every
protection check), GO token, then the tenant initializes. The filter drops every packet until the Manager arms the
policy.

## Sealed-Process NIC gate

The Tamper Sentinel object also holds the NIC gate. For processes of the protected tenant cgroup it attaches to the
kernel functions through which the mlx5 PMD acquires and controls the NIC, i.e. the RDMA uverbs command interface:
`security_file_open` (uverbs character devices, matched by device number), `security_file_ioctl` /
`security_file_ioctl_compat`, `security_mmap_file` and `security_file_permission` (write) on files whose
`file_operations` are `uverbs_fops` / `uverbs_mmap_fops` (fmod_ret programs: the call fails with `-EPERM` before the
uverbs handler runs). A process without a valid Sealed-Process entry is denied and SIGKILLed. The decision also
depends on the device of the uverbs file (Request Q): only the operator-selected RDMA device of the tenant may be
used, and only by sealed tenant processes; a tenant process (sealed or not) touching another uverbs device is denied
and SIGKILLed; the tenant device used by a process outside the tenant cgroup (e.g. through a passed fd) is denied.

- Registry `sealed_procs` (pinned in the root-only bpffs directory): key tgid, identity tgid + start time (clock
  ticks, `/proc/<pid>/stat` field 22). Only the Manager writes it (`chap_nicgate seal`), as the last step before GO.
- `fork`/`clone` of a new process (not a thread) of a sealed process: the child is registered (`origin=2`). A thread
  uses the entry of its thread group.
- Successful `exec`: the entry is removed (a new program starts without the Agent). A failed exec keeps it.
- Exit of the last thread of the process removes the entry (a leader that exits first leaves it while other threads
  live); an entry whose start time differs from the current process (reused PID) is deleted and the access denied.
- `madvise(MADV_DONTFORK|MADV_WIPEONFORK)` on a protected range is a Tamper Sentinel violation, so a sealed child
  always inherits the sealed regions.
- `chap_nicgate cfg <pindir> on <ibdev>` takes the uverbs `file_operations` addresses from `/proc/kallsyms`, every
  uverbs device present at that time, and the selected RDMA device of the tenant VF (required); the launcher refuses
  if not all 8 gate programs attached or the configuration fails.
- `chap_nicgate dump <pindir>` prints the entries and the allow/deny counters.

## Modes (environment variables)

| Variable | Effect |
|---|---|
| (none) | default functional run: pre-arm drop, arm ALLOW, live DROP/ALLOW flips, resource pre-check and hard limit, Tamper Sentinel attached |
| `HARD=N` | flow hard limit for the resource checks (default 3) |
| `RESAPI=1 RESP=1 WILD=1 UNCLASS_TEST=1` | Table API resource matrix, RESP allow-list rule, wildcard combinations, unclassifiable packets |
| `RX_TEST=1` / `TX_TEST=1` | RX burst compaction / TX burst exclusion judges (`RXVEC=0|1` selects the mlx5 RX variant) |
| `RXSLOT_PROBE=1` | which RX burst function the PMD uses (dispatcher slot counts) |
| `TAMPER=1 TAMPER_TARGET=agentcode` | destructive integrity check (tamper attempt must be killed) |
| `PROGFN_ATK=1` | sealed dispatch table tamper test |
| `MEMJ=agent` / `MEMJ=kill RES_PASS=1` / `MEMJ=race RES_PASS=1` / `MEMJ=forge RES_PASS=1` | memory-API rate tests (TEST-ONLY driver preloaded) |
| `PERF1=1` | one RX throughput sample template (see [PERF_EVAL_SETUP.md](PERF_EVAL_SETUP.md)) |
| `UNCLASS_ALLOW=1` | pass unclassifiable packets (default: drop) |
| `BLOCK_EXEC=1` | legacy exec block: any `execve` in the tenant cgroup is killed (default `0`: exec allowed, the new program is unsealed and the NIC gate stops its NIC access) |
| `NICJ=all` | Request P checks with the TEST-ONLY driver `tests/reqP/chap_nicgate_test.so`: sealed allow (launch, thread, fork child + protected regions), failed exec, exec of normal programs, exec of an unsealed `dpdk-testpmd`, inherited / SCM_RIGHTS uverbs fds, same-cgroup unregistered process, forged registration, PID reuse, worker syscalls during traffic, entry removed at exit (with `BLOCK_EXEC=1` the exec cases are replaced by the legacy-block check) |
| `NICJ=madv NICJ_MADV=10\|18` | destructive: the sealed tenant calls `madvise(MADV_DONTFORK\|MADV_WIPEONFORK)` on a protected range and must be killed |
| `NICQ=all` | Request Q checks: no privilege gain (fork child, `sudo`, file-capability `ping`), NIC paths outside uverbs from the sealed process and from exec'd images with a peer-VF observer (AF_PACKET, UDP, raw IP, netdev/tc/RDMA control, `iopl`/`ioperm`, `/proc/bus/pci`), derived event fds, another VF's RDMA device, a tenant fd used outside the cgroup, vfork, CLONE_VM, non-leader exec, leader exit first, EACCES exec, compat ioctl, concurrency + PID reuse; INFO: direct verbs transmission by sealed tenant code |
| `TNETNS=0` | TEST-ONLY: no tenant network namespace (the kernel-stack paths of the VF netdev are then open) |
| `tests/reqP/reqP_unit.sh` | kernel-level gate test on the real RDMA device without DPDK (own test cgroup and Sentinel instance) |
| `run_3plane_F_hl.sh HARD=3` | NIC command-submission boundary probe (generated by `make_F_hl.py`) |

## Policies

- Communication (L4) policy: `communication/chap_policy_flip <map id> 16384 <cgroup id> <src ip> <dst ip> <sport>
  <dport> <proto> <action|99=reset>` writes one rule into the kernel policy table (seqlock + writer lock) and adds its
  wildcard combination to the active-combination header (0 = wildcard field). Action `0` ALLOW, `2` DROP; `99`
  clears the table.
- L7 rules: the launcher writes `hs_rules.txt` in the run directory (`ESAC_HS_PATTERNS`); one regex per line = deny;
  `allow tcp/<port> <regex>` makes that service allow-listed (loader flag `--l7-allowlist`, added automatically).
- Resource policy: `resource/manager/chap_res_policy <pinned resource_policy> <slot> key=value …` with keys
  `lcores`, `max_lcores`, `max_hp_mb`, `max_mem_bytes`/`max_mem_mb`, `max_mbufs`, `max_rxq`, `max_txq`,
  `hard_flows`, `flow_rate`, `flow_burst`, and `<api>.rate` / `<api>.burst` / `<api>.budget` for
  `flow_destroy`, `flow_flush`, `dev_start`, `dev_stop`, `promisc_en`, `promisc_dis`, `mc_addr`, `mem`.
  The launcher passes extra keys from `RESPOL_EXTRA` (e.g. `RESPOL_EXTRA="mem.rate=50 mem.burst=600"`).

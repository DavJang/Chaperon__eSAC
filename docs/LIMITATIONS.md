# Limitations and verification coverage

Chaperon is a research prototype. This file lists what the implementation does not do and which paths were not
exercised by the functional verification.

## Scope of the implementation

- **Platform**: the packet-path hooks target the mlx5 PMD burst functions; other PMDs are not supported. The
  reference tenant is `dpdk-testpmd` (DPDK 22.11); the launcher contains fixed offsets for that build.
- **L7**: payload rules apply to individual packets; no TCP stream reassembly, no multi-packet requests, no
  decryption. Payload candidates are recognized by shape (DNS, TLS, HTTP, Redis RESP) unless a service is
  allow-listed.
- **Unclassifiable packets** (non-IPv4, fragments, malformed) are dropped by default.
- **Drop reporting**: per-direction counters, not individual drop events.

## Resource control

- Memory-API rate: one token per request. Calls nested in a resource API call are free up to a per-API budget (about
  4× the nested calls observed with `dpdk-testpmd`), also when tenant code runs inside that call (callbacks, signal
  handlers, a direct call of the boundary function). The memory-API call rate of a tenant is therefore bounded by
  (1 + budget) × the policy rate, not by the policy rate alone.
- Nesting is tracked per thread: a memory call of another thread while an outer call is open is charged as an
  outermost call.
- A resource API call of another class (e.g. `rte_eth_dev_start`) pays one memory token at its first allocation; with
  no token left, the Agent fails that allocation gracefully (the call returns an error) and, without the Agent,
  the Sentinel terminates the tenant.
- Memory-rate policies must admit the application's start-up burst (about 500 calls for `dpdk-testpmd`).
- The Agent identifies nested calls by kernel thread id; inside a PID namespace the ids differ and the Agent always
  applies its rate check (the kernel limit is unaffected).
- Memory API calls cross into the kernel (uprobes at the boundary and in the allocator); per-packet heap allocation
  changes the kernel-crossing profile.

## NIC access gate (Sealed Process)

- Gated paths: the RDMA uverbs command interface of the mlx5 PMD — `open` of the uverbs character devices present when
  the gate is armed (matched by device number), and `ioctl`, compat `ioctl`, `mmap` and `write` on any file with the
  uverbs `file_operations` (also an fd opened before joining the cgroup, inherited across `exec`, or received over
  `SCM_RIGHTS`). Only the operator-selected device of the tenant is usable (by sealed tenant processes); other uverbs
  devices are denied to every tenant process; the tenant device is denied to processes outside the tenant cgroup
  (deny only, no kill). A uverbs device added after arming is not in the `open` list; `ioctl`/`mmap`/`write` on it are
  still gated (same `file_operations`, device not selected).
- **Unresolved: direct NIC programming by code inside a sealed process.** The Agent enforces at the PMD burst functions;
  application code in the same (sealed) process can create its own queue on the tenant VF through verbs (or write to
  the PMD's queues) and transmit without passing the Agent. Verified on the reference host: 20 raw frames sent by the
  sealed tenant through a raw packet QP reached the peer VF (`NICQ=all`, `nicq_sealed_direct_verbs`). The kernel gate
  cannot separate PMD code from application code of the same process; closing this needs a design change (not done).
- Kernel network stack and other paths (Request Q): the tenant has no `CAP_NET_ADMIN` (netlink, socket ioctls, ethtool,
  tc and RDMA-netlink changes fail with `EPERM`) and runs in a network namespace holding only `lo` and its VF netdev,
  kept DOWN; `AF_PACKET`, raw and UDP sends cannot reach the NIC (verified with a peer-VF observer) and RoCE on the VF is
  DOWN. `iopl`/`ioperm` fail (seccomp) and `/proc/bus/pci` is masked. Event fds derived from a uverbs context have no
  command interface (`ioctl` `ENOTTY`, `mmap` `ENODEV`).
- `CAP_SYS_RAWIO` stays (the mlx5 PMD loses ~60x TX throughput without it). Its port-I/O and `/proc/bus/pci` uses are
  removed as above; its remaining uses are governed by root-only file permissions (`/dev/mem`, `/dev/port`, MSR
  devices, PCI `resource*` files) or are not hardware access. That no other `CAP_SYS_RAWIO` path reaches the NIC was not
  proven exhaustively. `devlink` writes were not exercised (they require `CAP_NET_ADMIN`, which the tenant lacks).
- Without `CAP_NET_ADMIN` the mlx5 PMD cannot change netdev-level settings (MTU, promiscuous flag through netlink,
  link up/down, VF MAC through the PF); the tested start-up, RX/TX, `rte_flow` and port restart do not need them.
- `security_file_permission` runs for every `read`/`write` system call on the host; the gate program returns at once for
  other files. This cost is outside the tenant packet path (the forwarding lcore makes no system calls) and was not
  measured.
- A program executed in the tenant cgroup stays in that cgroup: the cgroup limits, the Resource Sentinel's cgroup-slot
  accounting (calls through its attach points in the same binary are charged to the tenant) and the Tamper Sentinel's
  cgroup-wide rules (sealed address ranges of the tenant, `/proc/<pid>/mem`, `ptrace`) apply to it. A `munmap`,
  `mprotect(PROT_WRITE)`, `MAP_FIXED` or `madvise` of the new program that overlaps one of those addresses kills it
  (not observed; address randomization makes an overlap unlikely).
- Registration reads the start time from `/proc/<pid>/stat` and re-reads it after the map write (the entry is removed if
  the process changed); the kernel compares it with the task's start time in clock ticks on every gated call.

## Not exercised by the functional verification

- NIC gate: the uverbs `write` command path inside a DPDK tenant (tested with the kernel-level test only); a genuine
  32-bit tenant binary (compat `ioctl` tested through `int $0x80` from a 64-bit process); applications other than
  `dpdk-testpmd` and dperf.

- MPRQ RX burst variants (hooked, not selected in the tested configuration).
- `rte_mempool_create` denial, Sentinel termination on queue setup, release on `rte_mempool_free`, release of a failed
  heap allocation (`dpdk-testpmd` does not exercise these paths).
- Concurrency of Sentinel attach points other than the memory-rate boundary and flow creation (same atomic helpers).
- NIC command-submission boundary for APIs other than `rte_flow_create`.
- Multi-core scaling of the packet path.
- Applications other than `dpdk-testpmd` for the resource and integrity planes.

## Observed outside Chaperon

- After a gracefully denied heap allocation during start-up, `dpdk-testpmd`'s event callback dereferences a NULL
  array during `rte_exit`.
- After a denied Tx-queue allocation, the mlx5 PMD cannot restart the port.

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
  `SCM_RIGHTS`). A uverbs device added after arming is not in the `open` list; `ioctl`/`mmap`/`write` on it are still
  gated (same `file_operations`).
- Not gated, not claimed: control of the VF netdev through the kernel network stack (netlink, socket ioctls, ethtool,
  tc) with the tenant's `CAP_NET_ADMIN`; `AF_PACKET`/raw sockets with `CAP_NET_RAW` on the VF netdev; RDMA netlink;
  event file descriptors derived from a uverbs context (async event / completion channel: other `file_operations`,
  they deliver events and do not submit commands); NIC access paths of other drivers (VFIO, PCI resource files —
  root-only device files, not used by the mlx5 PMD). Only the mlx5/uverbs path is implemented.
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

- NIC gate: compat (32-bit) `ioctl`, `exec` from a non-leader thread, `vfork`/`clone(CLONE_VM)` children, the uverbs
  `write` command path inside a DPDK tenant (tested with the kernel-level test only), applications other than
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

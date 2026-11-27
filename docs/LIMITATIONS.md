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

## Not exercised by the functional verification

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

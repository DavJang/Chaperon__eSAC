# R_Filter — Resource Filtering (eSAC-authored)

Resource-plane eBPF programs that enforce a tenant's **resource quota** on DPDK's
resource-allocation and NIC-control APIs, from inside the tenant process via bpftime.

- **Role.** Stop a co-tenant from abusing the **PF-shared resources SR-IOV does not isolate**
  (hugepage pool, host allocator, NIC eSwitch flow-table / firmware steering) by
  (a) **overriding** over-quota allocation calls to a failure value, and
  (b) **token-bucket throttling** the *rate* of churn-prone control calls.
- **Programs (source → object).**
  - `r_filter.bpf.c` → `r_filter.bpf.o` — allocation override (NULL / -EAGAIN).
  - `r_filter_rate.bpf.c` → `r_filter_rate.bpf.o` — rate throttle (token bucket).
  - `r_filter_quota.bpf.c` → `r_filter_quota.bpf.o` — quota accounting.
  - `r_filter_monitor.bpf.o` — monitor-only variant.
- **Inputs.** Per-tenant quota from `Policy_Maps` (read-only shm). Hooked APIs:
  `rte_malloc` / `rte_zmalloc` / `rte_free` / `rte_memzone_reserve` / `rte_flow_create` /
  `rte_flow_destroy` (and other launch/alloc calls).
- **Outputs.** `BPF_MODIFY_RETURN` rewrites (`NULL` for allocators/`rte_flow_create`, `-EAGAIN`
  for others) or throttling of the call rate — affecting only the offending tenant.
- **Loaded by.** `bpftime_Loader/r_loader` and `r_loader_rate` (host side).
- **Upstream dependency.** Runs on the bpftime Agent runtime (upstream; not part of this module).
- **Build.** `clang -O2 -g -target bpf -c r_filter*.bpf.c -o r_filter*.bpf.o` (see `BUILD.md`).

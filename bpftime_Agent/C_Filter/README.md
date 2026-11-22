# C_Filter — Communication Filtering (eSAC-authored)

Communication-plane eBPF programs enforcing **per-tenant network access control** on the DPDK
RX/TX burst path, inside the tenant process via bpftime.

- **Role.** L4 5-tuple **ALLOW / DROP** keyed by `cgroup_id` (per tenant), plus the **L7 content
  gate** that drives `H_matcher`.
- **Programs (source → object).**
  - `c_filter.bpf.c` → `c_filter.bpf.o` — L4 5-tuple **mask-probe hash**, cost independent of the
    policy count (2 or 16,384 rules scan at the same rate).
  - `c_filter_hs_gate.bpf.c` → `c_filter_hs_gate.bpf.o` — L7 gate: content-prescans the burst and
    hands candidate payloads to the Hyperscan matcher.
  - Headers: `common.h`, `common_cgroup.h`, `ufunc.bpf.h`.
- **Inputs.** Per-tenant L4 policy from `Policy_Maps` (read-only shm); burst payload pointers.
- **Outputs.** Per-packet ALLOW / DROP. For L7, the gate defers the match verdict to `H_matcher`.
- **Loaded by.** `bpftime_Loader/c_loader` (datapath), `c_loader_rx` (RX-only), `c_loader_tx` (TX).
- **Interplay.** The L7 gate invokes the `H_matcher` ufunc (`esac_hs_scan`) through bpftime's ufunc
  mechanism; `H_matcher` returns the L7 match used for the DROP decision.
- **Upstream dependency.** Runs on the bpftime Agent runtime (upstream; not part of this module).
- **Build.** `clang -O2 -g -target bpf -c c_filter*.bpf.c -o c_filter*.bpf.o` (see `BUILD.md`).

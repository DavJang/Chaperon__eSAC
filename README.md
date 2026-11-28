# Chaperon

**Fine-grained security enforcement for multi-tenant DPDK environments**

## Overview

Chaperon is a research prototype for enforcing communication, resource, and integrity policies in multi-tenant DPDK environments.

User-space networking frameworks such as DPDK provide high-performance packet processing by bypassing the conventional kernel networking stack. However, this execution model also limits the applicability of conventional kernel-based security enforcement to the user-space data path.

Chaperon addresses this problem by integrating in-process eBPF enforcement with host-side policy management and kernel-assisted protection mechanisms. Its design aims to preserve the performance advantages of user-space networking while providing security enforcement for untrusted, non-root tenants.

Chaperon builds upon our earlier eSAC research prototype and extends its security enforcement beyond communication policies.

## Architecture

Chaperon consists of three cooperating architectural components.

### Manager

The Manager performs admission control, configures tenant-specific policies, manages kernel-backed policy maps, and coordinates protected application launch.

### Agent

The Agent executes eBPF programs within the tenant's address space using a modified bpftime runtime. It enforces communication policies at DPDK packet-processing boundaries and performs resource-policy pre-checks before resource allocation or configuration.

### Sentinel

The Sentinel provides kernel-assisted resource accounting, hard-limit enforcement, integrity protection, and NIC access control. The Resource Sentinel monitors selected resource-control operations; the Tamper Sentinel monitors attempts to modify protected memory regions and gates the kernel functions through which the NIC driver is acquired and controlled.

Together, these components separate packet-path enforcement from host-side security management and resource-control enforcement.

## Security Enforcement

### Gated Launch

- The tenant is started stopped, placed in its own cgroup, and released only after the Sentinels are attached.
- A trusted bootstrap in the tenant seals the Agent before any application code runs and waits at a launch barrier.
- The Manager independently verifies the barrier state, registers the protected memory ranges, and registers the tenant as a Sealed Process before it issues a root-owned GO token.
- The Communication Filter drops every packet until the Manager arms the policy; any failed step refuses the launch.

### Kernel-backed Policy Maps

- Communication and resource policies and resource usage live in pinned kernel BPF maps owned by the Manager.
- The Agent maps them read-only; the tenant cannot obtain writable map file descriptors.
- Policies are updated at run time by the Manager (live ALLOW/DROP changes without restarting the tenant).

### L4/L7 Communication Filtering

- Fine-grained L4 access control using five-tuple policies.
- Exact and wildcard matching across all five-tuple fields.
- Tenant-specific and global policies.
- Active-mask optimization supporting up to 64 mask-probe combinations.
- L7 payload inspection using Hyperscan.
- Payload allowlist and denylist policies.
- Protocol-aware payload classification, including DNS and Redis RESP.
- RX burst compaction and TX burst exclusion.
- Default-drop behavior for unclassifiable packets.

The normal packet-processing path performs policy enforcement within user space without requiring additional kernel crossings for each packet.

Payload inspection operates on packet contents and does not perform general TCP stream reassembly.

### Resource Control and Resource Sentinel

- Admission control for tenant resource requests.
- Resource quota and rate enforcement.
- Read-only Agent-side policy and usage-map access.
- Kernel-backed resource accounting.
- Atomic accounting across concurrent callers.
- GCRA-based rate enforcement.
- Graceful rejection through Agent pre-checks.
- Kernel-assisted hard-limit enforcement through the Resource Sentinel.

Memory rate enforcement is performed at protected resource-call boundaries. Nested allocations use bounded per-request accounting rather than charging every internal allocation independently.

Resource-control operations may enter the kernel for accounting and enforcement. Applications that perform heap allocation on the packet path therefore have different kernel-crossing characteristics from workloads that reuse preallocated packet buffers.

### Integrity Protection and Tamper Sentinel

- Read-only protection of security-critical code and data.
- Sealed hook-to-filter dispatch.
- Protected policy and runtime metadata.
- Kernel monitoring of memory-modification operations, including `madvise` operations that would keep protected ranges from being inherited by a child process.
- Cgroup-scoped tamper detection.
- Fail-closed handling of detected protection failures.

### NIC Access Control

- **Sealed Process tracking**: the Tamper Sentinel records the processes that completed Agent sealing (identity: PID plus start time, so a reused PID is never trusted). Only the Manager registers a process, as the last step before GO; the registry is not accessible to the tenant.
- **Fork, exec and threads**: a process forked by a Sealed Process (including `vfork` and `CLONE_VM` children) inherits the status together with the sealed regions; a successful `exec` removes it (a new program starts without the Agent), a failed `exec` keeps it; threads share the status of their process, which is removed when the last thread exits.
- **NIC gate**: the kernel functions through which the mlx5 PMD acquires and controls the NIC (the RDMA verbs device: open, command `ioctl` including compat, `mmap`, `write`) are denied before the driver handler runs to a tenant process that is not sealed, which is then terminated. The check is made per call, so inherited or passed file descriptors are covered.
- **VF-level device restriction**: only the RDMA device of the tenant's VF, selected by the operator, may be used, and only by Sealed tenant processes; tenant access to another VF's device is denied and terminated, and use of the tenant's device from outside the tenant is denied.
- **Tenant privileges**: the tenant runs under a dedicated non-root account without sudo rights, with only the capabilities the mlx5 PMD needs (`CAP_NET_RAW`, `CAP_SYS_RAWIO`), `NO_NEW_PRIVS`, and a seccomp filter denying I/O-port access, in its own network namespace without access to the kernel network interfaces of the NIC.

## Repository Structure

| Directory | Description |
| --- | --- |
| [manager/](manager/) | Admission control, policy management, and protected launch |
| [agent/](agent/) | Modified bpftime runtime and sealed dispatch |
| [communication/](communication/) | L4/L7 packet enforcement and policy lookup |
| [resource/](resource/) | Resource pre-checks, kernel accounting, and hard-limit enforcement |
| [integrity/](integrity/) | Memory sealing and tamper protection |
| [tests/](tests/) | Functional tests, regression tests, and evaluation harnesses |
| [docs/](docs/) | Implementation and evaluation documentation |

## Implementation Environment

The current research prototype has been developed and evaluated using:

- Linux
- DPDK
- bpftime
- eBPF
- Hyperscan
- SR-IOV virtual functions
- NVIDIA/Mellanox mlx5 network interfaces

The reference implementation uses a trusted host environment to configure and launch untrusted, non-root DPDK tenants.

See the implementation documentation for software requirements, hardware configuration, build instructions, and experiment setup.

## Threat Model and Scope

- Trusted: the host operator, the Manager, the Linux kernel, and the Sentinels. Untrusted: the non-root tenant and the processes it creates.
- Out of scope: direct NIC programming by code inside the same tenant process. The Agent enforces at the PMD packet-processing boundaries; application code running in the same (sealed) process could program its own VF directly through the RDMA verbs interface or the PMD's queues, bypassing those boundaries. The kernel cannot distinguish PMD code from application code of the same process. This was observed on the reference host and is not prevented.
- `CAP_SYS_RAWIO` is retained because the mlx5 PMD needs it. Its known hardware paths (I/O ports, `/proc/bus/pci`) are removed; the remaining uses are governed by root-only file permissions, but it has not been proven exhaustively that no other path reaches the NIC.
- Functional constraints of the current implementation: without `CAP_NET_ADMIN` the PMD cannot change netdev-level settings (MTU, promiscuous mode through netlink, link state, VF MAC through the PF); only mlx5/RDMA-verbs NIC access is gated; the reference applications are `dpdk-testpmd` and dperf.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the complete list of limitations and verification coverage.

## Evaluation

The implementation includes functional and regression tests covering:

- L4 and L7 policy enforcement
- Multi-tenant policy isolation
- Concurrent resource accounting
- Resource quota and rate limits
- Kernel-side hard-limit enforcement
- RX and TX packet exclusion
- Runtime integrity protection
- Protected application launch
- Sealed Process lifecycle (fork, vfork, `CLONE_VM`, exec, multithreaded exit, PID reuse)
- NIC access control for unsealed processes, inherited and passed file descriptors, and other VFs' devices
- Tenant privilege restrictions and NIC paths outside the RDMA verbs interface

Representative enforcement paths have been tested using real DPDK traffic over SR-IOV virtual functions.

Chaperon is a research prototype. Its security properties are subject to its threat model, implementation coverage, and documented limitations.

Comprehensive performance evaluation results will be documented as the evaluation progresses.

## Documentation

- [VERSION_MANIFEST.md](VERSION_MANIFEST.md) — Current implementation versions and component hashes.
- [docs/BUILD.md](docs/BUILD.md) — Software requirements and build instructions.
- [docs/RUN.md](docs/RUN.md) — Host setup, protected launch, and test modes.
- [docs/PERF_EVAL_SETUP.md](docs/PERF_EVAL_SETUP.md) — Performance evaluation setup.
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — Implementation limitations and verification coverage.
- [agent/README.md](agent/README.md) — Agent runtime (bpftime base and Chaperon changes).
- [tests/README.md](tests/README.md) — Functional, regression, and unit tests.
- [ATTRIBUTION.md](ATTRIBUTION.md) — Upstream components.

## Legacy Implementation

The earlier eSAC research prototype is preserved in the `legacy/esac` branch.

The main branch contains the current Chaperon implementation. Legacy components should not be used for current Chaperon builds or performance evaluations.

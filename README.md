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

The Sentinel provides kernel-assisted resource accounting, hard-limit enforcement, and integrity protection. It monitors selected resource-control operations and attempts to modify protected memory regions.

Together, these components separate packet-path enforcement from host-side security management and resource-control enforcement.

## Security Enforcement

### Communication Control

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

### Resource Control

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

### Integrity Protection

- Read-only protection of security-critical code and data.
- Sealed hook-to-filter dispatch.
- Protected policy and runtime metadata.
- Kernel monitoring of memory-modification operations.
- Cgroup-scoped tamper detection.
- Gated application launch.
- Fail-closed handling of detected protection failures.

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

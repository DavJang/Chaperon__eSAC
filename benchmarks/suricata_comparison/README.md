# eSAC vs Suricata — L7 all-match throughput comparison

Throughput of **none** (no inspection) vs **eSAC** (in-process L7 Hyperscan) vs
**Suricata** (DPDK middlebox IDS), all under an **all-match** workload (every packet
matches the inspection pattern — the worst case for the inspector). Payload sweep
64 / 256 / 512 / 1400 B. mlx5 ConnectX, kernel-bypass (DPDK) on both sides.

## Headline

**eSAC 1 core ≈ Suricata 5–8 cores** (all-match). eSAC on a single core already runs
at 82–92% of wire rate; Suricata needs 5–8 cores to match one eSAC core, and even at
4 cores it does not reach one eSAC core at 1400 B.

| payload | none (wire) | eSAC 1c | Suricata 1c | Suricata 2c | Suricata 4c | eSAC 1c ≈ Suri N cores |
|--------:|------------:|--------:|------------:|------------:|------------:|:----------------------:|
| 64 B    | 5.72 M pps  | **5.18 M** (91%) | 0.66 M | 1.27 M | 2.05 M | ~8 |
| 256 B   | 5.37 M      | **4.42 M** (82%) | 0.62 M | 1.15 M | 2.23 M | ~7 |
| 512 B   | 4.58 M      | **3.88 M** (85%) | 0.58 M | 1.08 M | 2.21 M | ~7 |
| 1400 B  | 2.92 M      | **2.68 M** (92%) | 0.57 M | 1.05 M | 2.01 M | ~5 |

*pps = packets/s. eSAC = in-process delivered; Suricata = decoded+alerted (every packet alerts).*

## Why the shapes differ

- **eSAC is byte-scan bound**: pps falls as payload grows (5.18 M → 2.68 M), but it stays
  near wire rate because at these sizes the wire saturates before Hyperscan does. The eSAC
  numbers here are a *floor* (single-core generator is wire-bound, CPU still idle).
- **Suricata is per-packet bound**: ~0.57–0.66 M pps **per core regardless of payload**
  (decode + flow + transaction + detect cost is per packet, not per byte). At 1400 B that
  per-core rate is 6.4 Gbps; it scales **near-linearly 1→4c (3.5–3.8×)**.

## Getting real multicore out of Suricata on mlx5

Out of the box, Suricata's **DPDK mlx5 RSS concentrates ~90–99% of traffic on queue 0**,
so extra worker threads sit idle and throughput does **not** scale with cores. This is an
application-level issue (the same VF spreads perfectly 25%/queue under `testpmd`), matching
the open upstream report
[OISF redmine #6747](https://redmine.openinfosecfoundation.org/issues/6747). It is **not**
hardware, DPDK version, RSS key, RETA size, hash-function, or IPS-vs-IDS — all were ruled out.

To measure Suricata's true multicore ceiling we bypass its RSS and split at the NIC eSwitch:

1. SR-IOV switchdev on the PF; one generator VF + N inspector VFs.
2. `tc flower skip_sw` rules on the generator representor match `src_ip` ranges and
   `mirred` redirect to each inspector VF representor — **fully HW-offloaded (`in_hw`),
   kernel-bypass**.
3. Suricata runs N DPDK interfaces, 1 thread each (workers runmode). Each VF feeds one core.

This yields perfectly balanced per-core load and near-linear scaling. See `harness/`.

> Note (rig-specific): a locally-instrumented Suricata build called
> `rte_eth_xstats_get` **every RX burst** (per-queue debug dump), which pins DPDK
> throughput to a few K pps/core. Disabling that per-burst xstats call restores normal
> ~0.57 M pps/core. Upstream Suricata does not have this.

## Reproduce

- `harness/matchall.rules` — rule that matches every packet (`content:"|00|"`).
- `harness/suricata_dpdk_4iface.yaml` — 4-interface (4-core) DPDK IDS config.
- `harness/mvfmatch.sh` — payload-sweep driver: sets the eSwitch split, runs Suricata
  1/2/4c, floods with `testpmd --txonly-multi-flow` at the chosen size, reports decoded
  pps + alerts. (Paths are for the development rig; adjust `W`, interface PCI ids, and the
  `tc` representor names to your setup. Needs root for mlx5 DevX.)

eSAC numbers come from the in-process L7 Hyperscan path (`demos/` + the Policy_Maps
all-match ruleset); none = the same datapath with inspection disabled.

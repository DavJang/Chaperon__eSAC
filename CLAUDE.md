# CLAUDE.md — eSAC maintenance rules

**eSAC** (eBPF-enforced Security Access Control for multi-tenant DPDK) is built **on upstream
bpftime** (a dependency, **not** a fork). Follow these rules on every change in this repo.

## Code boundaries
1. **Separate upstream bpftime from eSAC code.** The injected runtime (`libbpftime-agent*.so`,
   `libbpftime-syscall-server.so`) and **Frida-Gum** are upstream — build from their own source,
   never edit them here. eSAC's own code is `bpftime_Agent/{R_Filter,C_Filter,H_matcher}`,
   `bpftime_Loader`, `Policy_Maps`, `Resource_Bank`, `Tamper_Sentinel`. See `ATTRIBUTION.md`.
2. **Keep module boundaries.** R_Filter = resource plane, C_Filter = communication plane,
   H_matcher = L7 Hyperscan/DNS matcher. New security logic goes in the module that owns it.
3. **Do not re-implement existing functionality.** Reuse before adding.
4. **Host vs tenant.** Host loaders live under `bpftime_Loader` (`c_loader*`, `r_loader*`); the BPF
   each injects lives under its Agent module; admission/policy stays with its plane.

## Build & binaries
5. **Commit source, not binaries.** `*.so`, `*.o`, compiled loaders/ctl tools, and `*.rawscan-bak`
   are gitignored — rebuild via `BUILD.md`. Never commit the large runtime `.so`. (Two binaries
   without committed source are still tracked and flagged in the README — source or drop them.)
6. **Verify dependencies when paths change.** Loaders reference `--bpf`/`--lib` by absolute path and
   many scripts hardcode paths; validate build + load after any move/rename.

## Experiments
7. **Results go to `~/eSAC-runs/`, never `~/` or the repo.** Launch experiments through
   `benchmarks/esac_run.sh` (it sets the output dir and writes `meta.json`: git commit, ruleset
   sha256, config, timing, metrics). **Wrap existing harnesses — do not rewrite their logic.**
8. **Benchmark provenance.** Keep **raw-scan** and **DNS-aware v2** results distinct. The headline
   throughput (89–96 % intra; ~7.5× a DPDK-IPS baseline @ 4 matched cores) is **raw-scan**; v2 is
   correctness-verified and re-measured only on the inter-host payload sweep so far. Mark pending
   re-measurements; never present raw-scan numbers as v2. Do **not** extrapolate IPS core-equivalence
   (IPS scales sub-linearly).

## Data & safety
9. **Never delete or bulk-move existing code or experiment data without explicit approval.** Do not
   assume same-named files are duplicates — check hash, git history, build deps, and in-use status
   first. Never change NIC/SR-IOV/hugepage/kernel settings or `git push`/force-push without approval.
10. **Docs track code.** Update README/BUILD/RUN and the module READMEs with any change; do not
    claim unimplemented capability (e.g. DNS **compression is not decompressed** — fallback-only;
    stated in `bpftime_Agent/H_matcher/README.md`).

## Canonical layout (target)
- `~/eSAC/` — the **single** canonical dev repo (this tree). Do not spawn new `FINAL` / `eSACfinal`
  / `GOWN` working copies.
- `~/eSAC-runs/` — experiment outputs (`<type>/<timestamp>_<desc>/` + `meta.json`).
- `~/eSAC-archive/` — old working trees & backups, read-only.

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
   `benchmarks/esac_run.sh` (it sets a collision-safe output dir, writes `meta.json` — git commit,
   ruleset sha256, config, timing — a before/after system snapshot, and a report-only post-run
   residual check). **Wrap existing harnesses — do not rewrite their logic.**
   - **Every new or modified harness MUST route its output through `$ESAC_RUNS`**, i.e.
     `ROOT="${ESAC_RUNS:-<fallback>}"`, or be launched via `esac_run.sh`. A script that writes
     results under `$HOME` (e.g. `ROOT=/home/.../esac_pps_*`) is a defect — fix it before use.
   - `esac_run.sh`'s post-run check is **report-only**: it never kills a process or changes
     NIC/VF/hugepage. Act on its warnings manually.
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

## Canonical layout
- `~/eSAC/` — the **single** canonical dev repo (this tree), GitHub remote `DavJang/eSAC`. Do not
  spawn new `FINAL` / `eSACfinal` / `GOWN` working copies; use branches + commits here instead.
- `~/eSAC-runs/` — experiment outputs (`<type>/<timestamp>_<desc>/` + `meta.json`).
- `~/eSAC-archive/` — old working trees & backups, read-only.
- `~/bpftime/` — upstream bpftime dependency source.

## Single source of truth (prevents the FINAL/eSACfinal divergence this cleanup fixed)
- **All source edits happen in `~/eSAC` only.** `FINAL/eSAC` and any experiment rig are a
  **deploy target**, not a source: built artifacts arrive via `tools/deploy.sh --install <rig>`
  (which preserves the big bpftime runtime and backs up what it replaces). Never edit source or
  rebuild independently inside a rig. If two trees ever diverge again, reconcile into `~/eSAC` and
  re-deploy — do not keep editing both.

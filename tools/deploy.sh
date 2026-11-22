#!/bin/bash
# deploy.sh - build every eSAC artifact from THIS canonical source, and ensure the
# ufunc -> H_matcher compatibility symlink so legacy harness paths resolve to current code.
# Build happens in-tree (artifacts are gitignored). Does not touch anything outside this repo.
# usage: tools/deploy.sh
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
A="$SRC/bpftime_Agent"
BPF="clang -O2 -g -target bpf -D__TARGET_ARCH_x86"
echo "[deploy] source=$SRC"

echo "[deploy] eBPF objects"
$BPF -I "$A/C_Filter" -c "$A/C_Filter/c_filter.bpf.c"         -o "$A/C_Filter/c_filter.bpf.o"
$BPF -I "$A/C_Filter" -c "$A/C_Filter/c_filter_hs_gate.bpf.c" -o "$A/C_Filter/c_filter_hs_gate.bpf.o"
for r in r_filter r_filter_quota r_filter_rate; do
  $BPF -I "$A/R_Filter" -I "$A/C_Filter" -c "$A/R_Filter/$r.bpf.c" -o "$A/R_Filter/$r.bpf.o"
done

echo "[deploy] host loaders"
for l in c_loader c_loader_rx r_loader r_loader_rate; do
  gcc "$SRC/bpftime_Loader/src/$l.c" -o "$SRC/bpftime_Loader/$l" -lbpf -lelf -lz
done

echo "[deploy] L7 matcher + hsdb ctl"
HSI="-I $A/H_matcher/hsdb_ctl/src"
gcc -shared -fPIC -O2 $HSI "$A/H_matcher/src/esac_hs_ufunc.c" -o "$A/H_matcher/esac_hs_ufunc.so" -lhs
gcc -shared -fPIC -O2 $HSI "$A/H_matcher/src/esac_suricata_dns_ufunc.c" -o "$A/H_matcher/esac_suricata_dns_ufunc.so" -lhs -lrt \
  || echo "[deploy] WARN: esac_suricata_dns_ufunc.so (secondary) failed to build; continuing"
gcc $HSI "$A/H_matcher/hsdb_ctl/src/esac_hs_ctl_rx.c"    -o "$A/H_matcher/hsdb_ctl/esac_hs_ctl_rx"    -lhs
gcc $HSI "$A/H_matcher/hsdb_ctl/src/esac_dom_ctl_bulk.c" -o "$A/H_matcher/hsdb_ctl/esac_dom_ctl_bulk"

echo "[deploy] legacy-path compat symlink (ufunc -> H_matcher)"
[ -e "$A/ufunc" ] || ln -s H_matcher "$A/ufunc"

echo "[deploy] OK. ufunc -> $(readlink "$A/ufunc"); artifacts rebuilt from source."
echo "[deploy] NOTE: the two source-less binaries (c_loader_tx, r_filter_monitor.bpf.o) are kept as-is."

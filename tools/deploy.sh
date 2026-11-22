#!/bin/bash
# deploy.sh - build eSAC artifacts from THIS canonical source, and optionally install the
# eSAC-unique binaries into an experiment rig (preserving the upstream bpftime runtime).
#
# usage:
#   tools/deploy.sh                      build all artifacts in-tree + ufunc->H_matcher symlink
#   tools/deploy.sh --install <RIG>      build, then install eSAC-unique artifacts into <RIG>
#                                        (backs up + hashes each target; NEVER touches the big
#                                         libbpftime-agent*/libbpftime-syscall-server runtime)
#   tools/deploy.sh --rollback <RIG> [TS]  restore <RIG> from a deploy backup (latest, or TS)
#
# The install map below maps repo paths -> rig-relative paths. The repo's H_matcher/ installs
# into the rig's legacy ufunc/ dir (so existing harness paths keep working).
set -uo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
A="$SRC/bpftime_Agent"
BPF="clang -O2 -g -target bpf -D__TARGET_ARCH_x86"
GITC=$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)

# repo_src :: rig_relative_dst  (eSAC-unique artifacts only; big runtime is NEVER listed)
MAP=(
  "bpftime_Agent/C_Filter/c_filter.bpf.o::eSAC/bpftime_Agent/C_Filter/c_filter.bpf.o"
  "bpftime_Agent/C_Filter/c_filter_hs_gate.bpf.o::eSAC/bpftime_Agent/C_Filter/c_filter_hs_gate.bpf.o"
  "bpftime_Agent/R_Filter/r_filter.bpf.o::eSAC/bpftime_Agent/R_Filter/r_filter.bpf.o"
  "bpftime_Agent/R_Filter/r_filter_quota.bpf.o::eSAC/bpftime_Agent/R_Filter/r_filter_quota.bpf.o"
  "bpftime_Agent/R_Filter/r_filter_rate.bpf.o::eSAC/bpftime_Agent/R_Filter/r_filter_rate.bpf.o"
  "bpftime_Agent/H_matcher/esac_hs_ufunc.so::eSAC/bpftime_Agent/ufunc/esac_hs_ufunc.so"
  "bpftime_Agent/H_matcher/esac_suricata_dns_ufunc.so::eSAC/bpftime_Agent/ufunc/esac_suricata_dns_ufunc.so"
  "bpftime_Loader/c_loader::eSAC/bpftime_Loader/c_loader"
  "bpftime_Loader/c_loader_rx::eSAC/bpftime_Loader/c_loader_rx"
  "bpftime_Loader/r_loader::eSAC/bpftime_Loader/r_loader"
  "bpftime_Loader/r_loader_rate::eSAC/bpftime_Loader/r_loader_rate"
)
PROTECT='libbpftime-agent|libbpftime-syscall-server'   # never overwrite these in a rig

build_all(){
  echo "[deploy] source=$SRC (version $GITC)"
  $BPF -I "$A/C_Filter" -c "$A/C_Filter/c_filter.bpf.c"         -o "$A/C_Filter/c_filter.bpf.o"
  $BPF -I "$A/C_Filter" -c "$A/C_Filter/c_filter_hs_gate.bpf.c" -o "$A/C_Filter/c_filter_hs_gate.bpf.o"
  for r in r_filter r_filter_quota r_filter_rate; do
    $BPF -I "$A/R_Filter" -I "$A/C_Filter" -c "$A/R_Filter/$r.bpf.c" -o "$A/R_Filter/$r.bpf.o"
  done
  for l in c_loader c_loader_rx r_loader r_loader_rate; do
    gcc "$SRC/bpftime_Loader/src/$l.c" -o "$SRC/bpftime_Loader/$l" -lbpf -lelf -lz
  done
  local HSI="-I $A/H_matcher/hsdb_ctl/src"
  gcc -shared -fPIC -O2 $HSI "$A/H_matcher/src/esac_hs_ufunc.c" -o "$A/H_matcher/esac_hs_ufunc.so" -lhs -ldl
  gcc -shared -fPIC -O2 $HSI "$A/H_matcher/src/esac_suricata_dns_ufunc.c" -o "$A/H_matcher/esac_suricata_dns_ufunc.so" -lhs -lrt \
    || echo "[deploy] WARN: esac_suricata_dns_ufunc.so (secondary) failed; continuing"
  gcc $HSI "$A/H_matcher/hsdb_ctl/src/esac_hs_ctl_rx.c"    -o "$A/H_matcher/hsdb_ctl/esac_hs_ctl_rx"    -lhs
  gcc $HSI "$A/H_matcher/hsdb_ctl/src/esac_dom_ctl_bulk.c" -o "$A/H_matcher/hsdb_ctl/esac_dom_ctl_bulk"
  [ -e "$A/ufunc" ] || ln -s H_matcher "$A/ufunc"
  echo "[deploy] build OK. ufunc -> $(readlink "$A/ufunc"); (c_loader_tx, r_filter_monitor.bpf.o kept as-is)"
}

install_to_rig(){
  local RIG="$1"; [ -d "$RIG" ] || { echo "[deploy] rig not found: $RIG" >&2; exit 1; }
  local BK="$RIG/.esac_deploy_backup/$(date +%Y%m%d_%H%M%S)"; mkdir -p "$BK"
  local MAN="$RIG/.esac_deploy_manifest.json"; : > "$MAN"
  echo "{ \"deployed\": \"$(date -Iseconds)\", \"version\": \"$GITC\", \"backup\": \"$BK\", \"files\": [" >> "$MAN"
  local n=0
  for pair in "${MAP[@]}"; do
    local src="${pair%%::*}" dst="${pair##*::}"
    local S="$SRC/$src" D="$RIG/$dst"
    [ -f "$S" ] || { echo "[deploy] skip (no built src): $src"; continue; }
    if echo "$(basename "$D")" | grep -qE "$PROTECT"; then echo "[deploy] REFUSE protected: $dst" >&2; continue; fi
    local oldsha="absent"
    if [ -f "$D" ]; then oldsha=$(sha256sum "$D" | cut -c1-16); mkdir -p "$BK/$(dirname "$dst")"; cp -a "$D" "$BK/$dst"; fi
    mkdir -p "$(dirname "$D")"; cp -a "$S" "$D"; local newsha=$(sha256sum "$D" | cut -c1-16)
    [ $n -gt 0 ] && echo "," >> "$MAN"; n=$((n+1))
    printf '  { "file": "%s", "old_sha": "%s", "new_sha": "%s" }' "$dst" "$oldsha" "$newsha" >> "$MAN"
    echo "[deploy] install $dst  ($oldsha -> $newsha)"
  done
  echo "" >> "$MAN"; echo "] }" >> "$MAN"
  # verify big runtime untouched
  echo "[deploy] protected runtime preserved:"
  find "$RIG" -name 'libbpftime-*' -printf '  kept %s %p\n' 2>/dev/null | head
  echo "[deploy] installed $n eSAC artifacts into $RIG; backup=$BK; manifest=$MAN"
}

rollback(){
  local RIG="$1" TS="${2:-}"
  [ -d "$RIG/.esac_deploy_backup" ] || { echo "[deploy] no backups in $RIG" >&2; exit 1; }
  [ -z "$TS" ] && TS=$(ls -1 "$RIG/.esac_deploy_backup" | tail -1)
  local BK="$RIG/.esac_deploy_backup/$TS"
  [ -d "$BK" ] || { echo "[deploy] no backup $BK" >&2; exit 1; }
  (cd "$BK" && find . -type f -printf '%P\n') | while read -r f; do cp -a "$BK/$f" "$RIG/$f"; echo "[deploy] restored $f"; done
  echo "[deploy] rollback from $BK complete"
}

case "${1:-}" in
  --install)  build_all; install_to_rig "${2:?usage: --install <RIG>}" ;;
  --rollback) rollback "${2:?usage: --rollback <RIG> [TS]}" "${3:-}" ;;
  "")         build_all ;;
  *)          echo "usage: deploy.sh [--install <RIG> | --rollback <RIG> [TS]]" >&2; exit 2 ;;
esac

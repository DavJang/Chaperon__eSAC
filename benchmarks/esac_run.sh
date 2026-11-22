#!/bin/bash
# esac_run.sh - canonical experiment launcher.
# Forces results into ~/eSAC-runs/<type>/<timestamp>_<desc>[_N]/ and records meta.json
# (git commit, ruleset sha256, config, timing) + a before/after system snapshot and a
# post-run residual check. It WRAPS a command; it does NOT alter any harness's own logic.
#
# usage:  benchmarks/esac_run.sh <type> <desc> -- <command ...>
#   <type>: l4_intra | l4_inter | l7_intra | l7_inter | lcore | suricata | resource | tamper | other
#
# Harnesses that honor $ESAC_RUNS for their output root write straight into the run dir
# (e.g. ROOT=${ESAC_RUNS:-<old default>}); others still run and at least their stdout is captured.
#
# SAFETY: the post-run check is REPORT-ONLY. It never kills a process and never changes
# NIC / SR-IOV VF / hugepage settings. Anomalies are logged for the user to act on.
set -u
TYPE="${1:?usage: esac_run.sh <type> <desc> -- <cmd...>}"
DESC="${2:?usage: esac_run.sh <type> <desc> -- <cmd...>}"
shift 2
[ "${1:-}" = "--" ] && shift

# resolve the invoking user's home even under sudo ($HOME would be /root), so results
# always land in the real user's ~/eSAC-runs, never /root/eSAC-runs
RUNS="${ESAC_RUNS_ROOT:-}"
if [ -z "$RUNS" ]; then
  _uh=$(getent passwd "${SUDO_USER:-$(id -un)}" 2>/dev/null | cut -d: -f6)
  RUNS="${_uh:-$HOME}/eSAC-runs"
fi
TS=$(date +%Y%m%d_%H%M%S)
SAFE_DESC=$(echo "$DESC" | tr ' /' '__')
# collision-safe unique dir: append _N if the timestamped name already exists
base="$RUNS/$TYPE/${TS}_${SAFE_DESC}"
OUT="$base"; i=1
while [ -e "$OUT" ]; do OUT="${base}_$i"; i=$((i+1)); done
mkdir -p "$OUT" || { echo "[esac_run] cannot create $OUT" >&2; exit 1; }

# read-only system snapshot (never mutates anything)
pc(){ local n; n=$(pgrep -xc "$1" 2>/dev/null); echo "${n:-0}"; }   # pgrep -xc exits 1 on 0 matches; normalize
loaders_count(){ echo $(( $(pc comm_loader_rxonly) + $(pc comm_loader_kernel128) + $(pc c_loader) + $(pc r_loader) )); }
snapshot(){
  printf '{ "ts":"%s", "dperf":%s, "loaders":%s, "testpmd":%s, "vf_3b00":"%s", "hp_free_n0":"%s", "hp_free_n1":"%s" }\n' \
    "$(date -Iseconds)" \
    "$(pc dperf)" "$(loaders_count)" "$(pc dpdk-testpmd)" \
    "$(cat /sys/bus/pci/devices/0000:3b:00.0/sriov_numvfs 2>/dev/null||echo NA)" \
    "$(cat /sys/devices/system/node/node0/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null||echo NA)" \
    "$(cat /sys/devices/system/node/node1/hugepages/hugepages-2048kB/free_hugepages 2>/dev/null||echo NA)"
}
snapshot > "$OUT/state_before.json"

SELFDIR=$(cd "$(dirname "$0")" && pwd)
GITC=$(git -C "$SELFDIR/.." rev-parse --short HEAD 2>/dev/null || echo unknown)
RULESET="${ESAC_HS_PATTERNS:-}"; RULESHA=""
[ -n "$RULESET" ] && [ -f "$RULESET" ] && RULESHA=$(sha256sum "$RULESET" | cut -d' ' -f1)
cat > "$OUT/meta.json" <<JSON
{
  "type": "$TYPE", "desc": "$DESC", "started": "$(date -Iseconds)",
  "git_commit": "$GITC", "host": "$(hostname)",
  "ruleset": "$RULESET", "ruleset_sha256": "$RULESHA",
  "cmd": "$*",
  "env": { "ESAC_HS_PATTERNS": "${ESAC_HS_PATTERNS:-}", "KA": "${KA:-}", "GENCPS": "${GENCPS:-}", "GENCPU": "${GENCPU:-}" }
}
JSON

export ESAC_RUNS="$OUT"
echo "[esac_run] out=$OUT type=$TYPE commit=$GITC"
( "$@" ) 2>&1 | tee "$OUT/run.log"
rc=${PIPESTATUS[0]}
snapshot > "$OUT/state_after.json"

# post-run residual check (REPORT ONLY -- no kill, no NIC/VF/hugepage change)
rd=$(pc dperf); rl=$(loaders_count); rt=$(pc dpdk-testpmd)
vf=$(cat /sys/bus/pci/devices/0000:3b:00.0/sriov_numvfs 2>/dev/null||echo NA)
saved=$([ -f "$OUT/run.log" ] && echo yes || echo no)
warn=""
[ "$rc" != 0 ] && warn="${warn}abnormal_exit(rc=$rc); "
[ "$rd" -gt 0 ] 2>/dev/null && warn="${warn}residual_dperf=$rd; "
[ "$rl" -gt 0 ] 2>/dev/null && warn="${warn}residual_loaders=$rl; "
[ "$rt" -gt 0 ] 2>/dev/null && warn="${warn}residual_testpmd=$rt; "
{ [ "$vf" != NA ] && [ "$vf" != 0 ]; } 2>/dev/null && warn="${warn}VF_still_up=$vf; "
[ "$saved" = no ] && warn="${warn}no_result_saved; "
cat > "$OUT/postcheck.json" <<JSON
{
  "ended": "$(date -Iseconds)", "rc": $rc, "result_saved": "$saved",
  "residual_dperf": $rd, "residual_loaders": $rl, "residual_testpmd": $rt, "vf_3b00": "$vf",
  "warnings": "${warn:-none}",
  "note": "report-only; esac_run.sh never kills processes or changes NIC/VF/hugepage"
}
JSON
if [ -n "$warn" ]; then
  echo "[esac_run] POST-RUN ANOMALY: ${warn}(reported only -- no action taken; see $OUT/postcheck.json)" >&2
fi
echo "[esac_run] done rc=$rc out=$OUT"
exit "$rc"

#!/bin/bash
# eSAC L4 DROP demo (deterministic). c_loader + c_filter.bpf.o drop a matching 5-tuple on the PMD
# RX burst BEFORE the tenant app sees it. ALLOW run: 0 drops. DROP run: every packet dropped.
#
# REQUIRES: Mellanox mlx5 NIC + DPDK (dpdk-testpmd on PATH) + root + hugepages, and the bpftime
# runtime built into bpftime_Agent/ (see BUILD.md). Set PF1/IF1 (and SCORES/GCORES for your NUMA).
# Run from the repo root:  sudo bash demos/l4_drop.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
SCORES=${SCORES:-6,7}; GCORES=${GCORES:-8,9}
TESTPMD=$(command -v "${TESTPMD:-dpdk-testpmd}" 2>/dev/null || echo "${TESTPMD:-dpdk-testpmd}")  # full path (loader --lib needs a real file path)
AGENT="$ROOT/bpftime_Agent/Frida/libbpftime-agent.so"
SERVER="$ROOT/bpftime_Loader/libbpftime-syscall-server.so"
LOADER="$ROOT/bpftime_Loader/c_loader"
COMBO="$ROOT/bpftime_Agent/C_Filter/c_filter.bpf.o"
OFFS="$ROOT/demos/offsets.json"
for f in "$AGENT" "$SERVER" "$LOADER" "$COMBO"; do [ -e "$f" ] || { echo "missing $f (build bpftime + loaders, see BUILD.md)"; exit 1; }; done
command -v $TESTPMD >/dev/null || { echo "need dpdk-testpmd on PATH"; exit 1; }
OUT=$(mktemp -d); say(){ echo "[$(date +%H:%M:%S)] $*" >&2; }

eval "$(bash "$ROOT/demos/setup_mlx5_fabric.sh" | grep INTRA_)"
SVF=${INTRA_SVF:-}; CVF=${INTRA_CVF:-}
[ -z "$SVF" ] && { say "FAIL: no mlx5 VF (check PF1/IF1 in demos/setup_mlx5_fabric.sh)"; exit 1; }
say "fabric SVF=$SVF CVF=$CVF"
cleanup(){ sudo -n pkill -9 -f 'dpdk-testpm[d]' 2>/dev/null; sudo -n pkill -9 -f '[c]_loader' 2>/dev/null; for c in /sys/fs/cgroup/esac_demo_*; do sudo -n rmdir "$c" 2>/dev/null; done; sleep 1; }
cleanup

run(){ local ACT="$1" tag="$2" o="$OUT/$2"; mkdir -p "$o"; local SHM="esac_demo_$(date +%s%N)"
  sudo -n setsid bash -c "echo \$\$>$o/tpid; kill -STOP \$\$; exec env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD=$AGENT $TESTPMD -l $SCORES -n4 --socket-mem 1024,0 -a ${SVF},rx_vec_en=0 --file-prefix=svf$$ -- --forward-mode=rxonly --no-lsc-interrupt --stats-period 1" > "$o/tenant.log" 2>&1 </dev/null &
  sleep 3; local TPID=$(cat "$o/tpid")
  sudo -n mkdir -p /sys/fs/cgroup/esac_demo_$tag 2>/dev/null; echo $TPID | sudo -n tee /sys/fs/cgroup/esac_demo_$tag/cgroup.procs >/dev/null 2>&1
  local CGID=$(stat -c %i /sys/fs/cgroup/esac_demo_$tag)
  printf '{"rules":[{"layer":"L2","cgroup_id":%s,"dst_ip":"198.18.0.2","proto":17,"dst_port":9,"action":"%s"}]}\n' "$CGID" "$ACT" > "$o/pol.json"
  sudo -n env BPFTIME_GLOBAL_SHM_NAME=$SHM LD_PRELOAD="$SERVER" "$LOADER" --max-burst-inspect 128 --bpf "$COMBO" --lib "$TESTPMD" --pmd-lib "$TESTPMD" --offsets "$OFFS" --policy "$o/pol.json" --no-pin --enforcement --attach-pid "$TPID" -v > "$o/loader.log" 2>&1 &
  local rdy=NO j; for j in $(seq 1 30); do grep -q 'attach summary: RX=OK' "$o/loader.log" 2>/dev/null && { rdy=YES; break; }; sleep 1; done
  sudo -n kill -CONT "$TPID" 2>/dev/null; sleep 1
  sudo -n timeout 8 $TESTPMD -l $GCORES -n4 --socket-mem 1024,0 -a ${CVF} --file-prefix=cvf$$ -- --forward-mode=txonly --txonly-multi-flow --tx-ip=198.18.0.1,198.18.0.2 --tx-udp=9 --stats-period 1 > "$o/gen.log" 2>&1
  sleep 1; sudo -n pkill -9 -f "svf$$" 2>/dev/null; sleep 1
  local dr=$(grep -aoE 'dropped=[0-9]+' "$o/loader.log" | awk -F= '{s+=$2}END{print s+0}')
  say "  [$tag] action=$ACT attach=$rdy ACT_DROP_events=$(grep -ac ACT_DROP "$o/loader.log") total_dropped=$dr"
  echo "${dr:-0}" > "$o/dropcount"; cleanup
}

say "===== eSAC L4 DROP (testpmd, deterministic) ====="
run ALLOW allow        # called directly (NOT in $(...) -- a pipeline subshell kills the bg traffic)
run DROP  drop
A=$(cat "$OUT/allow/dropcount" 2>/dev/null || echo 0); D=$(cat "$OUT/drop/dropcount" 2>/dev/null || echo 0)
say "RESULT: ALLOW dropped=$A (expect 0)   DROP dropped=$D (expect >0)"
if [ "${A:-1}" = 0 ] && [ "${D:-0}" -gt 0 ] 2>/dev/null; then say "VERDICT: PASS -- L4 DROP enforced"; else say "VERDICT: CHECK (see $OUT, tune fabric/cores)"; fi
rm -rf "$OUT"

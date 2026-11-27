#!/bin/bash
# Chaperon Request I: Table tab:apis matrix on the real mlx5 testpmd (one harness run per row, sequential).
#   rows: name|environment for run_3plane_F.sh
# Summary: $OUT (one block per row: run dir + the Request I check lines + OVERALL).
CHAP_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); [ -f "$CHAP_ROOT/manager/chap_env.sh" ] && . "$CHAP_ROOT/manager/chap_env.sh"   # repository root + host-local paths
MG=$CHAP_ROOT/manager
OUT=${OUT:-$CHAP_ROOT/tests/reqI/resapi_matrix_summary.txt}
ROWS=${ROWS:-full|RESAPI=1
bypass_dev_start|RESAPI=1 RES_OMIT=agent_dev_start RESAPI_BYPASS=dev_start
bypass_rxq_config|RESAPI=1 RES_OMIT=agent_dev_configure RESAPI_BYPASS=rxq_config
launch_eal_lcores|RESLAUNCH=agent RESPOL_EXTRA=lcores=6
launch_eal_hugepages|RESLAUNCH=agent RESPOL_EXTRA=max_hp_mb=512
launch_mbufs_agent|RESLAUNCH=agent RESPOL_EXTRA=max_mbufs=2048
launch_mbufs_sentinel|RESLAUNCH=sentinel RES_OMIT=agent_pktmbuf_pool RESPOL_EXTRA=max_mbufs=2048
launch_heap_agent|RESLAUNCH=agent RESPOL_EXTRA=max_mem_mb=16
launch_heap_sentinel|RESLAUNCH=sentinel RES_OMIT=agent_malloc+agent_memzone+agent_mempool+agent_pktmbuf_pool RESPOL_EXTRA=max_mem_mb=16
launch_hugetlb_kernel|RESLAUNCH=kernel CG_HP_MB=512}
echo "# Request I Table tab:apis matrix $(date -Is) agent=$(sha256sum $CHAP_RUNTIME_DIR/libbpftime-agent.so | cut -c1-8) r_precheck=$(sha256sum $CHAP_ROOT/resource/agent/r_precheck_agent.bpf.o | cut -c1-8) sentinel=$(sha256sum $CHAP_ROOT/resource/kernel/resource_sentinel.bpf.o | cut -c1-8)" >> "$OUT"
echo "$ROWS" | while IFS='|' read -r NAME ENVS; do
  [ -z "$NAME" ] && continue
  rm -f /sys/fs/bpf/chap/* 2>/dev/null
  LOG=/tmp/reqI_matrix_$NAME.log
  ( cd $MG && eval "env $ENVS bash run_3plane_F.sh" > "$LOG" 2>&1 )
  O=$(ls -td /var/tmp/chap_3pu_*/run | head -1)
  { echo "== $NAME ($ENVS) run=$O"
    grep -aE "reslaunch_|resource_sentinel_hardlimit|resapi_|comm_after|resource_agent_table_apis|resource_policy_set|launch_kernel_limits|FAIL" "$O/CHECKS.tsv" | cut -c1-700
    [ -f "$O/reslaunch.txt" ] && cat "$O/reslaunch.txt" | cut -c1-900
    grep -a OVERALL "$LOG" | tail -1; } >> "$OUT"
  sleep 3
done
echo "# MATRIX_DONE $(date -Is)" >> "$OUT"

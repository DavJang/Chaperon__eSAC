#!/bin/bash
# Request J fix closing chain (lazy outer-request charge, Sentinel 470da08a) on ONE build. Progress: $P ; logs /tmp/runJd_<name>.log
CHAP_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); [ -f "$CHAP_ROOT/manager/chap_env.sh" ] && . "$CHAP_ROOT/manager/chap_env.sh"   # repository root + host-local paths
cd $CHAP_ROOT/manager
P=$CHAP_ROOT/tests/reqJ/reqJ_runs2.progress; : > $P
OLD=${CHAP_OLD_SENTINEL_OBJ:-}
echo "VERSION agent=$(sha256sum $CHAP_RUNTIME_DIR/libbpftime-agent.so|cut -c1-8) r_precheck=$(sha256sum ../resource/agent/r_precheck_agent.bpf.o|cut -c1-8) rsentinel=$(sha256sum ../resource/kernel/resource_sentinel.bpf.o|cut -c1-8) reuse=$(sha256sum ../resource/kernel/rs_sentinel_reuse|cut -c1-8) filter=$(sha256sum ../communication/combo/c_filter_hs_gate_excl.bpf.o|cut -c1-8) driver=$(sha256sum ../tests/reqJ/chap_memapi_test.so|cut -c1-8)" >> $P
run(){ name=$1; shift; rm -f /sys/fs/bpf/chap/* 2>/dev/null; echo "$(date +%T) START $name" >> $P
  "$@" > /tmp/runJd_$name.log 2>&1
  echo "$(date +%T) END $name rundir=$(ls -dt /var/tmp/chap_3pu_* | head -1) $(grep -a OVERALL /tmp/runJd_$name.log | head -1)" >> $P; sleep 3; }
[ -n "$OLD" ] && run forge_oldobj env MEMJ=forge RES_PASS=1 RS_OBJ=$OLD bash run_3plane_F.sh
run agent env MEMJ=agent "RESPOL_EXTRA=mem.rate=50 mem.burst=600" bash run_3plane_F.sh
run kill env MEMJ=kill RES_PASS=1 bash run_3plane_F.sh
run race env MEMJ=race RES_PASS=1 bash run_3plane_F.sh
run combined env RESAPI=1 RESP=1 WILD=1 UNCLASS_TEST=1 bash run_3plane_F.sh
run rx_vec1 env RX_TEST=1 RXVEC=1 bash run_3plane_F.sh
run tx env TX_TEST=1 bash run_3plane_F.sh
run hl env HARD=3 bash run_3plane_F_hl.sh
cd $CHAP_ROOT/resource/kernel && ./rs_concurrency_test resource_sentinel.bpf.o ./libstub_flow.so 1100 1110 atomic 200000 2 3 > $CHAP_ROOT/tests/reqJ/conc_atomic_reqJ2.log 2>&1; echo "$(date +%T) conc rc=$? $(grep RESULT $CHAP_ROOT/tests/reqJ/conc_atomic_reqJ2.log)" >> $P
echo ALL_DONE >> $P

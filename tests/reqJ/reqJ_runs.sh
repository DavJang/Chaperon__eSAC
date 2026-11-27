#!/bin/bash
# Request J closing chain on ONE build. Progress: $P ; logs /tmp/runJc_<name>.log
CHAP_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); [ -f "$CHAP_ROOT/manager/chap_env.sh" ] && . "$CHAP_ROOT/manager/chap_env.sh"   # repository root + host-local paths
cd $CHAP_ROOT/manager
P=$CHAP_ROOT/tests/reqJ/reqJ_runs.progress; : > $P
echo "VERSION agent=$(sha256sum $CHAP_RUNTIME_DIR/libbpftime-agent.so|cut -c1-8) r_precheck=$(sha256sum ../resource/agent/r_precheck_agent.bpf.o|cut -c1-8) rsentinel=$(sha256sum ../resource/kernel/resource_sentinel.bpf.o|cut -c1-8) reuse=$(sha256sum ../resource/kernel/rs_sentinel_reuse|cut -c1-8) filter=$(sha256sum ../communication/combo/c_filter_hs_gate_excl.bpf.o|cut -c1-8)" >> $P
run(){ h=$1; shift; spec="$*"; name=$(echo "$h $spec" | tr " =/\"" "____" | cut -c1-120); rm -f /sys/fs/bpf/chap/* 2>/dev/null
  echo "$(date +%T) START $h $spec" >> $P
  env $spec bash $h > /tmp/runJc_$name.log 2>&1
  echo "$(date +%T) END $h $spec rundir=$(ls -dt /var/tmp/chap_3pu_* | head -1) $(grep -a OVERALL /tmp/runJc_$name.log | head -1)" >> $P; sleep 3; }
python3 -I make_F_hl.py >> $P 2>&1
run run_3plane_F.sh MEMJ=kill RES_PASS=1
run run_3plane_F.sh MEMJ=race RES_PASS=1
run run_3plane_F.sh RESAPI=1 RESP=1 WILD=1 UNCLASS_TEST=1
run run_3plane_F.sh RX_TEST=1
run run_3plane_F.sh TX_TEST=1
run run_3plane_F.sh PROGFN_ATK=1
run run_3plane_F.sh TAMPER=1 TAMPER_TARGET=agentcode
run run_3plane_F_hl.sh HARD=3
run run_3plane_F.sh RXSLOT_PROBE=1 RXVEC=1
run run_3plane_F.sh RXSLOT_PROBE=1 RXVEC=0
cd $CHAP_ROOT/resource/kernel && ./rs_concurrency_test resource_sentinel.bpf.o ./libstub_flow.so 1100 1110 atomic 200000 2 3 > $CHAP_ROOT/tests/reqJ/conc_atomic_reqJ.log 2>&1; echo "$(date +%T) conc rc=$? $(grep RESULT $CHAP_ROOT/tests/reqJ/conc_atomic_reqJ.log)" >> $P
echo ALL_DONE >> $P

#!/bin/bash
# Request I final regression chain on ONE build (see VERSION line). Progress: $P ; per-run logs /tmp/runI_<name>.log
CHAP_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); [ -f "$CHAP_ROOT/manager/chap_env.sh" ] && . "$CHAP_ROOT/manager/chap_env.sh"   # repository root + host-local paths
cd $CHAP_ROOT/manager
P=$CHAP_ROOT/tests/reqI/reqI_runs.progress; : > $P
echo "VERSION agent=$(sha256sum $CHAP_RUNTIME_DIR/libbpftime-agent.so|cut -c1-8) filter=$(sha256sum ../communication/combo/c_filter_hs_gate_excl.bpf.o|cut -c1-8) hsprov=$(sha256sum ../communication/esac_hs_fullscan_enforce.chap.so|cut -c1-8) loader=$(sha256sum chaperon_loader|cut -c1-8) r_precheck=$(sha256sum ../resource/agent/r_precheck_agent.bpf.o|cut -c1-8) rsentinel=$(sha256sum ../resource/kernel/resource_sentinel.bpf.o|cut -c1-8) integ=$(sha256sum ../integrity/kernel/integrity_sentinel.bpf.o|cut -c1-8)" >> $P
run(){ h=$1; shift; spec="$*"; name=$(echo "$h $spec" | tr " =/" "___" | cut -c1-120); rm -f /sys/fs/bpf/chap/* 2>/dev/null
  echo "$(date +%T) START $h $spec" >> $P
  env $spec bash $h > /tmp/runI_$name.log 2>&1
  echo "$(date +%T) END $h $spec rundir=$(ls -dt /var/tmp/chap_3pu_* | head -1) $(grep -a OVERALL /tmp/runI_$name.log | head -1)" >> $P; sleep 3; }
python3 -I make_F_hl.py >> $P 2>&1
run run_3plane_F.sh RESAPI=1 RESP=1 WILD=1 UNCLASS_TEST=1
run run_3plane_F.sh RX_TEST=1
run run_3plane_F.sh TX_TEST=1
run run_3plane_F.sh FAIL_INJECT=rx_window_fail
run run_3plane_F.sh PROGFN_ATK=1
run run_3plane_F.sh DISPATCH_ATK=1
run run_3plane_F.sh ALIAS=1
run run_3plane_F.sh RATE=1
run run_3plane_F.sh TAMPER=1 SEAL_VERIFY=1
run run_3plane_F.sh TAMPER=1 TAMPER_TARGET=dispatch
run run_3plane_F.sh TAMPER=1 TAMPER_TARGET=selector
run run_3plane_F.sh TAMPER=1 TAMPER_TARGET=agentcode
run run_3plane_F.sh TAMPER=1 TAMPER_TARGET=jit
run run_3plane_F.sh FAIL_INJECT=range_drop
run run_3plane_F.sh FAIL_INJECT=dispatch_unsealed
run run_3plane_F.sh FAIL_INJECT=view_unsealed
run run_3plane_F.sh FAIL_INJECT=broker_miss
run run_3plane_F.sh FAIL_INJECT=l7_badpatterns
run run_3plane_F_hl.sh HARD=3
echo ALL_DONE >> $P

#!/bin/bash
# Chaperon Request I: two tenants with DIFFERENT communication and resource policies on one host, each
# under the full gated launch (run_3plane_F.sh in MT mode), then cross-tenant checks by the Manager:
#   C1 comm policy independence   C2 resource usage independence   C3 live update independence
#   C4 root-only policy write + FREEZE of usage   C5 no FD reissue   C6 tamper isolation (cgroup scope)
#   C7 cleanup of both tenants (processes, cgroups, pins, GO tokens)
# Run as root. Output: $OUT/TWO_TENANT.tsv + both harness logs.
CHAP_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); [ -f "$CHAP_ROOT/manager/chap_env.sh" ] && . "$CHAP_ROOT/manager/chap_env.sh"   # repository root + host-local paths
set -u
MG=$CHAP_ROOT/manager; T=$CHAP_ROOT/tests/reqI; IK=$CHAP_ROOT/integrity/kernel
RPOL=$CHAP_ROOT/resource/manager/chap_res_policy; GEN=${CHAP_GEN:-$CHAP_ROOT/tests/gen/esac_l47gen}
DPDKLIB=${CHAP_DPDK_LIBDIR:-}
OUT=$T/two_tenant_$(date +%Y%m%d_%H%M%S); mkdir -p $OUT; R=$OUT/TWO_TENANT.tsv; : > $R
res(){ printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> $R; echo "[2t] $1 $2 $3"; }
eval "$(bash $T/reqI_fabric3.sh 2>&1 | tee $OUT/fabric.txt | grep -E '^(VF_A|VF_B|VF_G|MAC_A|MAC_B)=')"
grep FABRIC $OUT/fabric.txt
rm -rf /sys/fs/bpf/chapA /sys/fs/bpf/chapB 2>/dev/null
# tenant A: flow quota 3, comm allows udp 1111->2222 ; tenant B: flow quota 1 + mc_addr budget 1, comm allows udp 3333->4444
( cd $MG && env RUN_ID=mtA_$$ PIND=/sys/fs/bpf/chapA TLC=6,7 TCPUS=6-7 MT_SVF=$VF_A MT_CVF=$VF_G SVFMAC=$MAC_A MT_HOLD=1 HARD=3 \
    bash run_3plane_F.sh > $OUT/A.log 2>&1 ) &
for i in $(seq 1 120); do [ -e /var/tmp/chap_3pu_mtA_$$/run/HOLD_READY ] && break; grep -qa OVERALL $OUT/A.log && break; sleep 2; done
( cd $MG && env RUN_ID=mtB_$$ PIND=/sys/fs/bpf/chapB TLC=4,5 TCPUS=4-5 MT_SVF=$VF_B MT_CVF=$VF_G SVFMAC=$MAC_B MT_HOLD=1 HARD=1 RESPOL_EXTRA=mc_addr.budget=1 \
    bash run_3plane_F.sh > $OUT/B.log 2>&1 ) &
for i in $(seq 1 120); do [ -e /var/tmp/chap_3pu_mtB_$$/run/HOLD_READY ] && break; grep -qa OVERALL $OUT/B.log && break; sleep 2; done
OA=/var/tmp/chap_3pu_mtA_$$/run; OB=/var/tmp/chap_3pu_mtB_$$/run
if [ ! -e $OA/HOLD_READY ] || [ ! -e $OB/HOLD_READY ]; then
  res launch_both FAIL "A_ready=$( [ -e $OA/HOLD_READY ] && echo y || echo n) B_ready=$( [ -e $OB/HOLD_READY ] && echo y || echo n)"
  touch $OA/HOLD_CONTINUE $OB/HOLD_CONTINUE 2>/dev/null; wait; exit 1; fi
eval "$(sed 's/^/A_/' $OA/tenant.env)"; eval "$(sed 's/^/B_/' $OB/tenant.env)"
res launch_both PASS "A pid=$A_TPID cg=$A_CGID maps comm=$A_CKID usage=$A_UID_ policy=$A_PID_ lcores=$A_TLC | B pid=$B_TPID cg=$B_CGID maps comm=$B_CKID usage=$B_UID_ policy=$B_PID_ lcores=$B_TLC (each: full gated launch, all REQUIRED checks up to GO PASS)"
tp(){ echo "$2" > $1/cmd; sleep ${3:-1}; }
rxp(){ kill -USR1 $1 2>/dev/null; sleep 1; grep -aE "^0 +0 +[0-9]" $2/loader.log | tail -1; }
gen(){ env LD_LIBRARY_PATH=$DPDKLIB timeout 12 $GEN -l 8,9 -n4 --in-memory --socket-mem 1024,0 -a $VF_G --file-prefix=gmt$$ -- 2000 $1 10.0.0.1 10.0.0.2 $2 $3 udp none > $OUT/gen.log 2>&1; }
# one traffic probe: deltas (allow drop) on A and B
probe(){ local a0 b0 a1 b1; a0=$(rxp $A_LPID $A_O); b0=$(rxp $B_LPID $B_O); gen $1 $2 $3; sleep 2; a1=$(rxp $A_LPID $A_O); b1=$(rxp $B_LPID $B_O)
  echo "$(( $(echo $a1|awk '{print $6}') - $(echo $a0|awk '{print $6}') )) $(( $(echo $a1|awk '{print $5}') - $(echo $a0|awk '{print $5}') )) $(( $(echo $b1|awk '{print $6}') - $(echo $b0|awk '{print $6}') )) $(( $(echo $b1|awk '{print $5}') - $(echo $b0|awk '{print $5}') ))"; }
usage(){ kill -USR1 $1 2>/dev/null; sleep 1; grep -a "USAGE api_calls" $2/rsent.log | tail -1; }
fv(){ echo "$1" | grep -oE "(^| )$2=[0-9]+" | head -1 | cut -d= -f2; }
for t in A B; do eval "W_=\$${t}_W"; tp $W_ "set fwd rxonly"; tp $W_ "start" 2; done
$A_W/policy_flip $A_CKID 16384 $A_CGID 10.0.0.1 10.0.0.2 1111 2222 17 0 >> $OUT/flip.log 2>&1
$B_W/policy_flip $B_CKID 16384 $B_CGID 10.0.0.1 10.0.0.2 3333 4444 17 0 >> $OUT/flip.log 2>&1; sleep 1

# ---- C1: each tenant enforces only its own communication policy; traffic to one never moves the other's counters
read -r a1 d1 ba1 bd1 <<< "$(probe $MAC_A 1111 2222)"; read -r a2 d2 ba2 bd2 <<< "$(probe $MAC_A 3333 4444)"
read -r xa1 xd1 b1a b1d <<< "$(probe $MAC_B 3333 4444)"; read -r xa2 xd2 b2a b2d <<< "$(probe $MAC_B 1111 2222)"
echo "C1 A<-t1: A allow=$a1 drop=$d1 (B $ba1/$bd1) | A<-t2: A allow=$a2 drop=$d2 (B $ba2/$bd2) | B<-t2: B allow=$b1a drop=$b1d (A $xa1/$xd1) | B<-t1: B allow=$b2a drop=$b2d (A $xa2/$xd2)" >> $OUT/detail.txt
{ [ $a1 -ge 1900 ] && [ $d2 -ge 1900 ] && [ $a2 -le 100 ] && [ $b1a -ge 1900 ] && [ $b2d -ge 1900 ] && [ $b2a -le 100 ] && [ $((ba1+bd1+ba2+bd2)) -le 10 ] && [ $((xa1+xd1+xa2+xd2)) -le 10 ]; } \
  && res C1_comm_policy_independent PASS "$(tail -1 $OUT/detail.txt)" || res C1_comm_policy_independent FAIL "$(tail -1 $OUT/detail.txt)"

# ---- C2: resource usage is per tenant (A quota 3, B quota 1)
for i in 1 2 3 4 5; do tp $A_W "flow create 0 ingress pattern eth / end actions drop / end" 0.4; done
UA1=$(usage $A_SPID $A_O); UB0=$(usage $B_SPID $B_O)
for i in 1 2 3; do tp $B_W "flow create 0 ingress pattern eth / end actions drop / end" 0.4; done
UA2=$(usage $A_SPID $A_O); UB1=$(usage $B_SPID $B_O)
echo "C2 A after 5 creates: $UA1 | B before: $UB0 | B after 3 creates: $UB1 | A after B's creates: $UA2" >> $OUT/detail.txt
{ [ "$(fv "$UA1" api_calls)" = 3 ] && [ "$(fv "$UB0" api_calls)" = 0 ] && [ "$(fv "$UB1" api_calls)" = 1 ] && [ "$(fv "$UA2" api_calls)" = 3 ]; } \
  && res C2_resource_usage_independent PASS "A 5 creates -> 3 (quota 3); B 3 creates -> 1 (quota 1); A unchanged by B (3); separate usage maps $A_UID_/$B_UID_" \
  || res C2_resource_usage_independent FAIL "$(tail -1 $OUT/detail.txt)"

# ---- C3: live policy updates of one tenant do not touch the other
$RPOL $A_PIND/resource_policy 0 hard_flows=5 > $OUT/livepol.txt 2>&1
for i in 1 2 3; do tp $A_W "flow create 0 ingress pattern eth / end actions drop / end" 0.4; done
for i in 1 2; do tp $B_W "flow create 0 ingress pattern eth / end actions drop / end" 0.4; done
UA3=$(usage $A_SPID $A_O); UB2=$(usage $B_SPID $B_O)
tp $A_W "flow flush 0" 2; tp $B_W "flow flush 0" 2
$A_W/policy_flip $A_CKID 16384 $A_CGID 10.0.0.1 10.0.0.2 1111 2222 17 2 >> $OUT/flip.log 2>&1; sleep 1
read -r la1 ld1 lb1 lbd1 <<< "$(probe $MAC_A 1111 2222)"; read -r lxa lxd lb2 lbd2 <<< "$(probe $MAC_B 3333 4444)"
echo "C3 A hard_flows 3->5: $UA3 | B (unchanged quota 1): $UB2 | comm: A t1 flipped to DROP -> A allow=$la1 drop=$ld1 ; B t2 -> B allow=$lb2 drop=$lbd2" >> $OUT/detail.txt
{ [ "$(fv "$UA3" api_calls)" = 5 ] && [ "$(fv "$UB2" api_calls)" = 1 ] && [ $ld1 -ge 1900 ] && [ $la1 -le 100 ] && [ $lb2 -ge 1900 ]; } \
  && res C3_live_update_independent PASS "A resource policy 3->5 flows: A 5, B still 1; A comm rule flipped to DROP: A drop+=$ld1, B (own rule) allow+=$lb2" \
  || res C3_live_update_independent FAIL "$(tail -1 $OUT/detail.txt)"

# ---- C4: policy writes are root-only; usage is FROZEN (even root cannot write it)
TU=$(awk '/^Uid:/{print $2}' /proc/$A_TPID/status)
W1=$(sudo -u "#$TU" $RPOL $A_PIND/resource_policy 0 hard_flows=99 2>&1 | tail -1)
W2=$(sudo -u "#$TU" bpftool map update id $A_PID_ key hex 00 00 00 00 value hex $(printf '00 %.0s' $(seq 1 $(( (3+2+2+2+2+16)*8 )))) 2>&1 | tail -1)
ZU=$(printf '00 %.0s' $(seq 1 240))
W3=$(bpftool map update id $A_UID_ key hex 00 00 00 00 value hex $ZU 2>&1 | tail -1)
PA=$($RPOL $A_PIND/resource_policy 0 2>&1 | tail -1)
echo "C4 tenant uid=$TU policy write via pin: '$W1' | via map id: '$W2' | root write to usage: '$W3' | policy now: $PA" >> $OUT/detail.txt
{ echo "$W1" | grep -qiE "denied|not permitted" && echo "$W2" | grep -qiE "denied|not permitted" && echo "$W3" | grep -qiE "not permitted|denied|busy" && echo "$PA" | grep -q "hard_flows=5 "; } \
  && res C4_root_only_policy_and_frozen_usage PASS "$(tail -1 $OUT/detail.txt)" || res C4_root_only_policy_and_frozen_usage FAIL "$(tail -1 $OUT/detail.txt)"

# ---- C5: no FD reissue: each broker served its tenant once and exited; a later request is refused
BA=$(grep -a "served .* request(s); exiting" $A_O/broker.log | tail -1); BB=$(grep -a "served .* request(s); exiting" $B_O/broker.log | tail -1)
CN=$(sudo -u "#$TU" python3 -I -c "import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
try:
  s.connect(sys.argv[1]); print('CONNECTED')
except Exception as e: print('REFUSED', type(e).__name__)" $A_SOCK 2>&1)
FDA=$(ls -l /proc/$A_TPID/fd 2>/dev/null | grep -c bpf-map); FDB=$(ls -l /proc/$B_TPID/fd 2>/dev/null | grep -c bpf-map)
echo "C5 A broker: '$BA' | B broker: '$BB' | later request to A's broker: $CN | tenant bpf-map fds A=$FDA B=$FDB" >> $OUT/detail.txt
{ [ -n "$BA" ] && [ -n "$BB" ] && echo "$CN" | grep -q REFUSED && [ "$FDA" = 0 ] && [ "$FDB" = 0 ]; } \
  && res C5_no_fd_reissue PASS "$(tail -1 $OUT/detail.txt)" || res C5_no_fd_reissue FAIL "$(tail -1 $OUT/detail.txt)"

# ---- C6: tamper isolation: a process in A's cgroup is killed for touching A's protected page; the same attempt
#      outside any protected cgroup is not; tenant B (and A) keep running
HK=$(head -1 $A_O/sealed_ranges.txt | awk '{print $1}')
VA0=$(grep -ac "VIOLATION\|KILL" $A_O/integ.log); VB0=$(grep -ac "VIOLATION\|KILL" $B_O/integ.log)
$IK/tamper_child $A_CGDIR/cgroup.procs $HK > $OUT/tamper_A.txt 2>&1; TRC=$?
mkdir -p /sys/fs/cgroup/chap_mt_ctl_$$; $IK/tamper_child /sys/fs/cgroup/chap_mt_ctl_$$/cgroup.procs $HK > $OUT/tamper_ctl.txt 2>&1; CRC=$?; rmdir /sys/fs/cgroup/chap_mt_ctl_$$ 2>/dev/null
sleep 1; VA1=$(grep -ac "VIOLATION\|KILL" $A_O/integ.log); VB1=$(grep -ac "VIOLATION\|KILL" $B_O/integ.log)
AA=$(kill -0 $A_TPID 2>/dev/null && echo YES || echo NO); AB=$(kill -0 $B_TPID 2>/dev/null && echo YES || echo NO)
read -r ta tdd tb tbd <<< "$(probe $MAC_B 3333 4444)"
echo "C6 tamper in A's cgroup at $HK: rc=$TRC ($(cat $OUT/tamper_A.txt | tr '\n' ' ')) | same outside protected cgroups: rc=$CRC ($(cat $OUT/tamper_ctl.txt | tr '\n' ' ')) | (integ_sentinel_run logs no per-event line; the SIGKILL is the evidence) | A alive=$AA B alive=$AB, B traffic allow+=$tb" >> $OUT/detail.txt
{ [ $TRC -gt 128 ] && grep -q TAMPER_SURVIVED $OUT/tamper_ctl.txt && [ "$AA" = YES ] && [ "$AB" = YES ] && [ $tb -ge 1900 ]; } \
  && res C6_tamper_isolation PASS "$(tail -1 $OUT/detail.txt)" || res C6_tamper_isolation FAIL "$(tail -1 $OUT/detail.txt)"

# ---- C7: both tenants exit and leave nothing behind
touch $OA/HOLD_CONTINUE $OB/HOLD_CONTINUE; wait
sleep 2
LEFT=""; for p in $A_TPID $A_LPID $A_SPID $A_IPID $B_TPID $B_LPID $B_SPID $B_IPID; do kill -0 $p 2>/dev/null && LEFT="$LEFT $p"; done
PINS=$(find /sys/fs/bpf/chapA /sys/fs/bpf/chapB -mindepth 1 2>/dev/null | wc -l); CGS=$(ls -d /sys/fs/cgroup/chap_3pu_mtA_$$ /sys/fs/cgroup/chap_3pu_mtB_$$ 2>/dev/null | wc -l)
GOS=$(ls /var/lib/chap_gate/go_$A_TPID /var/lib/chap_gate/go_$B_TPID 2>/dev/null | wc -l); SHMS=$(ls /dev/shm 2>/dev/null | grep -c "chap3pu")
echo "C7 leftover processes='$LEFT' pins=$PINS cgroups=$CGS go_tokens=$GOS shm=$SHMS ; A: $(grep -a OVERALL $OUT/A.log | tail -1) ; B: $(grep -a OVERALL $OUT/B.log | tail -1)" >> $OUT/detail.txt
{ [ -z "$LEFT" ] && [ "$PINS" = 0 ] && [ "$CGS" = 0 ] && [ "$GOS" = 0 ] && grep -qa "OVERALL: PASS" $OUT/A.log && grep -qa "OVERALL: PASS" $OUT/B.log; } \
  && res C7_cleanup_both PASS "$(tail -1 $OUT/detail.txt)" || res C7_cleanup_both FAIL "$(tail -1 $OUT/detail.txt)"
cp $OA/CHECKS.tsv $OUT/A_CHECKS.tsv 2>/dev/null; cp $OB/CHECKS.tsv $OUT/B_CHECKS.tsv 2>/dev/null
echo 0 > /sys/bus/pci/devices/0000:3b:00.1/sriov_numvfs 2>/dev/null   # the single-tenant fabric is rebuilt by the next harness run
echo "TWO_TENANT_DONE $OUT"

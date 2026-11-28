#!/bin/bash
# Chaperon Request P -- kernel-level test of the sealed-process registry and NIC gate on the REAL kernel and the REAL
# mlx5 RDMA device (no DPDK). A test cgroup is protected by its own Sentinel instance; probes run as the tenant uid
# with the tenant's ambient capabilities (amblaunch). Independent witness: kprobes on the uverbs HANDLERS
# (ib_uverbs_open/ioctl/mmap/write) show whether a call reached the RDMA command interface at all.
set -u
B=${B:-/home/sungwoo/chaperon_reqP}; IK=$B/integrity/kernel; NP=$B/tests/reqP/nicprobe; AMB=$B/manager/tools/amblaunch
IBDEV=${IBDEV:-rocep59s0f1v0}
R=${R:-/home/sungwoo/chaperon_results/reqP_20261128/unit}; mkdir -p $R; cd $R
CG=/sys/fs/cgroup/reqp_unit_$$; mkdir $CG; CGID=$(stat -c %i $CG)
PIND=/sys/fs/bpf/chap_reqp_unit_$$; mkdir -p $PIND
RES=$R/UNIT_RESULT.txt; : > $RES
say(){ echo "$*" | tee -a $RES; }
judge(){ local n=$1 ok=$2; shift 2; say "TEST $n $( [ "$ok" = 1 ] && echo PASS || echo FAIL ) :: $*"; }
cleanup(){ kill $BT $SP 2>/dev/null; sleep 1; rm -f $PIND/*; rmdir $PIND $CG 2>/dev/null; }
trap cleanup EXIT
$IK/integ_sentinel_run $IK/integrity_sentinel.bpf.o $CGID $PIND > integ.log 2>&1 & SP=$!
for i in $(seq 1 20); do grep -q READY integ.log && break; sleep 0.5; done
say "SENTINEL $(grep -o 'NICGATE attached=[0-9/]*' integ.log) $(grep -c READY integ.log) READY; obj=$(sha256sum $IK/integrity_sentinel.bpf.o | cut -c1-8)"
$IK/chap_nicgate cfg $PIND on > cfg.log 2>&1; say "$(cat cfg.log)"
printf 'kprobe:ib_uverbs_open,kprobe:ib_uverbs_ioctl,kprobe:ib_uverbs_mmap,kprobe:ib_uverbs_write /comm == "nicprobe"/ { printf("%%llu %%s pid=%%d\\n", nsecs, func, pid); }\ntracepoint:sched:sched_process_exec /comm == "nicprobe"/ { printf("%%llu EXEC pid=%%d\\n", nsecs, pid); }\n' > uv.bt
bpftrace uv.bt > uv_trace.txt 2>&1 & BT=$!
for i in $(seq 1 40); do grep -q Attaching uv_trace.txt && break; sleep 0.5; done; sleep 1
dump(){ $IK/chap_nicgate dump $PIND; }
handler_calls(){ grep -c " $2 pid=$1\$" uv_trace.txt; }                       # $1 pid  $2 ib_uverbs_*
after_exec(){ local p=$1 f=$2 t; t=$(grep "EXEC pid=$p$" uv_trace.txt | tail -1 | awk '{print $1}');   # LAST exec (the first is the launch into nicprobe) [ -z "$t" ] && { echo NA; return; }
  awk -v t=$t -v p="pid=$p" -v f=$f '$1>t && $2==f && $3==p' uv_trace.txt | wc -l; }
incg(){ bash -c "echo \$\$ > $CG/cgroup.procs; exec $AMB $NP $IBDEV $*"; }   # tenant uid + caps, inside the cgroup

# T1 scope: a process OUTSIDE the protected cgroup is not affected
$AMB $NP $IBDEV open close > t1.out 2>&1; R1=$?
judge T1_outside_cgroup_unaffected $( grep -q "OPEN RESULT ok" t1.out && [ $R1 = 0 ] && echo 1 || echo 0 ) "rc=$R1 $(tr '\n' ' ' < t1.out | cut -c1-160)"

# T2 unsealed tenant process: open denied before the handler + SIGKILL
incg open > t2.out 2>&1; R2=$?; P2=$(grep -oE "begin pid=[0-9]+" t2.out | grep -oE "[0-9]+" | head -1)
judge T2_unsealed_open_blocked $( [ $R2 = 137 ] && ! grep -q "open_device ok" t2.out && [ "$(handler_calls $P2 ib_uverbs_open)" = 0 ] && echo 1 || echo 0 ) \
  "rc=$R2 (137=SIGKILL) last=[$(tail -1 t2.out)] ib_uverbs_open_calls(pid $P2)=$(handler_calls $P2 ib_uverbs_open) $(dump | tail -1)"

# T3 sealed lifecycle: Manager registers -> NIC allowed; fork child inherits; failed exec keeps; exec removes -> inherited fd ioctl blocked
mkfifo f3; incg wait open close forkopen 4 execfail open close fdopen exec $NP $IBDEV fdioctl 50 < f3 > t3.out 2>&1 & J3=$!
exec 7>f3; for i in $(seq 1 40); do grep -q "WAIT pid=" t3.out && break; sleep 0.25; done
P3=$(grep -oE "WAIT pid=[0-9]+" t3.out | grep -oE "[0-9]+" | head -1); $IK/chap_nicgate seal $PIND $P3 > t3_seal.txt 2>&1
D0=$(dump | grep "ENTRY pid=$P3 "); echo go >&7
for i in $(seq 1 40); do grep -q "CHILD pid=" t3.out && break; sleep 0.25; done; sleep 1.5
C3=$(grep -oE "CHILD pid=[0-9]+" t3.out | grep -oE "[0-9]+" | head -1); DC=$(dump | grep "ENTRY pid=$C3 ")
INH=$(python3 -I -c "
import sys
def maps(p): return [l.split()[0]+' '+l.split()[1] for l in open('/proc/%s/maps'%p) if len(l.split())>5]
try: a=set(maps($P3)); b=set(maps($C3)); print('parent_maps=%d child_maps=%d parent_subset_of_child=%s'%(len(a),len(b),a<=b))
except Exception as e: print('maps_err',e)")
wait $J3; R3=$?; exec 7>&-
sleep 0.5; DA=$(dump)
OKS=$(grep -c "OPEN RESULT ok" t3.out)
judge T3a_sealed_registered_allowed $( [ -n "$D0" ] && [ "$(handler_calls $P3 ib_uverbs_open)" -ge 2 ] && grep -q "SEALED pid=$P3" t3_seal.txt && echo 1 || echo 0 ) \
  "$(cat t3_seal.txt) entry=[$D0] OPEN_ok_lines=$OKS ib_uverbs_open/ioctl/mmap(pid $P3)=$(handler_calls $P3 ib_uverbs_open)/$(handler_calls $P3 ib_uverbs_ioctl)/$(handler_calls $P3 ib_uverbs_mmap)"
judge T3b_fork_child_inherits $( echo "$DC" | grep -q "origin=2 parent=$P3" && grep -q "FORKOPEN child=$C3 EXIT 0" t3.out && echo "$INH" | grep -q "parent_subset_of_child=True" && echo 1 || echo 0 ) \
  "child entry=[$DC] $(grep FORKOPEN t3.out) child_handler_open=$(handler_calls $C3 ib_uverbs_open) $INH"
judge T3c_failed_exec_keeps_status $( grep -q "EXECFAIL /nonexistent" t3.out && [ "$OKS" -ge 3 ] && echo 1 || echo 0 ) "$(grep EXECFAIL t3.out) ; open after failed exec ok=$([ $OKS -ge 3 ] && echo yes || echo no)"
judge T3d_exec_unseals_inherited_fd_blocked $( [ $R3 = 137 ] && grep -q "FDIOCTL begin fd=50" t3.out && ! grep -q "FDIOCTL ret" t3.out && [ "$(after_exec $P3 ib_uverbs_ioctl)" = 0 ] && echo 1 || echo 0 ) \
  "rc=$R3 last=[$(tail -1 t3.out)] ib_uverbs_ioctl_after_exec=$(after_exec $P3 ib_uverbs_ioctl)"
judge T3e_exit_and_exec_clear_entries $( ! echo "$DA" | grep -qE "ENTRY pid=($P3|$C3) " && echo 1 || echo 0 ) "$(echo "$DA" | tail -1)"

# T4/T5 inherited fd after exec: mmap and legacy write
for M in fdmmap fdwrite; do
  mkfifo f_$M; incg wait fdopen exec $NP $IBDEV $M 50 < f_$M > t_$M.out 2>&1 & J=$!; exec 7>f_$M
  for i in $(seq 1 40); do grep -q "WAIT pid=" t_$M.out && break; sleep 0.25; done
  PM=$(grep -oE "WAIT pid=[0-9]+" t_$M.out | grep -oE "[0-9]+" | head -1); $IK/chap_nicgate seal $PIND $PM > /dev/null; echo go >&7; wait $J; RM=$?; exec 7>&-
  H=$([ $M = fdmmap ] && echo ib_uverbs_mmap || echo ib_uverbs_write)
  judge T_${M}_inherited_fd_after_exec_blocked $( [ $RM = 137 ] && ! grep -qE "FDMMAP ret|FDWRITE ret" t_$M.out && [ "$(after_exec $PM $H)" = 0 ] && echo 1 || echo 0 ) \
    "rc=$RM last=[$(tail -1 t_$M.out)] ${H}_after_exec=$(after_exec $PM $H)"
done

# T6 fd passed via SCM_RIGHTS from a sealed process to an unsealed one
mkfifo f6; incg wait sockpair fdopenclo sendfd 60 50 forkexec $NP $IBDEV recvfd 61 fdioctl 51 < f6 > t6.out 2>&1 & J6=$!; exec 7>f6
for i in $(seq 1 40); do grep -q "WAIT pid=" t6.out && break; sleep 0.25; done
P6=$(grep -oE "WAIT pid=[0-9]+" t6.out | grep -oE "[0-9]+" | head -1); $IK/chap_nicgate seal $PIND $P6 > /dev/null; echo go >&7; wait $J6; exec 7>&-
C6=$(grep -oE "FORKEXEC child=[0-9]+" t6.out | grep -oE "[0-9]+" | head -1)
judge T6_scm_rights_passed_fd_blocked $( grep -q "FORKEXEC child=$C6 SIGNAL 9" t6.out && grep -q "RECVFD sock=61 fd=51" t6.out && [ "$(handler_calls $C6 ib_uverbs_ioctl)" = 0 ] && echo 1 || echo 0 ) \
  "$(grep -E 'RECVFD|FDIOCTL|FORKEXEC child=[0-9]+ (SIGNAL|EXIT)' t6.out | tr '\n' ' ') child_ib_uverbs_ioctl=$(handler_calls $C6 ib_uverbs_ioctl)"

# T7 the tenant cannot register itself (no bpf()/bpffs access)
B7=$(dump | head -1); incg forge $PIND > t7.out 2>&1; A7=$(dump | head -1)
judge T7_tenant_cannot_forge_registration $( grep -q "obj_get.*ret=-1" t7.out && grep -q "map_get_fd_by_id ret=-1" t7.out && grep -q "open(pin) ret=-1" t7.out && echo 1 || echo 0 ) \
  "$(grep FORGE t7.out | tr '\n' ' ') map_before=[$B7] after=[$A7]"

# T8 stale identity (a reused PID): entry with another start time must not authorize the new process
mkfifo f8; incg wait open < f8 > t8.out 2>&1 & J8=$!; exec 7>f8
for i in $(seq 1 40); do grep -q "WAIT pid=" t8.out && break; sleep 0.25; done
P8=$(grep -oE "WAIT pid=[0-9]+" t8.out | grep -oE "[0-9]+" | head -1); $IK/chap_nicgate put $PIND $P8 1 > t8_put.txt 2>&1; S0=$(dump | tail -1)
echo go >&7; wait $J8; R8=$?; exec 7>&-; S1=$(dump | tail -1)
judge T8_reused_pid_stale_entry_rejected $( [ $R8 = 137 ] && ! dump | grep -q "ENTRY pid=$P8 " && [ "$(handler_calls $P8 ib_uverbs_open)" = 0 ] && echo 1 || echo 0 ) \
  "$(cat t8_put.txt) rc=$R8 ib_uverbs_open=$(handler_calls $P8 ib_uverbs_open) before=[$S0] after=[$S1]"
say "FINAL $(dump | tail -1)"
say "UNIT SUMMARY: $(grep -c ' PASS ' $RES) PASS, $(grep -c ' FAIL ' $RES) FAIL"

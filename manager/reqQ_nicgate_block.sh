# Chaperon Request Q: tenant privileges, NIC paths outside the uverbs command interface, Sealed-Process lifecycle.
# Sourced by run_3plane_F.sh when NICQ is set (forwarding stopped). In-tenant actions are issued by the TEST-ONLY driver
# thread "chap-nicj" (chap_nicgate_test.so); unsealed processes are images exec'd by the tenant (clean environment) or
# processes that only join the tenant cgroup (cg_probe.py). Privilege checks use existing system binaries (sudo, ping)
# and the kernel's /proc status only. Witnesses: bpftrace kprobes on the uverbs handlers, tcpdump on the peer VF netdev.
NC=/tmp/chap_nicj_cmd_$TPID; NO=$W/tenant_cwd/nicj_out.txt; : > $NC; chmod 644 $NC
NP=$CHAP_ROOT/tests/reqP/nicprobe; CGP=$CHAP_ROOT/tests/reqP/cg_probe.py; NPP=$CHAP_ROOT/tests/reqQ/netpath_probe; TUID=$(id -u "$TUSER")
UVN=$(ls /sys/class/infiniband/$NICJ_IBDEV/device/infiniband_verbs/ 2>/dev/null | grep -m1 uverbs); UVD=/dev/infiniband/$UVN
CN=$(ls /sys/bus/pci/devices/$CVF/net/ 2>/dev/null | head -1); CMAC=$(cat /sys/class/net/$CN/address); CIB=$(ls /sys/bus/pci/devices/$CVF/infiniband/ 2>/dev/null | head -1)
SNQ=$( [ -n "$TNS" ] && ip netns exec $TNS ls /sys/class/net | grep -v '^lo$' | head -1 || ls /sys/bus/pci/devices/$SVF/net/ | head -1 )
SMACQ=$( [ -n "$TNS" ] && ip netns exec $TNS cat /sys/class/net/$SNQ/address || cat /sys/class/net/$SNQ/address )
QJ=$O/nicq.txt; : > $QJ; WT=$O/nicq_uverbs_trace.txt
say "===== Request Q NICQ=$NICQ: privileges, non-uverbs NIC paths, Sealed-Process lifecycle (tenant ibdev=$NICJ_IBDEV, other VF ibdev=$CIB) ====="
ngd(){ "$IK/chap_nicgate" dump "$PIND"; }
ngs(){ ngd | tail -1 | sed -E 's/allow\{/allow_/; s/\} deny\{/ deny_/; s/\}//' | awk '{p="";for(i=1;i<=NF;i++){t=$i; if(t ~ /^allow_/){p="allow_";sub(/^allow_/,"",t)} else if(t ~ /^deny_/){p="deny_";sub(/^deny_/,"",t)} else if(t ~ /^(entries|fork_inherit)/) p=""; printf "%s%s ", p, t} print ""}'; }
nv(){ local v; v=$(echo "$1" | grep -oE "(^| )$2=[0-9]+" | head -1 | sed 's/.*=//'); echo ${v:-0}; }
dl(){ echo $(( $(nv "$2" $3) - $(nv "$1" $3) )); }
alive(){ kill -0 $TPID 2>/dev/null && echo YES || echo NO; }
ndone(){ grep -ac "^DONE " $NO 2>/dev/null || echo 0; }
nrun(){ local n0; n0=$(ndone); echo "$1" >> $NC; for i in $(seq 1 ${2:-60}); do [ "$(ndone)" -gt "$n0" ] && break; kill -0 $TPID 2>/dev/null || break; sleep 0.5; done; }
nsend(){ echo "$1" >> $NC; }                                                   # asynchronous
hall(){ grep " pid=$1 " $WT 2>/dev/null | grep -c ib_uverbs; }
after_exec(){ local p=$1 t; t=$(grep "EXEC pid=$p " $WT | tail -1 | awk '{print $1}'); [ -z "$t" ] && { echo NA; return; }
  awk -v t=$t -v p="pid=$p" '$1>t && $3==p && $2 ~ /^ib_uverbs/' $WT | wc -l; }
clog(){ cat $W/tenant_cwd/nicj_child_$1.log 2>/dev/null | tr '\n' ' ' | cut -c1-${2:-300}; }
lastc(){ grep -a "^$1 child=[0-9]* \(EXIT\|SIGNAL\)" $NO | tail -1; }
cpid(){ echo "$1" | grep -oE "child=[0-9]+" | head -1 | cut -d= -f2; }
rec(){ echo "$*" >> $QJ; }
obs_on(){ timeout ${2:-40} tcpdump -i $CN -nn -A -l 2>/dev/null > $O/obs_$1.txt & OBS=$!; sleep 2; }
obs_off(){ sleep 2; kill $OBS 2>/dev/null; wait $OBS 2>/dev/null; }
pstat(){ awk '/^(Uid|NoNewPrivs|Seccomp|CapPrm|CapEff):/{printf "%s%s ", $1, $2}' /proc/$1/status 2>/dev/null; }

printf '%s\n' "kprobe:ib_uverbs_open,kprobe:ib_uverbs_ioctl,kprobe:ib_uverbs_mmap,kprobe:ib_uverbs_write { printf(\"%llu %s pid=%d tid=%d comm=%s cg=%llu\n\", nsecs, func, pid, tid, comm, cgroup); }" \
  "tracepoint:sched:sched_process_exec /cgroup == cgroupid(\"$CGDIR\")/ { printf(\"%llu EXEC pid=%d comm=%s\n\", nsecs, pid, comm); }" > $O/nicq_uv.bt
bpftrace $O/nicq_uv.bt > $WT 2>&1 & NBT=$!
for i in $(seq 1 60); do grep -q Attaching $WT && break; sleep 0.5; done; sleep 1

# ---------------- Q1 privileges: NO_NEW_PRIVS kept by fork/exec; setuid (sudo) and file capabilities (ping) give nothing
nsend "nnp_child 4"; for i in $(seq 1 20); do grep -qa "^NNPCHILD pid=" $NO && break; sleep 0.25; done; sleep 0.5
NC1=$(grep -a "^NNPCHILD pid=" $NO | tail -1 | grep -oE "[0-9]+$"); FK=$(pstat $NC1); for i in $(seq 1 30); do grep -qa "^NNPCHILD child=$NC1 " $NO && break; sleep 0.5; done
nrun "fork_exec /usr/bin/sudo -n /usr/bin/id -u" 60; SU=$(lastc FORK_EXEC); SUL=$(clog $(cpid "$SU") 250)
N0=$(grep -ac "^FORK_EXEC child=.* path=/usr/bin/ping" $NO); nsend "fork_exec /usr/bin/ping -c 4 -i 0.5 127.0.0.1"
for i in $(seq 1 40); do [ "$(grep -ac "^FORK_EXEC child=.* path=/usr/bin/ping" $NO)" -gt "$N0" ] && break; sleep 0.1; done; sleep 0.3
PGP=$(grep -a "^FORK_EXEC child=.* path=/usr/bin/ping" $NO | tail -1 | grep -oE "child=[0-9]+" | cut -d= -f2); PGS=$(pstat $PGP); PGF=$(getcap /usr/bin/ping)
for i in $(seq 1 30); do grep -qa "^FORK_EXEC child=$PGP " $NO && break; sleep 0.5; done
rec "Q1 tenant=[$TPRIV] fork_child=[$FK] sudo=[$SU log='$SUL'] ping_filecaps=[$PGF] ping_running=[$PGS]"
PCE=$(echo "$PGS" | grep -oE "CapEff:[0-9a-f]+" | cut -d: -f2)
( for k in "Uid:$TUID " "CapPrm:$TCAP " "CapEff:$TCAP " "NoNewPrivs:1 " "Seccomp:2 "; do echo "$FK" | grep -q "$k" || exit 1; done ) \
  && ! echo "$SU" | grep -q "EXIT 0" && ! echo "$SUL" | grep -qE "(^| )0( |$)" \
  && echo "$PGS" | grep -q "Uid:$TUID " && echo "$PGS" | grep -q "NoNewPrivs:1 " && echo "$PGS" | grep -q "Seccomp:2 " && [ -n "$PCE" ] && [ $(( 0x$PCE & ~0x$TCAP )) = 0 ] \
  && mark nicq_no_privilege_gain REQUIRED PASS "forked child: $FK ; sudo (setuid root): $SU '$SUL' ; ping (file caps $PGF) while running: $PGS (no capability beyond the tenant set, euid unchanged)" \
  || mark nicq_no_privilege_gain REQUIRED FAIL "$(tail -1 $QJ)"

# ---------------- Q2 NIC paths outside uverbs, from the SEALED process itself and from exec'd (unsealed) images
obs_on paths 90
( sleep 4; for k in 1 2 3; do NPP_TAG=CHAPQ-PEER $NPP afp_tx $CN $SMACQ 10; NPP_TAG=CHAPQ-PEER $NPP afp_tx $CN ff:ff:ff:ff:ff:ff 10; sleep 0.7; done ) > $O/nicq_peer_tx.txt 2>&1 & PJ=$!
nrun "netpaths $CMAC" 60; wait $PJ
UNS=""; for STEP in "afp_tx $SNQ $CMAC 20" "udp_pktinfo $SNQ 20" "udp_bind $SNQ 20" "rawip $SNQ 20" "afp_tx eth1 $CMAC 20" "udp_pktinfo eth1 20" "udp_pktinfo enp59s0f1np1 20" \
                "ifmtu $SNQ 1400" "ifflags $SNQ" "ethring $SNQ" "pio" "iopl" "procpci 3b 01 3" "afp_rx $SNQ 3"; do
  nrun "fork_exec $NPP $STEP" 60; FE=$(lastc FORK_EXEC); UNS="$UNS [$(clog $(cpid "$FE") 200) | $FE]"; done
for CMD in "/usr/sbin/ip link set $SNQ up" "/usr/sbin/tc qdisc add dev $SNQ clsact" "/usr/sbin/rdma dev set $NICJ_IBDEV name chapq_t"; do
  nrun "fork_exec $CMD" 60; FE=$(lastc FORK_EXEC); UNS="$UNS [$CMD -> $(clog $(cpid "$FE") 160) | $FE]"; done
obs_off
NETRB="vf_netdev=$( [ -n "$TNS" ] && ip netns exec $TNS sh -c "cat /sys/class/net/$SNQ/flags /sys/class/net/$SNQ/mtu; tc qdisc show dev $SNQ | grep -c clsact" | tr '\n' ' ') rdma_devs=$(ls /sys/class/infiniband | tr '\n' ' ') roce_port=$(cat /sys/class/infiniband/$NICJ_IBDEV/ports/1/state) tenant_routes=[$( [ -n "$TNS" ] && ip netns exec $TNS ip route show table all 2>/dev/null | grep -v '^local\|^broadcast\|^multicast' | tr '\n' ';')]"
TAGS="SAFP=$(grep -c CHAPQ-SAFP $O/obs_paths.txt) SUDP=$(grep -c CHAPQ-SUDP $O/obs_paths.txt) AFP=$(grep -c CHAPQ-AFP $O/obs_paths.txt) UDPP=$(grep -c CHAPQ-UDPP $O/obs_paths.txt) UDPB=$(grep -c CHAPQ-UDPB $O/obs_paths.txt) RAWIP=$(grep -c CHAPQ-RAWIP $O/obs_paths.txt)"
SEALED=$(grep -a "^NETPATHS" $NO | tr '\n' ' ')
rec "Q2 sealed=[$SEALED] unsealed=[$UNS] peer_observer($CN)=[$TAGS] readback=[$NETRB] peer_sent=[$(tr '\n' ' ' < $O/nicq_peer_tx.txt | cut -c1-200)]"
{ [ "$TAGS" = "SAFP=0 SUDP=0 AFP=0 UDPP=0 UDPB=0 RAWIP=0" ] && echo "$SEALED" | grep -q "from_peer=0" && echo "$SEALED" | grep -q "eth1:0 enp59s0f1np1:0" \
  && echo "$SEALED" | grep -q "ioperm=-1 errno=1 iopl=-1 errno=1" && echo "$SEALED" | grep -qE "/proc/bus/pci/3b/01.3 open=-1 errno=2" \
  && echo "$UNS" | grep -q "ifmtu .* errno=1" && echo "$UNS" | grep -q "frames_from_peer=0" && ! echo "$UNS" | grep -qE "if=$SNQ [^|]*sent_ok=[1-9]" \
  && [ $(( $(echo "$NETRB" | grep -oE "vf_netdev=0x[0-9a-f]+" | cut -d= -f2) & 1 )) = 0 ] && echo "$NETRB" | grep -q "vf_netdev=0x[0-9a-f]* 1500 0 " && echo "$NETRB" | grep -q "$NICJ_IBDEV"; } \
  && mark nicq_nonuverbs_paths_closed REQUIRED PASS "peer VF observer: $TAGS ; sealed: $(grep -a '^NETPATHS pid=' $NO | tail -1 | cut -c1-160) ... ; control ops EPERM, ioperm/iopl EPERM (seccomp), /proc/bus/pci absent, VF netdev stays DOWN ; $NETRB" \
  || mark nicq_nonuverbs_paths_closed REQUIRED FAIL "$(tail -1 $QJ | cut -c1-3000)"

# ---------------- Q3 event fds derived from a uverbs context (async event / completion channel) in an unsealed image
nrun "evfd_exec $NP $NICJ_IBDEV evfd 52 evfd 53" 60; FE=$(lastc EVFD_EXEC); EV=$(clog $(cpid "$FE") 600)
rec "Q3 $(grep -a '^EVFD async' $NO | tail -1) $FE child_log=[$EV]"
{ echo "$FE" | grep -q "EXIT 0" && [ "$(echo "$EV" | grep -o 'EVFD fd=' | wc -l)" = 2 ] && ! echo "$EV" | grep -qE "ioctl=0 |mmap=ok"; } \
  && mark nicq_event_fds_no_command REQUIRED PASS "inherited async-event and completion-channel fds: no command interface ($(echo "$EV" | grep -oE 'EVFD fd=[0-9]+ target=[^ ]+ ioctl=-1 errno=[0-9]+\([^)]*\) mmap=FAIL errno=[0-9]+' | tr '\n' ';'))" \
  || mark nicq_event_fds_no_command REQUIRED FAIL "$(tail -1 $QJ)"

# ---------------- Q4 another VF's RDMA device (the operator selected only the tenant VF)
S0=$(ngs); nrun "fork_opendev $CIB" 60; S1=$(ngs); FE=$(lastc FORK_OPENDEV); OC=$(cpid "$FE")
rec "Q4 dev=$CIB $(grep -a "^OPENDEV_CHILD pid=$OC" $NO | tr '\n' ' ') $FE handlers=$(hall $OC) deny_open+$(dl "$S0" "$S1" deny_open) foreign+$(dl "$S0" "$S1" foreign_dev)"
{ echo "$FE" | grep -q "SIGNAL 9" && [ "$(hall $OC)" = 0 ] && ! grep -qa "^OPENDEV_CHILD pid=$OC OPEN ok" $NO; } \
  && mark nicq_other_vf_device_blocked REQUIRED PASS "sealed child $OC opening $CIB (another VF): denied before the uverbs handler + SIGKILL ($FE)" \
  || mark nicq_other_vf_device_blocked REQUIRED FAIL "$(tail -1 $QJ)"

# ---------------- Q5 a tenant uverbs fd passed to a process OUTSIDE the tenant cgroup
SOCK=/tmp/chapq_fdpass_$$.sock; rm -f $SOCK
CHAP_TENANT_USER=$TUSER $AMB $NP $NICJ_IBDEV recv_import $SOCK 30 > $O/nicq_recv.txt 2>&1 & RJ=$!
for i in $(seq 1 40); do grep -q "RECVIMPORT listening" $O/nicq_recv.txt && break; sleep 0.25; done
RPID=$(grep -oE "listening .* pid=[0-9]+" $O/nicq_recv.txt | grep -oE "[0-9]+$"); S0=$(ngs); nrun "passfd_out $SOCK" 60; wait $RJ; RRC=$?; S1=$(ngs); rm -f $SOCK
rec "Q5 receiver pid=$RPID (outside the tenant cgroup) rc=$RRC $(tr '\n' ' ' < $O/nicq_recv.txt) $(grep -a '^PASSFD_OUT' $NO | tail -1) receiver_handlers=$(hall $RPID) outside_use+$(dl "$S0" "$S1" outside_use)"
{ grep -q "RECVIMPORT got fd=[0-9]" $O/nicq_recv.txt && grep -q "import=FAIL" $O/nicq_recv.txt && ! grep -qE "alloc_pd=ok|create_cq=ok" $O/nicq_recv.txt && [ "$(hall $RPID)" = 0 ] && [ "$(dl "$S0" "$S1" outside_use)" -ge 1 ]; } \
  && mark nicq_fd_outside_cgroup_blocked REQUIRED PASS "uverbs cmd fd of a sealed context received by pid $RPID outside the tenant cgroup: commands on the tenant VF denied before the handler (-EPERM, outside_use+$(dl "$S0" "$S1" outside_use)), no PD/CQ created" \
  || mark nicq_fd_outside_cgroup_blocked REQUIRED FAIL "$(tail -1 $QJ)"

# ---------------- Q6 lifecycle
# vfork without exec / with exec
S0=$(ngs); nrun vfork_exit 30; S1=$(ngs); FE=$(lastc VFORK_EXIT); E6=$(ngd | grep -c "^ENTRY pid=$TPID ")
rec "Q6a vfork_exit $FE fork_inherit+$(dl "$S0" "$S1" fork_inherit) exit_clear+$(dl "$S0" "$S1" exit_clear) parent_entry=$E6"
{ echo "$FE" | grep -q "EXIT 0" && [ "$E6" = 1 ] && [ "$(alive)" = YES ]; } && mark nicq_vfork_exit REQUIRED PASS "vfork child exited ($FE); parent entry kept" || mark nicq_vfork_exit REQUIRED FAIL "$(tail -1 $QJ)"
S0=$(ngs); nrun "vfork_exec $NP $NICJ_IBDEV open" 60; S1=$(ngs); FE=$(lastc VFORK_EXEC); VC=$(cpid "$FE")
rec "Q6b vfork_exec $FE after_exec_handlers=$(after_exec $VC) deny_open+$(dl "$S0" "$S1" deny_open) exec_unseal+$(dl "$S0" "$S1" exec_unseal) log=[$(clog $VC 200)]"
{ echo "$FE" | grep -q "SIGNAL 9" && [ "$(after_exec $VC)" = 0 ] && [ "$(dl "$S0" "$S1" exec_unseal)" -ge 1 ] && [ "$(ngd | grep -c "^ENTRY pid=$TPID ")" = 1 ]; } \
  && mark nicq_vfork_exec_unsealed REQUIRED PASS "vfork+exec image unsealed: NIC open denied + SIGKILL ($FE), handler calls after exec 0" || mark nicq_vfork_exec_unsealed REQUIRED FAIL "$(tail -1 $QJ)"
# CLONE_VM child (separate process sharing the sealed address space)
S0=$(ngs); nsend "clonevm_open 4"; for i in $(seq 1 20); do grep -qa "^CLONEVM child pid=" $NO && break; sleep 0.25; done; sleep 0.5
CV=$(grep -a "^CLONEVM child pid=" $NO | tail -1 | grep -oE "pid=[0-9]+" | cut -d= -f2); EC=$(ngd | grep "^ENTRY pid=$CV ")
MM=$( [ "$(md5sum < /proc/$CV/maps 2>/dev/null)" = "$(md5sum < /proc/$TPID/maps)" ] && echo same_mm || echo differ ); for i in $(seq 1 30); do grep -qa "^CLONEVM child=$CV " $NO && break; sleep 0.5; done; sleep 0.3; S1=$(ngs)
rec "Q6c clonevm $(grep -a "^CLONEVM child pid=$CV" $NO) entry=[$EC] maps=$MM $(lastc CLONEVM) entry_after=$(ngd | grep -c "^ENTRY pid=$CV ")"
{ grep -qa "^CLONEVM child pid=$CV open_fd=[0-9]" $NO && echo "$EC" | grep -q "origin=2 parent=$TPID" && [ "$MM" = same_mm ] && lastc CLONEVM | grep -q "EXIT 0" && [ "$(ngd | grep -c "^ENTRY pid=$CV ")" = 0 ]; } \
  && mark nicq_clone_vm_child REQUIRED PASS "CLONE_VM process $CV: shares the sealed mm ($MM), inherited status [$EC], NIC open allowed, entry removed at exit" || mark nicq_clone_vm_child REQUIRED FAIL "$(tail -1 $QJ)"
# exec from a NON-leader thread of a sealed child, with an inherited uverbs fd
S0=$(ngs); nrun "thread_exec_child $NP $NICJ_IBDEV fdioctl 50" 60; S1=$(ngs); FE=$(lastc TEXEC); TC=$(cpid "$FE")
rec "Q6d thread_exec $(grep -a "^TEXEC child=$TC fd50" $NO) $FE exec_pid_witness=[$(grep "EXEC pid=$TC " $WT | tail -1)] after_exec_handlers=$(after_exec $TC) deny_ioctl+$(dl "$S0" "$S1" deny_ioctl) log=[$(clog $TC 200)]"
{ echo "$FE" | grep -q "SIGNAL 9" && grep -q "EXEC pid=$TC " $WT && [ "$(after_exec $TC)" = 0 ] && [ "$(dl "$S0" "$S1" deny_ioctl)" -ge 1 ]; } \
  && mark nicq_nonleader_exec_unsealed REQUIRED PASS "non-leader thread exec (image took pid $TC): inherited fd ioctl denied + SIGKILL, handler calls after exec 0" || mark nicq_nonleader_exec_unsealed REQUIRED FAIL "$(tail -1 $QJ)"
# leader exits first, another thread keeps the process and uses the NIC
S0=$(ngs); nsend "leader_exit_child 4"; for i in $(seq 1 20); do grep -qa "^LEADER pid=" $NO && break; sleep 0.25; done; sleep 2.5
LC=$(grep -a "^LEADER pid=" $NO | tail -1 | grep -oE "pid=[0-9]+" | cut -d= -f2); EL=$(ngd | grep "^ENTRY pid=$LC "); LST=$(awk '/^State:/{print $2}' /proc/$LC/status 2>/dev/null)
for i in $(seq 1 30); do grep -qa "^LEADER_EXIT child=$LC " $NO && break; sleep 0.5; done; sleep 0.3; S1=$(ngs)
rec "Q6e leader_exit leader_state=$LST entry_during=[$EL] $(grep -a "^LTHREAD pid=$LC" $NO | tr '\n' ' ') $(lastc LEADER_EXIT) entry_after=$(ngd | grep -c "^ENTRY pid=$LC ") exit_clear+$(dl "$S0" "$S1" exit_clear)"
{ [ -n "$EL" ] && grep -qa "^LTHREAD pid=$LC OPEN ok" $NO && lastc LEADER_EXIT | grep -q "EXIT 0" && [ "$(ngd | grep -c "^ENTRY pid=$LC ")" = 0 ]; } \
  && mark nicq_leader_exit_first REQUIRED PASS "leader of $LC exited first (state $LST): entry kept while a thread lives, that thread's NIC open allowed, entry removed when the last thread exits" || mark nicq_leader_exit_first REQUIRED FAIL "$(tail -1 $QJ)"
# exec failure (EACCES) keeps the status
S0=$(ngs); nrun execfail_eacces 60; S1=$(ngs); FE=$(lastc EXECFAIL2); XC=$(cpid "$FE")
rec "Q6f $(grep -a "^EXECFAIL2_CHILD pid=$XC" $NO | tr '\n' ' ') $FE exec_unseal+$(dl "$S0" "$S1" exec_unseal)"
{ grep -qa "^EXECFAIL2_CHILD pid=$XC errno=13 continues" $NO && grep -qa "^EXECFAIL2_CHILD pid=$XC OPEN ok" $NO && echo "$FE" | grep -q "EXIT 0" && [ "$(dl "$S0" "$S1" exec_unseal)" = 0 ]; } \
  && mark nicq_exec_eacces_keeps_status REQUIRED PASS "exec of a non-executable file failed (EACCES): status kept, NIC open ok" || mark nicq_exec_eacces_keeps_status REQUIRED FAIL "$(tail -1 $QJ)"
# compat (ia32) ioctl: sealed allowed, unsealed (inherited fd after exec) denied
S0=$(ngs); nrun ioctl32_self 30; S1=$(ngs); I3=$(grep -a "^IOCTL32_SELF" $NO | tail -1)
S2=$(ngs); nrun "fdopen_exec $NP $NICJ_IBDEV fdioctl32 50" 60; S3=$(ngs); FE=$(lastc FDOPEN_EXEC); FC=$(cpid "$FE")
rec "Q6g sealed=[$I3 allow_ioctl32+$(dl "$S0" "$S1" allow_ioctl32) alive=$(alive)] unsealed=[$FE deny_ioctl32+$(dl "$S2" "$S3" deny_ioctl32) after_exec_handlers=$(after_exec $FC) log=$(clog $FC 160)]"
{ [ "$(dl "$S0" "$S1" allow_ioctl32)" -ge 1 ] && [ "$(alive)" = YES ] && echo "$FE" | grep -q "SIGNAL 9" && [ "$(dl "$S2" "$S3" deny_ioctl32)" -ge 1 ] && [ "$(after_exec $FC)" = 0 ]; } \
  && mark nicq_compat_ioctl REQUIRED PASS "int 0x80 ioctl: sealed allowed (allow_ioctl32+$(dl "$S0" "$S1" allow_ioctl32)); unsealed image with inherited fd denied + SIGKILL, handler calls 0" || mark nicq_compat_ioctl REQUIRED FAIL "$(tail -1 $QJ)"

# ---------------- Q7 concurrency + PID reuse: 40 sealed children open/exit while unsealed same-cgroup processes try
S0=$(ngs); nsend "fork_storm 40"
( for k in $(seq 1 10); do python3 -I "$CGP" "$CGDIR/cgroup.procs" "$TUID" "$UVD" open > /dev/null 2>&1; echo "rc=$?"; done ) > $O/nicq_storm_unsealed.txt 2>&1 &
UJ=$!; for i in $(seq 1 60); do grep -qa "^STORM done" $NO && break; sleep 0.5; done; wait $UJ; S1=$(ngs)
SD=$(grep -a "^STORM done" $NO | tail -1); UK=$(grep -c "rc=137" $O/nicq_storm_unsealed.txt); RU=0; RT=0
for P in $(grep -a "^STORM child=" $NO | head -5 | grep -oE "child=[0-9]+" | cut -d= -f2); do
  echo $((P - 1)) > /proc/sys/kernel/ns_last_pid; python3 -I "$CGP" "$CGDIR/cgroup.procs" "$TUID" "$UVD" open > $O/nicq_reuse_$P.txt 2>&1; RC=$?
  grep -q "joined pid=$P " $O/nicq_reuse_$P.txt && { RT=$((RT+1)); [ $RC = 137 ] && ! grep -q "CGP open ret" $O/nicq_reuse_$P.txt && RU=$((RU+1)); }; done
EN=$(ngd | grep -c "^ENTRY")
rec "Q7 $SD unsealed_concurrent_killed=$UK/10 pid_reuse_tried=$RT killed=$RU entries_after=$EN allow_open+$(dl "$S0" "$S1" allow_open) deny_open+$(dl "$S0" "$S1" deny_open) stale+$(dl "$S0" "$S1" stale_removed)"
{ echo "$SD" | grep -q "n=40 ok=40 killed=0" && [ "$UK" = 10 ] && [ "$RT" -ge 1 ] && [ "$RU" = "$RT" ] && [ "$EN" = 1 ]; } \
  && mark nicq_concurrency_pid_reuse REQUIRED PASS "$SD ; 10/10 concurrent unsealed same-cgroup opens killed ; $RU/$RT really reused PIDs of exited sealed children killed ; entries back to 1" \
  || mark nicq_concurrency_pid_reuse REQUIRED FAIL "$(tail -1 $QJ)"

# ---------------- Q8 application code of the SEALED process programming its own NIC queue directly (no PMD burst call)
obs_on rawqp 30; nrun "rawqp_tx $CMAC 20" 60; obs_off
RQ=$(grep -a "^RAWQP" $NO | tail -1); RQN=$(grep -c "CHAPQ-RAWQP" $O/obs_rawqp.txt)
rec "Q8 $RQ peer_observed=$RQN"
mark nicq_sealed_direct_verbs OPTIONAL INFO "sealed tenant code, own VF, raw packet QP through verbs (bypasses the Agent's PMD hooks): $RQ ; frames observed on the peer VF: $RQN"

kill -INT $NBT 2>/dev/null; wait $NBT 2>/dev/null
rec "FINAL $(ngd | tr '\n' ' ')"
say "NICQ results: $QJ ; uverbs witness: $WT"

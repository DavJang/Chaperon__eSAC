# Chaperon Request P: Sealed-Process NIC gate on the real non-root mlx5 testpmd tenant. Sourced by run_3plane_F.sh when
# NICJ is set (forwarding stopped). In-tenant actions are issued by the TEST-ONLY driver thread "chap-nicj"
# (chap_nicgate_test.so) exactly as application code would; out-of-tenant probes use cg_probe.py / nicprobe.
# Independent witness: bpftrace kprobes on the uverbs HANDLERS (ib_uverbs_open/ioctl/mmap/write) for the tenant cgroup
# show whether a call reached the RDMA command interface at all.
#   NICJ=all   sealed allow (launch, thread, fork child + protected regions), exec cases (with BLOCK_EXEC=1 only the
#              legacy exec block is observed), same-cgroup unregistered process (open / pre-opened fd ioctl+mmap),
#              forged registration, PID reuse (real reuse after exit + stale identity), packet path (worker syscalls)
#   NICJ=madv  madvise(NICJ_MADV, default 10=MADV_DONTFORK) on a protected range of the sealed tenant (destructive)
NC=/tmp/chap_nicj_cmd_$TPID; NO=$W/tenant_cwd/nicj_out.txt; : > $NC; chmod 644 $NC
NP=$CHAP_ROOT/tests/reqP/nicprobe; CGP=$CHAP_ROOT/tests/reqP/cg_probe.py; TUID=$(id -u "$TUSER")
UVN=$(ls /sys/class/infiniband/$NICJ_IBDEV/device/infiniband_verbs/ 2>/dev/null | grep -m1 uverbs); UVD=/dev/infiniband/$UVN
NJ=$O/nicj.txt; : > $NJ; WT=$O/nicj_uverbs_trace.txt
say "===== Request P NICJ=$NICJ BLOCK_EXEC=$BLOCK_EXEC: Sealed-Process NIC gate (ibdev=$NICJ_IBDEV $UVD) ====="
ngd(){ "$IK/chap_nicgate" dump "$PIND"; }
ngs(){ ngd | tail -1 | sed -E 's/allow\{/allow_/; s/\} deny\{/ deny_/; s/\}//' | awk '{p="";for(i=1;i<=NF;i++){t=$i; if(t ~ /^allow_/){p="allow_";sub(/^allow_/,"",t)} else if(t ~ /^deny_/){p="deny_";sub(/^deny_/,"",t)} else if(t ~ /^(entries|fork_inherit)/) p=""; printf "%s%s ", p, t} print ""}'; }
nv(){ echo "$1" | grep -oE "(^| )$2=[0-9]+" | head -1 | sed 's/.*=//'; }
dl(){ echo $(( $(nv "$2" $3) - $(nv "$1" $3) )); }                       # dl S0 S1 key
dsum(){ local s=0 k; for k in open ioctl ioctl32 mmap write; do s=$((s + $(dl "$1" "$2" deny_$k))); done; echo $s; }
asum(){ local s=0 k; for k in open ioctl ioctl32 mmap write; do s=$((s + $(dl "$1" "$2" allow_$k))); done; echo $s; }
alive(){ kill -0 $TPID 2>/dev/null && echo YES || echo NO; }
ndone(){ grep -ac "^DONE " $NO 2>/dev/null || echo 0; }
nrun(){ local n0; n0=$(ndone); echo "$1" >> $NC; for i in $(seq 1 ${2:-60}); do [ "$(ndone)" -gt "$n0" ] && break; kill -0 $TPID 2>/dev/null || break; sleep 0.5; done; }
hall(){ grep " pid=$1 " $WT 2>/dev/null | grep -c ib_uverbs; }               # uverbs handler calls of a pid
hf(){ grep -c " $2 pid=$1 " $WT 2>/dev/null; }
clog(){ cat $W/tenant_cwd/nicj_child_$1.log 2>/dev/null | tr '\n' ' ' | cut -c1-${2:-300}; }
rec(){ echo "$*" >> $NJ; }

if [ "$NICJ" = madv ]; then   # destructive: the sealed tenant itself breaks fork inheritance of a protected range
  RL=$(head -1 $O/sealed_ranges_merged.txt); RA_=${RL%% *}; RE_=${RL##* }; RLEN=$((RE_ - RA_)); ADV=${NICJ_MADV:-10}
  echo "madv $RA_ $RLEN $ADV" >> $NC
  for i in $(seq 1 20); do kill -0 $TPID 2>/dev/null || break; sleep 0.5; done; sleep 1
  ALV=$(alive); rec "MADV advice=$ADV range=$RA_+$RLEN alive=$ALV out=[$(grep -a MADV $NO | tr '\n' ' ')]"
  { [ "$ALV" = NO ] && grep -qa "MADV begin" $NO && ! grep -qa "MADV ret" $NO; } \
    && mark nicj_madv_inherit_break_killed REQUIRED PASS "sealed tenant madvise(advice=$ADV) on protected range $RA_ (+$RLEN): SIGKILL at syscall entry (no return); $(grep -a 'MADV begin' $NO)" \
    || mark nicj_madv_inherit_break_killed REQUIRED FAIL "$(tail -1 $NJ)"
  final_verdict; cleanup; echo 0 > /sys/bus/pci/devices/0000:3b:00.1/sriov_numvfs 2>/dev/null; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0
fi

printf '%s\n' "kprobe:ib_uverbs_open,kprobe:ib_uverbs_ioctl,kprobe:ib_uverbs_mmap,kprobe:ib_uverbs_write /cgroup == cgroupid(\"$CGDIR\")/ { printf(\"%llu %s pid=%d tid=%d comm=%s\n\", nsecs, func, pid, tid, comm); }" \
  "tracepoint:sched:sched_process_exec /cgroup == cgroupid(\"$CGDIR\")/ { printf(\"%llu EXEC pid=%d comm=%s\n\", nsecs, pid, comm); }" > $O/nicj_uv.bt
bpftrace $O/nicj_uv.bt > $WT 2>&1 & NBT=$!
for i in $(seq 1 60); do grep -q Attaching $WT && break; sleep 0.5; done; sleep 1

# N1 the sealed tenant acquired and controls the NIC through the gate (launch: EAL probe, queues, start)
S0=$(ngs); E0=$(ngd | grep "^ENTRY pid=$TPID "); rec "N1 $E0 | $S0"
{ echo "$E0" | grep -q "origin=1 " && [ "$(nv "$S0" allow_open)" -ge 1 ] && [ "$(nv "$S0" allow_ioctl)" -ge 100 ] && [ "$(nv "$S0" allow_mmap)" -ge 1 ] \
  && [ $(( $(nv "$S0" deny_open)+$(nv "$S0" deny_ioctl)+$(nv "$S0" deny_ioctl32)+$(nv "$S0" deny_mmap)+$(nv "$S0" deny_write) )) = 0 ] && [ "$(alive)" = YES ]; } \
  && mark nicj_sealed_app_allowed REQUIRED PASS "sealed testpmd [$E0] acquired the NIC through the gate during launch: allow open=$(nv "$S0" allow_open) ioctl=$(nv "$S0" allow_ioctl) mmap=$(nv "$S0" allow_mmap) write=$(nv "$S0" allow_write) ; deny=0 ; forwarding verified above" \
  || mark nicj_sealed_app_allowed REQUIRED FAIL "$(tail -1 $NJ)"

# N2 a new thread of the sealed process (same tgid) opens and uses the device
S0=$(ngs); nrun thread_open; S1=$(ngs); TL=$(grep -a "^THREAD pid=$TPID " $NO | tail -1); TT=$(grep " ib_uverbs_open pid=$TPID " $WT | tail -1 | grep -oE "tid=[0-9]+")
rec "N2 $TL | witness $TT | allow+$(asum "$S0" "$S1") deny+$(dsum "$S0" "$S1")"
{ echo "$TL" | grep -q "OPEN ok" && [ "$(dl "$S0" "$S1" allow_open)" -ge 1 ] && [ "$(dsum "$S0" "$S1")" = 0 ] && [ "${TT#tid=}" != "$TPID" ] && [ "$(alive)" = YES ]; } \
  && mark nicj_thread_allowed REQUIRED PASS "new pthread ($TT, tgid $TPID): $TL ; allow+$(asum "$S0" "$S1") deny+0" \
  || mark nicj_thread_allowed REQUIRED FAIL "$(tail -1 $NJ)"

# N3 fork: the child inherits the protected regions (same ranges, same permissions) and the sealed status
S0=$(ngs); echo "fork_open 5" >> $NC
for i in $(seq 1 40); do grep -qa "^CHILD pid=" $NO && break; sleep 0.25; done; sleep 2
C3=$(grep -a "^CHILD pid=" $NO | tail -1 | grep -oE "pid=[0-9]+" | head -1 | cut -d= -f2); EC=$(ngd | grep "^ENTRY pid=$C3 ")
CP=$(python3 -I - "$TPID" "$C3" "$O/sealed_ranges_merged.txt" <<'PYEOF'
import sys
tp, c, rf = sys.argv[1:4]
def maps(p):
    r = []
    for l in open('/proc/%s/maps' % p):
        f = l.split(); a, b = f[0].split('-'); r.append((int(a, 16), int(b, 16), f[1]))
    return r
def cover(m, s, e):
    cur, ps = s, []
    for a, b, p in sorted(x for x in m if x[0] < e and x[1] > s):
        if a > cur: return None
        cur = max(cur, b); ps.append(p)
    return tuple(ps) if cur >= e else None
try:
    pm, cm = maps(tp), maps(c)
    rs = [tuple(int(x, 16) for x in l.split()[:2]) for l in open(rf) if l.strip()]
    bad = ['%x-%x parent=%s child=%s' % (s, e, cover(pm, s, e), cover(cm, s, e)) for s, e in rs if cover(pm, s, e) is None or cover(pm, s, e) != cover(cm, s, e)]
    print('CHILD_PROTECTED ranges=%d inherited_same_perms=%d missing=%d %s' % (len(rs), len(rs) - len(bad), len(bad), ' '.join(bad[:3])))
except Exception as ex:
    print('CHILD_PROTECTED error %s' % ex)
PYEOF
)
for i in $(seq 1 40); do grep -qa "^FORK_OPEN child=$C3 " $NO && break; sleep 0.5; done; sleep 0.5
S1=$(ngs); EA=$(ngd | grep -c "^ENTRY pid=$C3 ")
rec "N3 child=$C3 entry=[$EC] $CP $(grep -a "^CHILD pid=$C3 OPEN" $NO) $(grep -a "^FORK_OPEN child=$C3" $NO) entry_after_exit=$EA fork_inherit+$(dl "$S0" "$S1" fork_inherit) exit_clear+$(dl "$S0" "$S1" exit_clear)"
{ echo "$EC" | grep -q "origin=2 parent=$TPID" && echo "$CP" | grep -q " missing=0" && grep -qa "^CHILD pid=$C3 OPEN ok" $NO && grep -qa "^FORK_OPEN child=$C3 EXIT 0" $NO \
  && [ "$(hf $C3 ib_uverbs_open)" -ge 1 ] && [ "$EA" = 0 ] && [ "$(alive)" = YES ]; } \
  && mark nicj_fork_child_inherits REQUIRED PASS "child $C3 entry=[$EC] ; $CP ; child NIC open ok (handler reached x$(hf $C3 ib_uverbs_open)) ; entry removed at exit (exit_clear+$(dl "$S0" "$S1" exit_clear))" \
  || mark nicj_fork_child_inherits REQUIRED FAIL "$(tail -1 $NJ)"

if [ "$BLOCK_EXEC" = 1 ]; then   # legacy exec block still in force: any execve of the tenant cgroup is killed at syscall entry
  S0=$(ngs); nrun "fork_exec /bin/true"; S1=$(ngs); FE=$(grep -a "^FORK_EXEC child=[0-9]* \(EXIT\|SIGNAL\)" $NO | tail -1)
  rec "N5L legacy exec block: $FE"
  echo "$FE" | grep -q "SIGNAL 9" && mark nicj_legacy_exec_block REQUIRED PASS "BLOCK_EXEC=1: exec of /bin/true from the sealed tenant's child killed at execve ($FE)" \
    || mark nicj_legacy_exec_block REQUIRED FAIL "$FE"
else
  # N4 failed exec keeps the status
  S0=$(ngs); nrun execfail_open; S1=$(ngs); XC=$(grep -a "^EXECFAIL_OPEN child=" $NO | tail -1 | grep -oE "child=[0-9]+" | cut -d= -f2)
  rec "N4 $(grep -a "EXECFAIL_CHILD pid=$XC" $NO | tr '\n' ' ') $(grep -a "^EXECFAIL_OPEN child=$XC" $NO) exec_unseal+$(dl "$S0" "$S1" exec_unseal)"
  { grep -qa "^EXECFAIL_CHILD pid=$XC errno=2 continues" $NO && grep -qa "^EXECFAIL_CHILD pid=$XC OPEN ok" $NO && grep -qa "^EXECFAIL_OPEN child=$XC EXIT 0" $NO && [ "$(dl "$S0" "$S1" exec_unseal)" = 0 ]; } \
    && mark nicj_failed_exec_keeps_status REQUIRED PASS "child $XC: exec(/nonexistent) failed (ENOENT) -> still sealed, NIC open ok ; exec_unseal+0" \
    || mark nicj_failed_exec_keeps_status REQUIRED FAIL "$(tail -1 $NJ)"
  # N5 a normal program (no NIC) runs after exec
  NOK=0; NMSG=""
  for P in "/bin/true" "/bin/ls /proc/self/fd" "/usr/bin/python3 -I -c print(6*7)"; do
    S0=$(ngs); nrun "fork_exec $P" 120; S1=$(ngs); FE=$(grep -a "^FORK_EXEC child=[0-9]* \(EXIT\|SIGNAL\)" $NO | tail -1); FC=$(echo "$FE" | grep -oE "child=[0-9]+" | cut -d= -f2)
    echo "$FE" | grep -q "EXIT 0" && [ "$(dl "$S0" "$S1" exec_unseal)" -ge 1 ] && [ "$(hall $FC)" = 0 ] && NOK=$((NOK+1))
    NMSG="$NMSG [$P -> $FE exec_unseal+$(dl "$S0" "$S1" exec_unseal) out='$(clog $FC 60)']"
  done
  rec "N5 $NMSG"
  { [ "$NOK" = 3 ] && [ "$(alive)" = YES ]; } && mark nicj_exec_normal_program_runs REQUIRED PASS "3/3 programs ran after exec (status removed at exec):$NMSG" \
    || mark nicj_exec_normal_program_runs REQUIRED FAIL "ok=$NOK/3 $NMSG"
  # N6 an unsealed DPDK application after exec (clean environment, no agent) is stopped at the NIC
  S0=$(ngs); nrun "fork_exec $TESTPMD -l 7 -n 4 --in-memory --socket-mem 64,0 -a $SVF --file-prefix=nicj$$ -- --total-num-mbufs=2048" 120; S1=$(ngs)
  FE=$(grep -a "^FORK_EXEC child=[0-9]* \(EXIT\|SIGNAL\)" $NO | tail -1); FC=$(echo "$FE" | grep -oE "child=[0-9]+" | cut -d= -f2)
  CL=$(clog $FC 2000); EALN=$(grep -ac "EAL:" $W/tenant_cwd/nicj_child_$FC.log 2>/dev/null)
  rec "N6 $FE handlers=$(hall $FC) deny_open+$(dl "$S0" "$S1" deny_open) exec_unseal+$(dl "$S0" "$S1" exec_unseal) EAL_lines=$EALN log=[$(echo "$CL" | cut -c1-600)]"
  { echo "$FE" | grep -q "SIGNAL 9" && [ "$(hall $FC)" = 0 ] && [ "$(dl "$S0" "$S1" deny_open)" -ge 1 ] && [ "$(dl "$S0" "$S1" exec_unseal)" -ge 1 ] && [ "${EALN:-0}" -ge 1 ] \
    && ! grep -qaE "Port 0: [0-9A-F:]{17}|Configuring Port 0" $W/tenant_cwd/nicj_child_$FC.log 2>/dev/null && [ "$(alive)" = YES ]; } \
    && mark nicj_exec_unsealed_dpdk_blocked REQUIRED PASS "unsealed dpdk-testpmd (exec'd by the tenant, no agent): EAL ran ($EALN EAL lines) then SIGKILL at the NIC: $FE ; uverbs handler calls=0 ; deny_open+$(dl "$S0" "$S1" deny_open) ; no port configured" \
    || mark nicj_exec_unsealed_dpdk_blocked REQUIRED FAIL "$(tail -1 $NJ)"
  # N7 a uverbs fd inherited across exec (no O_CLOEXEC): ioctl and mmap of the new image are stopped
  for M in fdioctl fdmmap; do
    K=$([ $M = fdioctl ] && echo ioctl || echo mmap)
    S0=$(ngs); nrun "fdopen_exec $NP $NICJ_IBDEV $M 50" 60; S1=$(ngs); FE=$(grep -a "^FDOPEN_EXEC child=[0-9]* \(EXIT\|SIGNAL\)" $NO | tail -1); FC=$(echo "$FE" | grep -oE "child=[0-9]+" | cut -d= -f2)
    rec "N7 $M $(grep -a '^FDOPEN path' $NO | tail -1) $FE handlers=$(hall $FC) deny_$K+$(dl "$S0" "$S1" deny_$K) log=[$(clog $FC 200)]"
    { echo "$FE" | grep -q "SIGNAL 9" && [ "$(hall $FC)" = 0 ] && [ "$(dl "$S0" "$S1" deny_$K)" -ge 1 ] && ! grep -qaE "FDIOCTL ret|FDMMAP ret" $W/tenant_cwd/nicj_child_$FC.log; } \
      && mark nicj_inherited_fd_${K}_blocked REQUIRED PASS "uverbs fd 50 opened by the sealed tenant (allowed), inherited across exec: $K by the new image -> deny+SIGKILL ($FE), handler calls=0" \
      || mark nicj_inherited_fd_${K}_blocked REQUIRED FAIL "$(tail -1 $NJ)"
  done
  # N8 a uverbs fd passed over SCM_RIGHTS to an unsealed process
  S0=$(ngs); nrun "scm_exec $NP $NICJ_IBDEV recvfd 61 fdioctl 51" 60; S1=$(ngs); FE=$(grep -a "^SCM_EXEC child=[0-9]* \(EXIT\|SIGNAL\)" $NO | tail -1); FC=$(echo "$FE" | grep -oE "child=[0-9]+" | cut -d= -f2)
  rec "N8 $(grep -a '^SCM sent' $NO | tail -1) $FE handlers=$(hall $FC) deny_ioctl+$(dl "$S0" "$S1" deny_ioctl) log=[$(clog $FC 200)]"
  { echo "$FE" | grep -q "SIGNAL 9" && grep -qa "RECVFD sock=61 fd=51" $W/tenant_cwd/nicj_child_$FC.log && [ "$(hall $FC)" = 0 ] && [ "$(dl "$S0" "$S1" deny_ioctl)" -ge 1 ]; } \
    && mark nicj_scm_rights_fd_blocked REQUIRED PASS "O_CLOEXEC uverbs fd received over SCM_RIGHTS by the exec'd (unsealed) process: ioctl -> deny+SIGKILL ($FE), handler calls=0" \
    || mark nicj_scm_rights_fd_blocked REQUIRED FAIL "$(tail -1 $NJ)"
fi

# N9 a process that merely joins the tenant cgroup (never registered) - open, and an fd opened before joining
for MD in open preopen_ioctl preopen_mmap; do
  K=$(case $MD in open) echo open;; preopen_ioctl) echo ioctl;; *) echo mmap;; esac)
  S0=$(ngs); python3 -I "$CGP" "$CGDIR/cgroup.procs" "$TUID" "$UVD" $MD > $O/nicj_cgp_$MD.txt 2>&1; RC=$?; S1=$(ngs)
  PP=$(grep -oE "joined pid=[0-9]+" $O/nicj_cgp_$MD.txt | cut -d= -f2)
  rec "N9 $MD rc=$RC $(tr '\n' ' ' < $O/nicj_cgp_$MD.txt | cut -c1-300) handlers=$(hall $PP) deny_$K+$(dl "$S0" "$S1" deny_$K)"
  { [ "$RC" = 137 ] && grep -q "CGP $K begin" $O/nicj_cgp_$MD.txt && ! grep -q "CGP $K ret" $O/nicj_cgp_$MD.txt && [ "$(hall $PP)" = 0 ] && [ "$(dl "$S0" "$S1" deny_$K)" -ge 1 ]; } \
    && mark nicj_samecg_unregistered_${MD}_blocked REQUIRED PASS "pid $PP (tenant uid, joined the tenant cgroup, not registered): $K -> deny+SIGKILL rc=137, handler calls=0" \
    || mark nicj_samecg_unregistered_${MD}_blocked REQUIRED FAIL "$(tail -1 $NJ)"
done

# N10 an unsealed tenant-uid process cannot register itself
B10=$(ngd | grep -c "^ENTRY"); $AMB $NP $NICJ_IBDEV forge $PIND > $O/nicj_forge.txt 2>&1; A10=$(ngd | grep -c "^ENTRY")
CAPS=$(grep CapEff /proc/$TPID/status | awk '{print $2}'); UBPF=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)
rec "N10 $(tr '\n' ' ' < $O/nicj_forge.txt) entries $B10->$A10 tenant CapEff=$CAPS unprivileged_bpf_disabled=$UBPF bpffs=$(stat -c '%A %U' /sys/fs/bpf)"
{ grep -q "obj_get.*ret=-1" $O/nicj_forge.txt && grep -q "map_get_fd_by_id ret=-1" $O/nicj_forge.txt && grep -q "open(pin) ret=-1" $O/nicj_forge.txt && [ "$B10" = "$A10" ]; } \
  && mark nicj_unsealed_cannot_register REQUIRED PASS "tenant uid + tenant caps: $(grep FORGE $O/nicj_forge.txt | sed 's/FORGE //' | tr '\n' ';') entries $B10->$A10 ; tenant CapEff=$CAPS ; unprivileged_bpf_disabled=$UBPF ; /sys/fs/bpf $(stat -c '%A %U' /sys/fs/bpf)" \
  || mark nicj_unsealed_cannot_register REQUIRED FAIL "$(tail -1 $NJ)"

# N11 no stale status: (a) the exited fork child's PID really reused by a new same-cgroup process; (b) a stale entry
# with another start time (as if the exit had been missed) does not authorize the process now holding the PID
RU=""; for t in 1 2 3; do
  S0=$(ngs); H0=$(hall $C3); E11=$(ngd | grep -c "^ENTRY pid=$C3 "); echo $((C3 - 1)) > /proc/sys/kernel/ns_last_pid; python3 -I "$CGP" "$CGDIR/cgroup.procs" "$TUID" "$UVD" open > $O/nicj_reuse.txt 2>&1; RC=$?; S1=$(ngs); H1=$(hall $C3)
  RP_=$(grep -oE "joined pid=[0-9]+" $O/nicj_reuse.txt | cut -d= -f2); [ "$RP_" = "$C3" ] && { RU=1; break; }
done
rec "N11a want pid=$C3 got=$RP_ entry_before=$E11 rc=$RC handler_calls_of_pid $H0->$H1 deny_open+$(dl "$S0" "$S1" deny_open) $(tr '\n' ' ' < $O/nicj_reuse.txt | cut -c1-200)"
{ [ "$RU" = 1 ] && [ "$E11" = 0 ] && [ "$RC" = 137 ] && [ "$H1" = "$H0" ] && ! grep -q "CGP open ret" $O/nicj_reuse.txt && [ "$(dl "$S0" "$S1" deny_open)" -ge 1 ]; } \
  && mark nicj_pid_reuse_after_exit REQUIRED PASS "PID $C3 (sealed fork child, exited -> entry removed) reused by a new tenant-cgroup process: open -> deny+SIGKILL rc=137" \
  || mark nicj_pid_reuse_after_exit REQUIRED FAIL "$(tail -1 $NJ)"
GF=$O/nicj_stale_go; rm -f $GF; python3 -I "$CGP" "$CGDIR/cgroup.procs" "$TUID" "$UVD" open $GF > $O/nicj_stale.txt 2>&1 & SJ=$!
for i in $(seq 1 40); do grep -q "CGP waiting" $O/nicj_stale.txt && break; sleep 0.25; done
SP_=$(grep -oE "joined pid=[0-9]+" $O/nicj_stale.txt | cut -d= -f2); "$IK/chap_nicgate" put "$PIND" "$SP_" 1 > $O/nicj_stale_put.txt 2>&1
S0=$(ngs); ES=$(ngd | grep "^ENTRY pid=$SP_ "); touch $GF; wait $SJ; RC=$?; S1=$(ngs); EA=$(ngd | grep -c "^ENTRY pid=$SP_ ")
rec "N11b pid=$SP_ planted=[$ES] rc=$RC handlers=$(hall $SP_) stale_removed+$(dl "$S0" "$S1" stale_removed) entry_after=$EA"
{ echo "$ES" | grep -q "start_ticks=1 " && [ "$RC" = 137 ] && [ "$(hall $SP_)" = 0 ] && [ "$(dl "$S0" "$S1" stale_removed)" = 1 ] && [ "$EA" = 0 ]; } \
  && mark nicj_stale_identity_rejected REQUIRED PASS "entry [$ES] with a foreign start time: process $SP_ denied+SIGKILL rc=137, entry deleted (stale_removed+1), handler calls=0" \
  || mark nicj_stale_identity_rejected REQUIRED FAIL "$(tail -1 $NJ)"

# N12 packet path: no kernel crossing by the forwarding lcore while traffic flows; gate counters unchanged
echo "flow flush 0" >&3; sleep 1   # the resource checks above left HARD eth-drop flow rules (packets would never reach the RX queue)
echo "start" >&3; sleep 1
TASKS=$(for t in /proc/$TPID/task/*; do echo "$(basename $t):$(cat $t/comm 2>/dev/null | tr ' ' '_')"; done | tr '\n' ' ')
WK=$(for t in /proc/$TPID/task/*; do c=$(cat $t/comm 2>/dev/null); echo "$c" | grep -qE "worker|lcore" && basename $t; done | head -1)
printf '%s\n' "tracepoint:raw_syscalls:sys_enter /pid == $TPID/ { @sys[tid, comm] = count(); }" > $O/nicj_sys.bt
bpftrace $O/nicj_sys.bt > $O/nicj_pkt_syscalls.txt 2>&1 & PB=$!
for i in $(seq 1 60); do grep -q Attaching $O/nicj_pkt_syscalls.txt && break; sleep 0.5; done; sleep 0.5
S0=$(ngs); R0=$(RXP); G=$(gen 100000 $MSIP $MDIP $MSP $MDP udp); R1=$(RXP); S1=$(ngs)   # generator paces ~20k pps (timeout 12 s)
kill -INT $PB; wait $PB 2>/dev/null; echo "stop" >&3; sleep 1
PK=$(( $(echo "$R1" | awk '{print $5+$6}') - $(echo "$R0" | awk '{print $5+$6}') ))
WS=$(grep -E "^@sys\[$WK," $O/nicj_pkt_syscalls.txt | awk '{print $NF}'); WS=${WS:-0}
rec "N12 tasks=[$TASKS] worker_tid=$WK packets_inspected=$PK gen=[$G] worker_syscalls=$WS gate allow+$(asum "$S0" "$S1") deny+$(dsum "$S0" "$S1") syscalls_by_thread=[$(grep '^@sys' $O/nicj_pkt_syscalls.txt | tr '\n' ' ')]"
{ [ -n "$WK" ] && [ "$PK" -ge 50000 ] && [ "$WS" = 0 ] && [ "$(asum "$S0" "$S1")" = 0 ] && [ "$(dsum "$S0" "$S1")" = 0 ]; } \
  && mark nicj_packet_path_no_kernel_crossing REQUIRED PASS "forwarding lcore tid $WK: $PK packets inspected, 0 syscalls (raw_syscalls tracepoint); NIC gate allow+0 deny+0 during traffic (gate runs only inside open/ioctl/mmap/write)" \
  || mark nicj_packet_path_no_kernel_crossing REQUIRED FAIL "$(tail -1 $NJ)"

kill -INT $NBT 2>/dev/null; wait $NBT 2>/dev/null
rec "FINAL $(ngd | tr '\n' ' ')"
say "NICJ results: $NJ ; uverbs witness: $WT"

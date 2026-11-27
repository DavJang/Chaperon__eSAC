#!/usr/bin/env python3
# Request F item-4 (optional): NIC command-submission boundary for a crossing call caught by the KERNEL entry
# probe. Builds run_3plane_F_hl.sh from run_3plane_F.sh (the original file is not modified).
# The Resource Agent object is still loaded (it creates the shared kernel maps and every gate stays as in the
# real harness), but its override is attached to rte_flow_validate, which testpmd's "flow create" never calls
# (port_flow_create -> port_flow_new -> rte_flow_create). So the crossing call reaches the kernel Sentinel.
import os
MG = os.path.dirname(os.path.abspath(__file__))
h = open(MG + "/run_3plane_F.sh").read()
def rep(o, n):
    global h
    assert o in h, o[:70]; h = h.replace(o, n, 1)
rep("#!/bin/bash\n", "#!/bin/bash\n# HL_PROBE variant: Agent override moved off the flow-create path (kernel-only hard limit for 'flow create') + bpftrace at the mlx5 command-submission boundary.\n")
rep("FC_OFF=0x119e2d0;", "FC_OFF=0x119e2d0; FV_OFF=0x119e110;   # rte_flow_validate (HL_PROBE decoy target for the Agent override)\n")
rep('CHAP_RES_BPF="$RA/r_precheck_agent.bpf.o" CHAP_RFC_OFF=$FC_OFF', 'CHAP_RES_BPF="$RA/r_precheck_agent.bpf.o" CHAP_RFC_OFF=$FV_OFF')
rep('''grep -qa 'resource Agent (r_precheck) attached' "$O/loader.log" || refuse "resource_override_attach"''',
    '''grep -qa 'resource Agent (r_precheck) attached' "$O/loader.log" || refuse "resource_override_attach"
say "HL_PROBE: resource Agent override attached to rte_flow_validate (off the flow-create path) -> kernel-only hard limit for flow create"''')
old_q = h[h.index('else\n  tl RESOURCE_API_FIRST_CALL quota-mode;'):]
old_q = old_q[:old_q.index('\nfi\n') + 4]
new_q = r'''else
  LIBM=$(readlink -f /usr/local/lib/libmlx5.so.1); BT=$O/hl_bpftrace.txt
  cat > $O/hl.bt <<EOF2
uprobe:$TESTPMD:mlx5_flow_create /pid == $TPID && tid == $TPID/ { printf("%llu ENTRY mlx5_flow_create\n", nsecs); }
uretprobe:$TESTPMD:mlx5_flow_create /pid == $TPID && tid == $TPID/ { printf("%llu RETURN mlx5_flow_create ret=0x%llx\n", nsecs, retval); }
uprobe:$LIBM:mlx5dv_dr_rule_create /pid == $TPID && tid == $TPID/ { printf("%llu SUBMIT mlx5dv_dr_rule_create\n", nsecs); }
uprobe:$LIBM:mlx5dv_create_flow /pid == $TPID && tid == $TPID/ { printf("%llu SUBMIT mlx5dv_create_flow\n", nsecs); }
uprobe:$LIBM:mlx5dv_devx_obj_create /pid == $TPID && tid == $TPID/ { printf("%llu SUBMIT mlx5dv_devx_obj_create\n", nsecs); }
uprobe:$LIBM:mlx5dv_dr_matcher_create /pid == $TPID && tid == $TPID/ { printf("%llu SUBMIT mlx5dv_dr_matcher_create\n", nsecs); }
uprobe:$LIBM:mlx5dv_create_flow_matcher /pid == $TPID && tid == $TPID/ { printf("%llu SUBMIT mlx5dv_create_flow_matcher\n", nsecs); }
tracepoint:syscalls:sys_enter_ioctl /pid == $TPID && tid == $TPID/ { printf("%llu IOCTL fd=%d cmd=0x%lx\n", nsecs, args->fd, args->cmd); }
EOF2
  bpftrace $O/hl.bt > $BT 2>&1 & BTP=$!
  for i in $(seq 1 40); do grep -q "Attaching" $BT && break; sleep 1; done; sleep 3
  tl RESOURCE_API_FIRST_CALL hl-probe-mode
  for i in $(seq 1 $((HARD+1))); do kill -0 $TPID 2>/dev/null || break; tl HL_FLOW_CREATE_$i; echo "flow create 0 ingress pattern eth / end actions drop / end" >&3; sleep 2; done
  sleep 2; ALIVE=$(kill -0 $TPID 2>/dev/null && echo YES || echo NO); kill -INT $BTP 2>/dev/null; sleep 2
  kill -USR1 $SPID 2>/dev/null; sleep 1; RU=$(grep -aE 'USAGE api_calls' "$O/rsent.log"|tail -1)
  python3 -I "$MG/chap_hl_tools.py" "$BT" "$HARD" > "$O/hl_analysis.txt" 2>&1; HLR=$?
  { [ "$HLR" = 0 ] && [ "$ALIVE" = NO ]; } \
    && mark hardlimit_nic_boundary REQUIRED PASS "$(grep HL_RESULT $O/hl_analysis.txt) ; tenant killed ; $RU" \
    || mark hardlimit_nic_boundary REQUIRED FAIL "$(grep -E 'HL_RESULT|CALL' $O/hl_analysis.txt | tr '\n' ' ') alive=$ALIVE ; $RU"
fi
'''
h = h.replace(old_q, new_q, 1)
open(MG + "/run_3plane_F_hl.sh", "w").write(h)
import os; os.chmod(MG + "/run_3plane_F_hl.sh", 0o755)
open(MG + "/chap_hl_tools.py", "w").write(r'''#!/usr/bin/env python3
"""Split bpftrace events into per-mlx5_flow_create windows; the last (crossing) call must show the entry
probe but no RETURN and no command-submission activity (rdma-core submit calls / ioctl) before the kill."""
import re, sys
ev = []
for ln in open(sys.argv[1], errors="replace"):
    m = re.match(r"(\d+) (ENTRY|RETURN|SUBMIT|IOCTL)\b(.*)", ln.strip())
    if m: ev.append((int(m.group(1)), m.group(2), m.group(3).strip()))
ev.sort(); hard = int(sys.argv[2])
wins = []
for t, k, d in ev:
    if k == "ENTRY": wins.append({"t": t, "ret": None, "sub": [], "ioc": 0})
    elif wins:
        w = wins[-1]
        if k == "RETURN": w["ret"] = d
        elif k == "SUBMIT": w["sub"].append(d)
        elif k == "IOCTL": w["ioc"] += 1
for i, w in enumerate(wins, 1):
    print(f"CALL {i}: returned={'yes ' + w['ret'] if w['ret'] else 'NO'} submit_calls={len(w['sub'])} {sorted(set(w['sub']))} ioctls={w['ioc']}")
ok = len(wins) == hard + 1 and all(w["ret"] and (w["sub"] or w["ioc"]) for w in wins[:hard]) \
     and wins[-1]["ret"] is None and not wins[-1]["sub"] and wins[-1]["ioc"] == 0
print(f"HL_RESULT {'PASS' if ok else 'FAIL'}: calls={len(wins)} admitted_with_submission={sum(1 for w in wins[:hard] if w['ret'] and (w['sub'] or w['ioc']))}/{hard} "
      f"crossing_call: entry=yes return={'yes' if wins and wins[-1]['ret'] else 'no'} submit={len(wins[-1]['sub']) if wins else '?'} ioctl={wins[-1]['ioc'] if wins else '?'}")
sys.exit(0 if ok else 1)
''')
print("wrote run_3plane_F_hl.sh + chap_hl_tools.py")

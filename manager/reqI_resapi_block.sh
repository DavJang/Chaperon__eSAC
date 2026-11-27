# Chaperon Request I: Table tab:apis at runtime. Sourced by run_3plane_F.sh when RESAPI=1, after the
# rte_flow_create quota test (forwarding stopped, prompt up). The Manager changes the tenant policy LIVE
# (root, pinned resource_policy); the tenant only issues API calls on its prompt.
#   RESAPI_BYPASS=dev_start|rxq_config  (with RES_OMIT=agent_dev_start|agent_dev_configure): TEST-ONLY, the
#   Agent pre-check of that API is left out, so the over-policy call reaches the kernel Sentinel (hard limit).
RU2(){ kill -USR1 $SPID 2>/dev/null; sleep 1; grep -a "USAGE2" "$O/rsent.log" | tail -1; }
RU1(){ grep -a "USAGE api_calls" "$O/rsent.log" | tail -1; }
fv(){ echo "$1" | grep -oE "(^| )$2=[0-9,]+" | head -1 | cut -d= -f2; }
au(){ fv "$1" api_used | cut -d, -f$(( $2 + 1 )); }
pol(){ "$RPOL" "$PIND/resource_policy" 0 "$@" >> "$O/respolicy.log" 2>&1; }
tp(){ echo "$1" >&3; sleep ${2:-1}; }
alive(){ kill -0 $TPID 2>/dev/null && echo YES || echo NO; }
lg(){ grep -ac -- "$1" "$W/testpmd.log"; }
EAG="Resource temporarily unavailable|Unknown error 11"   # DPDK rte_strerror() prints EAGAIN as "Unknown error 11" (GNU strerror_r)
say "===== Request I RESAPI: NIC control / Port / Memory / Launch (runtime) ====="
R=$(RU2); echo "RESAPI_START $R" >> "$O/resapi.txt"

if [ -n "${RESAPI_BYPASS:-}" ]; then
  # ---- TEST-ONLY: Agent pre-check omitted -> the over-policy call must be stopped by the kernel Sentinel ----
  D0=$(fv "$R" denied2)
  case "$RESAPI_BYPASS" in
    dev_start)  DS=$(au "$R" 2); pol dev_start.budget=$DS; tp "port stop 0" 3; tp "port start 0" 4 ;;
    rxq_config) pol max_rxq=1; tp "port stop 0" 3; tp "port config all rxq 2" 1; tp "port start 0" 4 ;;
  esac
  sleep 2; A=$(alive); R=$(RU2); D1=$(fv "$R" denied2)
  [ -z "$D1" ] && D1=$(grep -a "USAGE2" "$O/rsent.log" | tail -1 | grep -oE "denied2=[0-9]+" | cut -d= -f2)
  TRC=NA; [ "$A" = NO ] && { wait $LJOB 2>/dev/null; TRC=$?; }
  LST=$(grep -aE "Port 0: link|Configuring Port 0|Fail to" "$W/testpmd.log" | tail -2 | tr '\n' ' ')
  { [ "$A" = NO ] && [ "${D1:-0}" -gt "${D0:-0}" ]; } \
    && mark resource_sentinel_hardlimit_$RESAPI_BYPASS REQUIRED PASS "Agent pre-check OMITTED (TEST-ONLY $RES_OMIT): over-policy $RESAPI_BYPASS reached the driver entry -> kernel Sentinel SIGKILL (tenant alive=$A rc=$TRC) denied2 ${D0}->${D1}; last tenant lines: $LST" \
    || mark resource_sentinel_hardlimit_$RESAPI_BYPASS REQUIRED FAIL "alive=$A rc=$TRC denied2 ${D0}->${D1}"
  echo "RESAPI_BYPASS_END $R" >> "$O/resapi.txt"
  return 0 2>/dev/null || true
fi

# ---- NIC control 1: flow flush / destroy -- exact holdings + per-API budget (live update) ----
U=$(RU1); H0=$(fv "$U" flow_held); FL0=$(au "$R" 1)
tp "flow flush 0" 2
R=$(RU2); U=$(RU1); H1=$(fv "$U" flow_held); FL1=$(au "$R" 1)
tp "flow create 0 ingress pattern eth / end actions drop / end" 1; tp "flow create 0 ingress pattern eth / end actions drop / end" 1
R=$(RU2); U=$(RU1); H2=$(fv "$U" flow_held); FD0=$(au "$R" 0)
pol flow_destroy.budget=$((FD0+1))          # one more driver destroy allowed (a budget of 0 would mean "no limit")
CE0=$(lg "Caught PMD error"); tp "flow destroy 0 rule 0" 1; tp "flow destroy 0 rule 1" 1
R=$(RU2); U=$(RU1); H3=$(fv "$U" flow_held); FD1=$(au "$R" 0); CE1=$(lg "Caught PMD error")
pol flow_destroy.budget=0; tp "flow destroy 0 rule 1" 1
R=$(RU2); U=$(RU1); H4=$(fv "$U" flow_held); FD2=$(au "$R" 0); A=$(alive)
echo "NIC_FLOW held $H0->flush->$H1 ->create x2->$H2 ->destroy r0 ok, r1 denied->$H3 ->destroy r1->$H4 ; flush_used $FL0->$FL1 ; destroy_used $FD0->$FD1->$FD2 ; complain $CE0->$CE1 ; alive=$A" >> "$O/resapi.txt"
{ [ "$H0" = "$HARD" ] && [ "$H1" = 0 ] && [ "$FL1" = $((FL0+1)) ] && [ "$H2" = 2 ] && [ "$H3" = 1 ] && [ "$FD1" = $((FD0+1)) ] && [ "$CE1" = $((CE0+1)) ] && [ "$H4" = 0 ] && [ "$FD2" = $((FD0+2)) ] && [ "$A" = YES ]; } \
  && mark resapi_nic_flow_flush_destroy REQUIRED PASS "flow_held $H0 -flush-> $H1 (mlx5_flow_flush ret=0 releases all) -create x2-> $H2; destroy budget $((FD0+1)): rule 0 destroyed, rule 1 pre-denied by the Agent (driver destroys $FD0->$FD1, held $H3); live update unlimited -> rule 1 destroyed, held $H4, driver destroys $FD2; tenant alive" \
  || mark resapi_nic_flow_flush_destroy REQUIRED FAIL "$(tail -1 $O/resapi.txt)"

# ---- NIC control 2: dev_start budget (Fig. policy: budget 1) + live update; Port restart keeps protection ----
R=$(RU2); DS0=$(au "$R" 2); DT0=$(au "$R" 3); F0=$(lg "Fail to start port")
pol dev_start.budget=$DS0
tp "port stop 0" 3; tp "port start 0" 4
R=$(RU2); DS1=$(au "$R" 2); DT1=$(au "$R" 3); F1=$(lg "Fail to start port"); FE=$(grep -a "Fail to start port 0" "$W/testpmd.log" | tail -1)
pol dev_start.budget=$((DS0+1)); tp "port start 0" 5
R=$(RU2); DS2=$(au "$R" 2); F2=$(lg "Fail to start port"); A=$(alive)
echo "NIC_DEVSTART start_used $DS0->$DS1->$DS2 stop_used $DT0->$DT1 fail $F0->$F1->$F2 [$FE] alive=$A" >> "$O/resapi.txt"
{ [ "$DS0" -ge 1 ] && [ "$DS1" = "$DS0" ] && [ "$DT1" = $((DT0+1)) ] && [ "$F1" = $((F0+1)) ] && echo "$FE" | grep -qE "$EAG" && [ "$DS2" = $((DS0+1)) ] && [ "$F2" = "$F1" ] && [ "$A" = YES ]; } \
  && mark resapi_nic_dev_start_budget REQUIRED PASS "budget=$DS0 already used by the launch start -> port start pre-denied by the Agent ('$FE'), driver starts stay $DS1; live update budget=$((DS0+1)) -> start OK ($DS2); tenant alive" \
  || mark resapi_nic_dev_start_budget REQUIRED FAIL "$(tail -1 $O/resapi.txt)"
pol dev_start.budget=0
# protection after the port stop/start: the same L4 policy still allows/drops on the restarted queues
echo "start" >&3; sleep 2
A0=$(RXP|awk '{print $6+0}'); D0=$(RXP|awk '{print $5+0}')
gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2; gen 2000 10.0.0.9 $MDIP $MSP $MDP udp >/dev/null; sleep 2
A1=$(RXP|awk '{print $6+0}'); D1=$(RXP|awk '{print $5+0}'); echo "stop" >&3; sleep 1
{ [ $((A1-A0)) -gt 1000 ] && [ $((D1-D0)) -gt 1000 ]; } \
  && mark comm_after_port_restart REQUIRED PASS "after port stop/start: match->allow+=$((A1-A0)) nomatch->drop+=$((D1-D0)) (hooks + policy survive the queue re-creation)" \
  || mark comm_after_port_restart REQUIRED FAIL "allow+=$((A1-A0)) drop+=$((D1-D0))"

# ---- NIC control 3: promiscuous rate (GCRA 1/s, burst 1) ----
R=$(RU2); PE0=$(au "$R" 4); PD0=$(au "$R" 5); PX0=$(grep -a "promiscuous mode" "$W/testpmd.log" | grep -cE "$EAG")
pol promisc_en.rate=1 promisc_en.burst=1; sleep 1.2
for i in 1 2 3; do echo "set promisc 0 off" >&3; sleep 0.1; echo "set promisc 0 on" >&3; sleep 0.1; done; sleep 1
R=$(RU2); PE1=$(au "$R" 4); PD1=$(au "$R" 5); PX1=$(grep -a "promiscuous mode" "$W/testpmd.log" | grep -cE "$EAG"); A=$(alive)
pol promisc_en.rate=0 promisc_en.burst=0; tp "set promisc 0 on" 1
echo "NIC_PROMISC en_used $PE0->$PE1 dis_used $PD0->$PD1 eagain $PX0->$PX1 alive=$A" >> "$O/resapi.txt"
{ [ "$PE1" = $((PE0+1)) ] && [ "$PX1" = $((PX0+2)) ] && [ "$A" = YES ]; } \
  && mark resapi_nic_promisc_rate REQUIRED PASS "rate 1/s burst 1: 3 rapid enables -> 1 reached the driver ($PE0->$PE1), 2 pre-denied -EAGAIN by the Agent; disables (unlimited) $PD0->$PD1; tenant alive" \
  || mark resapi_nic_promisc_rate REQUIRED FAIL "$(tail -1 $O/resapi.txt)"

# ---- NIC control 4: multicast list budget ----
R=$(RU2); MC0=$(au "$R" 6); MX0=$(lg "set_mc_addr_list(port=0")
pol mc_addr.budget=$((MC0+1))
tp "mcast_addr add 0 01:00:5e:00:00:01" 1; tp "mcast_addr add 0 01:00:5e:00:00:02" 1
R=$(RU2); MC1=$(au "$R" 6); MX1=$(lg "set_mc_addr_list(port=0"); ML=$(grep -a "set_mc_addr_list(port=0" "$W/testpmd.log" | tail -1); A=$(alive)
pol mc_addr.budget=0
echo "NIC_MC used $MC0->$MC1 failed $MX0->$MX1 [$ML] alive=$A" >> "$O/resapi.txt"
{ [ "$MC1" = $((MC0+1)) ] && [ "$MX1" -gt "$MX0" ] && echo "$ML" | grep -q "diag=-11" && [ "$A" = YES ]; } \
  && mark resapi_nic_mc_addr_budget REQUIRED PASS "budget $((MC0+1)): first set_mc_addr_list reached the driver ($MC0->$MC1), second pre-denied ('$ML'); tenant alive" \
  || mark resapi_nic_mc_addr_budget REQUIRED FAIL "$(tail -1 $O/resapi.txt)"

# ---- Port: queues of the VF (configure / queue setup) ----
R=$(RU2); RC0=$(fv "$R" rxq_cfg); RU0=$(fv "$R" rxq_used); G0=$(fv "$R" denied2); FC0=$(lg "Fail to configure port 0")
pol max_rxq=1 max_txq=1
tp "port stop 0" 3; tp "port config all rxq 2" 1; tp "port start 0" 4
R=$(RU2); RC1=$(fv "$R" rxq_cfg); FC1=$(lg "Fail to configure port 0"); A1=$(alive)
pol max_rxq=2; tp "port start 0" 5
R=$(RU2); RC2=$(fv "$R" rxq_cfg); RU2v=$(fv "$R" rxq_used)
tp "port stop 0" 3; pol max_rxq=1; QS0=$(lg "Failed to setup RX queue"); tp "port 0 rxq 1 setup" 2
R=$(RU2); RU3=$(fv "$R" rxq_used); QS1=$(lg "Failed to setup RX queue")
tp "port config all rxq 1" 1; tp "port start 0" 5
R=$(RU2); RC4=$(fv "$R" rxq_cfg); G1=$(fv "$R" denied2); A=$(alive)
echo "PORT rxq_cfg $RC0->deny->$RC1 ->max2->$RC2 (used $RU0->$RU2v) setup-deny used=$RU3 qsfail $QS0->$QS1 ->rxq1->$RC4 ; cfgfail $FC0->$FC1 denied2 $G0->$G1 alive=$A1/$A" >> "$O/resapi.txt"
{ [ "$FC1" = $((FC0+1)) ] && [ "$RC1" = "$RC0" ] && [ "$RC2" = 2 ] && [ "$RU2v" = 2 ] && [ "$QS1" = $((QS0+1)) ] && [ "$RC4" = 1 ] && [ "$G1" = "$G0" ] && [ "$A" = YES ]; } \
  && mark resapi_port_queues REQUIRED PASS "max_rxq=1: configure(2 rxq) pre-denied (Sentinel rxq_cfg stays $RC1); live max_rxq=2 -> configured $RC2, set up $RU2v; max_rxq=1: queue 1 setup pre-denied; back to 1 rxq -> $RC4; no Sentinel kill (denied2 $G0->$G1); tenant alive" \
  || mark resapi_port_queues REQUIRED FAIL "$(tail -1 $O/resapi.txt)"
pol max_rxq=0 max_txq=0

# ---- Memory: Sentinel accounting is exact across release/re-creation (port stop/start frees + re-allocates) ----
R=$(RU2); M0=$(fv "$R" mem_bytes); MB0=$(fv "$R" mbufs)
for c in 1 2; do tp "port stop 0" 3; tp "port start 0" 5; R=$(RU2); eval "MC$c=$(fv "$R" mem_bytes)"; done
echo "MEM mem_bytes base=$M0 cycle1=$MC1 cycle2=$MC2 mbufs=$MB0 (testpmd --total-num-mbufs=4096)" >> "$O/resapi.txt"
{ [ "$MB0" = 4096 ] && [ "$MC1" = "$MC2" ] && [ "${M0:-0}" -gt 0 ]; } \
  && mark resapi_memory_accounting REQUIRED PASS "mbufs held=$MB0 (= --total-num-mbufs); heap bytes base=$M0, after stop/start cycle1=$MC1 cycle2=$MC2 (release+re-allocate returns to the same value)" \
  || mark resapi_memory_accounting REQUIRED FAIL "$(tail -1 $O/resapi.txt)"

# ---- Launch: worker launch outside the admitted lcores; kernel cpuset backstop ----
LF0=$(lg "launch lcore 7 failed")
pol lcores=6; tp "start" 2; tp "stop" 2
LF1=$(lg "launch lcore 7 failed"); LL=$(grep -a "launch lcore 7 failed" "$W/testpmd.log" | tail -1)
pol lcores=6,7; tp "start" 2; tp "stop" 2; LF2=$(lg "launch lcore 7 failed"); A=$(alive)
TS=$(taskset -pc 8 $TPID 2>&1 | grep -i "failed" | head -1)
CAL=$(cat /proc/$TPID/task/*/status 2>/dev/null | awk '/^Cpus_allowed_list/{print $2}' | sort -u | paste -sd' ' -)   # every thread
CPE=$(cat $CGDIR/cpuset.cpus.effective 2>/dev/null); CALOK=1; for c in $CAL; do case "$c" in 6|7|6-7) ;; *) CALOK=0 ;; esac; done
HC=$(cat $CGDIR/hugetlb.2MB.current 2>/dev/null); HM=$(cat $CGDIR/hugetlb.2MB.max 2>/dev/null)
echo "LAUNCH remote_launch fail $LF0->$LF1->$LF2 [$LL] taskset8='$TS' cgroup_cpus=$CPE thread_cpus_allowed='$CAL' hugetlb.2MB current=$HC max=$HM alive=$A" >> "$O/resapi.txt"
{ [ "$LF1" = $((LF0+1)) ] && echo "$LL" | grep -q "diag=-11" && [ "$LF2" = "$LF1" ] && echo "$TS" | grep -qi "invalid argument" && [ "$CPE" = "6-7" ] && [ "$CALOK" = 1 ] && [ "${HC:-x}" -le "${HM:-0}" ] && [ "$A" = YES ]; } \
  && mark resapi_launch_lcores REQUIRED PASS "lcores={6}: worker launch on lcore 7 pre-denied ('$LL'); live {6,7} -> launched; kernel cpuset $CPE: taskset to CPU 8 refused ('$TS'), every thread within {6,7} ($CAL); hugetlb.2MB current=$HC <= max=$HM" \
  || mark resapi_launch_lcores REQUIRED FAIL "$(tail -1 $O/resapi.txt)"

# ---- Memory: memory-API rate vs PMD-internal allocations (Request J semantics). The rate covers memory API calls;
#      allocations the PMD makes inside rte_eth_dev_start are nested in that call: the request pays one token at its
#      first allocation, the rest take none, so a port restart (stop, 3 s, start) under 1/s burst 1 must succeed
#      without Agent NULL or kill. Graceful NULL / kernel kill of direct memory
#      API calls: MEMJ tests (reqJ_memrate_block.sh). ----
R=$(RU2); MU0=$(au "$R" 7); G0=$(fv "$R" denied2); FS0=$(lg "Fail to start port 0")
pol mem.rate=1 mem.burst=1; sleep 2; tp "port stop 0" 3; tp "port start 0" 5
R=$(RU2); MU1=$(au "$R" 7); G1=$(fv "$R" denied2); FS1=$(lg "Fail to start port 0"); A=$(alive)
pol mem.rate=0 mem.burst=0
echo "MEMRATE port restart under 1/s burst 1: memory tokens $MU0->$MU1 start_fail $FS0->$FS1 denied2 $G0->$G1 alive=$A" >> "$O/resapi.txt"
{ [ "$FS1" = "$FS0" ] && [ $((MU1-MU0)) -ge 1 ] && [ $((MU1-MU0)) -le 2 ] && [ "$G1" = "$G0" ] && [ "$A" = YES ]; }   && mark resapi_memory_rate REQUIRED PASS "mem rate 1/s burst 1: port stop/start OK, one memory token per ethdev request that allocates ($MU0->$MU1), further PMD allocations nested, no kill (Request J)"   || mark resapi_memory_rate REQUIRED FAIL "$(tail -1 $O/resapi.txt)"

R=$(RU2); echo "RESAPI_END $R" >> "$O/resapi.txt"

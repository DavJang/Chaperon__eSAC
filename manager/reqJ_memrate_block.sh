# Chaperon Request J: memory-API rate at the sealed-dispatch boundary, on the real non-root tenant.
# Sourced by run_3plane_F.sh when MEMJ is set (forwarding stopped). Calls are issued inside testpmd by the
# TEST-ONLY driver thread "chap-memapi" (chap_memapi_test.so) exactly as application code would.
#   MEMJ=agent  Agent pre-check active: launch, normal calls, Agent graceful NULL (alloc/free, quota flat),
#               nested pool creation and PMD port restart under 1/s, 2-CPU exact GCRA accounting
#   MEMJ=kill   RES_PASS=1 (Agent pre-check replaced by a pass-through, hook + boundary kept): kernel SIGKILL at the
#               boundary, the killed call never reaches malloc_heap_alloc, holdings flat (alloc/free)
#   MEMJ=race   RES_PASS=1: two CPUs race over a burst of 500 -> exactly 500 admitted, then SIGKILL
#   MEMJ=forge  RES_PASS=1: tenant code calls the boundary function directly (forged outer ethdev call) and issues
#               memory calls inside it -> one token per forged request, SIGKILL when the rate is used up
#               (RS_OBJ=<older Sentinel object>: same attack against that object, reported as INFO)
MC=/tmp/chap_memapi_cmd_$TPID; MO=$W/tenant_cwd/memapi_out.txt; : > $MC; chmod 644 $MC
u3(){ kill -USR1 $SPID 2>/dev/null; sleep 1; grep -a "USAGE3" "$O/rsent.log" | tail -1; }
u2(){ grep -a "USAGE2" "$O/rsent.log" | tail -1; }
fv(){ echo "$1" | grep -oE "(^| )$2=[0-9]+" | head -1 | cut -d= -f2; }
pol(){ "$RPOL" "$PIND/resource_policy" 0 "$@" >> "$O/respolicy.log" 2>&1; }
alive(){ kill -0 $TPID 2>/dev/null && echo YES || echo NO; }
mono(){ python3 -c "import time;print(time.monotonic_ns())"; }
nres(){ grep -ac "^RESULT" $MO 2>/dev/null || echo 0; }
mrun(){ local n0; n0=$(nres); echo "$1" >> $MC; for i in $(seq 1 ${2:-120}); do [ "$(nres)" -gt "$n0" ] && break; kill -0 $TPID 2>/dev/null || break; sleep 0.5; done; grep -a "^RESULT" $MO 2>/dev/null | tail -1; }
rf(){ echo "$1" | grep -oE "(^| )$2=[0-9]+" | head -1 | cut -d= -f2; }
J=$O/memj.txt; : > $J
say "===== Request J MEMJ=$MEMJ: memory-API rate at the sealed-dispatch boundary ====="
GATES=$(grep -a "attached rs_gate_" "$O/rsent.log" | tr '\n' ' ')

if [ "$MEMJ" = agent ]; then
  # J6a launch (EAL init, testpmd init, port start, mbuf pool) under the launch policy (RESPOL_EXTRA: finite memory rate)
  R=$(u3); echo "LAUNCH $R | $(u2) | $(grep -a NESTMAX $O/rsent.log | tail -1)" >> $J
  LC=$(fv "$R" mem_calls); LN=$(fv "$R" mem_nested); LS=$(fv "$R" gate_stale)
  { [ "${LN:-0}" -gt 0 ] && [ "${LS:-1}" = 0 ] && [ "$(alive)" = YES ]; } \
    && mark memj_launch_nested REQUIRED PASS "launch under '${RESPOL_EXTRA:-}': outermost memory API calls taxed=$LC, nested (EAL/PMD/pool internals, no token)=$LN, stale=$LS; no kill" \
    || mark memj_launch_nested REQUIRED FAIL "$(tail -1 $J)"
  # J1 normal calls within the rate
  pol mem.rate=100 mem.burst=20; sleep 0.5
  R=$(u3); C0=$(fv "$R" mem_calls); RES=$(mrun "malloc 20 256 20000 1"); R=$(u3); C1=$(fv "$R" mem_calls)
  echo "J1 rate 100/s burst 20: $RES calls $C0->$C1" >> $J
  { [ "$(rf "$RES" ok)" = 20 ] && [ "$(rf "$RES" null)" = 0 ] && [ $((C1-C0)) = 20 ] && [ "$(alive)" = YES ]; } \
    && mark memj_normal_allowed REQUIRED PASS "20 rte_malloc/rte_free at 50/s within 100/s: ok=20 null=0; kernel boundary took 20 tokens ($C0->$C1)" \
    || mark memj_normal_allowed REQUIRED FAIL "$(tail -1 $J)"
  # J2 + J5a Agent graceful NULL on alloc/free (holdings flat, rate exceeded)
  pol mem.rate=5 mem.burst=3; sleep 1.5
  R=$(u3); C0=$(fv "$R" mem_calls); M0=$(fv "$(u2)" mem_bytes); G0=$(fv "$(u2)" denied2)
  RES=$(mrun "malloc 30 4096 0 1"); R=$(u3); C1=$(fv "$R" mem_calls); M1=$(fv "$(u2)" mem_bytes); G1=$(fv "$(u2)" denied2)
  OK=$(rf "$RES" ok); NL=$(rf "$RES" null)
  echo "J2 rate 5/s burst 3: $RES calls $C0->$C1 mem_bytes $M0->$M1 denied2 $G0->$G1" >> $J
  { [ "${OK:-0}" -ge 3 ] && [ "${OK:-0}" -le 4 ] && [ $((OK+NL)) = 30 ] && [ $((C1-C0)) = "$OK" ] && [ "$M1" = "$M0" ] && [ "$G1" = "$G0" ] && [ "$(alive)" = YES ]; } \
    && mark memj_agent_graceful REQUIRED PASS "30 rapid rte_malloc/rte_free, rate 5/s burst 3: Agent NULL for $NL, $OK admitted; kernel tokens only for admitted calls ($C0->$C1); heap bytes flat ($M0->$M1); no kill" \
    || mark memj_agent_graceful REQUIRED FAIL "$(tail -1 $J)"
  # J6b nested pool creation under 1/s burst 1: one token, nested allocations exempt, no Agent NULL inside
  pol mem.rate=1 mem.burst=1; sleep 2
  R=$(u3); C0=$(fv "$R" mem_calls); N0=$(fv "$R" mem_nested); RES=$(mrun "pool 1024"); R=$(u3); C1=$(fv "$R" mem_calls); N1=$(fv "$R" mem_nested)
  echo "J6b pool under 1/s burst 1: $RES calls $C0->$C1 nested $N0->$N1" >> $J
  { echo "$RES" | grep -q " ok " && [ $((C1-C0)) = 1 ] && [ $((N1-N0)) -ge 2 ] && [ "$(alive)" = YES ]; } \
    && mark memj_nested_pool REQUIRED PASS "rte_pktmbuf_pool_create(1024) under 1/s burst 1 succeeded: 1 token, $((N1-N0)) nested memory API calls without token or Agent NULL" \
    || mark memj_nested_pool REQUIRED FAIL "$(tail -1 $J)"
  # J6c PMD internal allocations of port stop/start under 1/s burst 1
  sleep 2; R=$(u3); C0=$(fv "$R" mem_calls); N0=$(fv "$R" mem_nested); F0=$(grep -ac "Fail to start port" "$W/testpmd.log")
  echo "port stop 0" >&3; sleep 3; echo "port start 0" >&3; sleep 5
  R=$(u3); C1=$(fv "$R" mem_calls); N1=$(fv "$R" mem_nested); F1=$(grep -ac "Fail to start port" "$W/testpmd.log"); S1=$(fv "$R" gate_stale)
  echo "J6c port stop/start under 1/s burst 1: calls $C0->$C1 nested $N0->$N1 start_fail $F0->$F1 stale=$S1" >> $J
  { [ "$F1" = "$F0" ] && [ $((C1-C0)) -ge 1 ] && [ $((C1-C0)) -le 2 ] && [ "$N1" -gt "$N0" ] && [ "$(alive)" = YES ]; } \
    && mark memj_nested_pmd REQUIRED PASS "port stop/start under 1/s burst 1: one memory token per ethdev request that allocates ($C0->$C1, at its first PMD allocation), the further PMD allocations nested ($N0->$N1, no token), start OK, no kill" \
    || mark memj_nested_pmd REQUIRED FAIL "$(tail -1 $J)"
  # (runs before J7a: J7a moves the TAT far ahead on purpose)
  # J6d first PMD allocation of an ethdev request with no token left -> Agent graceful NULL (start fails, no kill,
  #     no kernel token for the denied request); after refill the same request is admitted and charged once
  pol mem.rate=1 mem.burst=1; sleep 2
  R=$(u3); C0=$(fv "$R" mem_calls); G0=$(fv "$(u2)" denied2)
  RES=$(mrun "devrestart 0 2500" 60); R=$(u3); C1=$(fv "$R" mem_calls); G1=$(fv "$(u2)" denied2)
  S1=$(echo "$RES" | grep -oE "start1=-?[0-9]+" | cut -d= -f2); S2=$(echo "$RES" | grep -oE "start2=-?[0-9]+" | cut -d= -f2)
  echo "J6d devrestart under 1/s burst 1 (token taken by one rte_malloc first): $RES calls $C0->$C1 denied2 $G0->$G1" >> $J
  { echo "$RES" | grep -q "malloc=ok" && [ "${S1:-0}" -lt 0 ] && [ "${S2:-1}" = 0 ] && [ $((C1-C0)) = 2 ] && [ "$G1" = "$G0" ] && [ "$(alive)" = YES ]; } \
    && mark memj_pmd_request_graceful REQUIRED PASS "token used by rte_malloc, then rte_eth_dev_stop+start at once: first PMD allocation denied by the Agent (start1=$S1, graceful), no kill, denied2 $G0->$G1; start again after refill: start2=$S2; kernel tokens $C0->$C1 (rte_malloc + the admitted start only)" \
    || mark memj_pmd_request_graceful REQUIRED FAIL "$(tail -1 $J)"
  echo "port stop 0" >&3; sleep 2; echo "port start 0" >&3; sleep 3   # resync testpmd port state (1 token after refill)
  # J8 API scope: each memory API of Table tab:apis (+ variants) once as an outermost call -> exactly one token each
  pol mem.rate=0 mem.burst=0; SC=""; SOK=1
  for a in malloc zmalloc calloc malloc_socket zmalloc_socket memzone memzone_aligned mempool pktmbuf_pool; do
    R=$(u3); C0=$(fv "$R" mem_calls); N0=$(fv "$R" mem_nested); RES=$(mrun "api $a"); R=$(u3); C1=$(fv "$R" mem_calls); N1=$(fv "$R" mem_nested)
    SC="$SC $a:$(echo $RES | awk '{print $4}'):tok=$((C1-C0)):nest=$((N1-N0))"
    { echo "$RES" | grep -q " ok$" && [ $((C1-C0)) = 1 ]; } || SOK=0
  done
  echo "J8 api scope:$SC" >> $J
  [ "$SOK" = 1 ] && mark memj_api_scope REQUIRED PASS "one outermost call each -> one token each:$SC" || mark memj_api_scope REQUIRED FAIL "$(tail -1 $J)"
  # J7a 2-CPU exact accounting: rate 1/s (T = 1 s), burst 5000 -> all admitted, TAT must advance by exactly N x 1 s
  pol mem.rate=1 mem.burst=5000; sleep 2
  R=$(u3); C0=$(fv "$R" mem_calls); T0=$(fv "$R" mem_tat); t0=$(mono)
  RES=$(mrun "par2 2000 64 6 7" 240); t1=$(mono); R=$(u3); C1=$(fv "$R" mem_calls); T1=$(fv "$R" mem_tat)
  ADM=$((C1-C0)); BASE=$((T1 - ADM * 1000000000))
  echo "J7a par2 2x2000 rate 1/s burst 5000: $RES calls $C0->$C1 tat $T0->$T1 t0=$t0 t1=$t1 admitted=$ADM tat-admitted*1s=$BASE" >> $J
  { [ "$(rf "$RES" ok)" = 4000 ] && [ $((C1-C0)) = 4000 ] && [ "$BASE" -ge "$t0" ] && [ "$BASE" -le "$t1" ] && [ "$(alive)" = YES ]; } \
    && mark memj_atomic_2cpu REQUIRED PASS "2 threads on CPUs 6/7, 2x2000 rte_malloc/rte_free: 4000 admitted, 4000 tokens; TAT advanced by exactly admitted x 1 s (TAT - $ADM s lies in the run window [t0,t1]; one lost update would be 1 s off)" \
    || mark memj_atomic_2cpu REQUIRED FAIL "$(tail -1 $J)"
  pol mem.rate=0 mem.burst=0
  echo "END $(u3) | $(grep -a NESTMAX $O/rsent.log | tail -1)" >> $J
  mark memj_nest_budgets OPTIONAL INFO "$(grep -a NESTMAX $O/rsent.log | tail -1)"
fi

if [ "$MEMJ" = par ]; then   # diagnostic: J7a alone (with RES_PASS=1 the Agent pre-check is a pass-through)
  pol mem.rate=1 mem.burst=5000; sleep 2
  R=$(u3); C0=$(fv "$R" mem_calls); T0=$(fv "$R" mem_tat); t0=$(mono)
  RES=$(mrun "par2 2000 64 6 7" 240); t1=$(mono); R=$(u3); C1=$(fv "$R" mem_calls); T1=$(fv "$R" mem_tat)
  ADM=$((C1-C0)); BASE=$((T1 - ADM * 1000000000))
  echo "PAR res_pass=${RES_PASS:-0}: $RES calls $C0->$C1 admitted=$ADM tat-admitted*1s=$BASE t0=$t0 t1=$t1" >> $J
  mark memj_par_diag OPTIONAL INFO "$(tail -1 $J)"
  pol mem.rate=0 mem.burst=0; final_verdict; cleanup; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0
fi
if [ "$MEMJ" = forge ]; then
  cat > $O/memj.bt <<EOB
uprobe:$W/agent.so:chap_res_gate_enter /pid == $TPID && comm == "chap-memapi"/ { @gate = count(); }
uprobe:$TESTPMD:malloc_heap_alloc /pid == $TPID && comm == "chap-memapi"/ { @heap = count(); }
EOB
  bpftrace $O/memj.bt > $O/memj_bt.txt 2>&1 & BTP=$!
  for i in $(seq 1 40); do grep -q "Attaching" $O/memj_bt.txt && break; sleep 0.5; done; sleep 2
  pol mem.rate=1 mem.burst=3; sleep 4
  R=$(u3); C0=$(fv "$R" mem_calls); N0=$(fv "$R" mem_nested); M0=$(fv "$(u2)" mem_bytes); G0=$(fv "$(u2)" denied2)
  CMD="forge 20 100 4096"; echo "$CMD" >> $MC
  for i in $(seq 1 120); do kill -0 $TPID 2>/dev/null || break; [ "$(nres)" -gt 0 ] && break; sleep 0.5; done; sleep 1
  A=$(alive); TRC=NA; [ "$A" = NO ] && { wait $LJOB 2>/dev/null; TRC=$?; }
  kill -INT $BTP 2>/dev/null; wait $BTP 2>/dev/null
  R=$(u3); C1=$(fv "$R" mem_calls); N1=$(fv "$R" mem_nested); M1=$(fv "$(u2)" mem_bytes); G1=$(fv "$(u2)" denied2)
  GT=$(grep -oE "@gate: [0-9]+" $O/memj_bt.txt | grep -oE "[0-9]+"); HP=$(grep -oE "@heap: [0-9]+" $O/memj_bt.txt | grep -oE "[0-9]+")
  LB=$(grep -a "begin" $MO 2>/dev/null | tail -1); KI=$(echo "$LB" | grep -oE "[0-9]+")
  RSO=$(sha256sum "$RS_OBJ" | cut -c1-8)
  echo "MEMJ=forge rsentinel=$RSO cmd='$CMD' alive=$A rc=$TRC tokens $C0->$C1 nested $N0->$N1 denied2 $G0->$G1 mem_bytes $M0->$M1 gate_enters=$GT heap_allocs=$HP last_begin='$LB' $(grep -a '^RESULT' $MO 2>/dev/null | tail -1) $(u3)" >> $J
  if [ "$RS_OBJ" != "$RK/resource_sentinel.bpf.o" ]; then
    mark memj_forged_gate_other_object OPTIONAL INFO "Sentinel $RSO under the same attack (rate 1/s burst 3, 20 forged ethdev calls x 100 rte_malloc): $(tail -1 $J | cut -c1-400)"
  else
    { [ "$A" = NO ] && [ "$G1" -gt "$G0" ] && [ "${KI:-0}" = $(( (C1-C0) * 100 )) ] && [ "${HP:-x}" = "$KI" ] && [ $((C1-C0)) -ge 3 ] && [ $((C1-C0)) -le 4 ]; } \
      && mark memj_forged_gate_bounded REQUIRED PASS "forged outer calls (tenant code calls chap_res_gate_enter as rte_eth_dev_start, Agent pass-through): each forged request paid one memory token at its first memory call (tokens $C0->$C1, nested $N0->$N1); rate 1/s burst 3 used up -> SIGKILL at call #$KI (rc=$TRC, denied2 $G0->$G1); malloc_heap_alloc $HP = admitted calls; the earlier object exempted all of them" \
      || mark memj_forged_gate_bounded REQUIRED FAIL "$(tail -1 $J | cut -c1-400)"
  fi
  final_verdict; cleanup; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0
fi
if [ "$MEMJ" = kill ] || [ "$MEMJ" = race ]; then
  cat > $O/memj.bt <<EOB
uprobe:$W/agent.so:chap_res_gate_enter /pid == $TPID && comm == "chap-memapi"/ { @gate = count(); }
uprobe:$TESTPMD:malloc_heap_alloc /pid == $TPID && comm == "chap-memapi"/ { @heap = count(); }
EOB
  bpftrace $O/memj.bt > $O/memj_bt.txt 2>&1 & BTP=$!
  for i in $(seq 1 40); do grep -q "Attaching" $O/memj_bt.txt && break; sleep 0.5; done; sleep 2
  if [ "$MEMJ" = kill ]; then pol mem.rate=2 mem.burst=5; CMD="malloc 20 4096 0 1"; EXP=5; else pol mem.rate=1 mem.burst=500; CMD="par2 1000 64 6 7"; EXP=500; fi
  sleep 3
  R=$(u3); C0=$(fv "$R" mem_calls); M0=$(fv "$(u2)" mem_bytes); G0=$(fv "$(u2)" denied2)
  echo "$CMD" >> $MC
  for i in $(seq 1 120); do kill -0 $TPID 2>/dev/null || break; [ "$(nres)" -gt 0 ] && break; sleep 0.5; done; sleep 1
  A=$(alive); TRC=NA; [ "$A" = NO ] && { wait $LJOB 2>/dev/null; TRC=$?; }
  kill -INT $BTP 2>/dev/null; wait $BTP 2>/dev/null
  R=$(u3); C1=$(fv "$R" mem_calls); M1=$(fv "$(u2)" mem_bytes); G1=$(fv "$(u2)" denied2)
  GT=$(grep -oE "@gate: [0-9]+" $O/memj_bt.txt | grep -oE "[0-9]+"); HP=$(grep -oE "@heap: [0-9]+" $O/memj_bt.txt | grep -oE "[0-9]+")
  LB=$(grep -a "begin" $MO 2>/dev/null | tail -1); LR=$(grep -aE "CALL [0-9]+ (ok|null)" $MO 2>/dev/null | tail -1)
  echo "MEMJ=$MEMJ cmd='$CMD' alive=$A rc=$TRC tokens $C0->$C1 denied2 $G0->$G1 mem_bytes $M0->$M1 gate_enters=$GT heap_allocs=$HP last_begin='$LB' last_result='$LR' $(grep -a '^RESULT' $MO 2>/dev/null | tail -1)" >> $J
  if [ "$MEMJ" = kill ]; then
    { [ "$A" = NO ] && [ $((C1-C0)) = $EXP ] && [ "$G1" -gt "$G0" ] && [ "${GT:-0}" = $((EXP+1)) ] && [ "${HP:-0}" = $EXP ] && [ "$M1" = "$M0" ] && [ "$LB" = "CALL $EXP begin" ] && [ "$LR" = "CALL $((EXP-1)) ok" ]; } \
      && mark memj_kernel_hardlimit_kill REQUIRED PASS "Agent pre-check replaced by pass-through (TEST-ONLY), boundary kept: rate 2/s burst 5, 20 rapid rte_malloc/rte_free -> 5 admitted, call #5 SIGKILLed at the boundary (rc=$TRC, denied2 $G0->$G1); gate enters $GT, malloc_heap_alloc $HP: the killed call never reached the allocator; heap bytes flat ($M0->$M1)" \
      || mark memj_kernel_hardlimit_kill REQUIRED FAIL "$(tail -1 $J)"
  else
    { [ "$A" = NO ] && [ $((C1-C0)) = $EXP ] && [ "$G1" -gt "$G0" ] && [ "${HP:-0}" = $EXP ]; } \
      && mark memj_kernel_race_exact REQUIRED PASS "Agent pass-through (TEST-ONLY): two CPUs race over rate 1/s burst 500 -> exactly $((C1-C0)) admitted (atomic CAS), then SIGKILL (rc=$TRC, denied2 $G0->$G1); malloc_heap_alloc $HP = admitted" \
      || mark memj_kernel_race_exact REQUIRED FAIL "$(tail -1 $J)"
  fi
  final_verdict; cleanup; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0
fi

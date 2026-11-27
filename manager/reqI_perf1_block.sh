# Chaperon Request I: ONE representative RX throughput sample (not a sweep), sourced when PERF1=1.
# Peer testpmd txonly, 64 B, single flow 10.0.0.1:1111 -> 10.0.0.2:2222 (the armed exact ALLOW rule) at full
# rate; tenant rxonly on lcore 7; 10 s; rate from the tenant's ethdev stats (telemetry socket, no syscall in the
# tenant). Used to compare filter builds with the same active combos (verification-only probes not attached).
PPF=$W/peer_perf_cmd; mkfifo "$PPF"; chmod 600 "$PPF"
env LD_LIBRARY_PATH=$DPDKLIB setsid stdbuf -oL "$TESTPMD" -l 10,11 -n4 --in-memory --socket-mem 1024,0 -a "$CVF" --file-prefix=peer${$}pf -- -i --tx-ip=10.0.0.1,10.0.0.2 --tx-udp=1111,2222 < "$PPF" > "$O/peer_perf.log" 2>&1 &
exec 6>"$PPF"; for w in $(seq 1 30); do grep -qa "testpmd>" "$O/peer_perf.log" && break; sleep 1; done
echo "set fwd txonly" >&6; echo "set eth-peer 0 $SVFMAC" >&6; sleep 1; echo "start" >&6; sleep 4
echo "show rxq info 0 0" >&3; sleep 1; BMODE=$(grep -a "Burst mode" "$W/testpmd.log" | tail -1 | sed "s/^ *//")   # RX burst function the PMD selected
RSOCK=$DPDKRUN/dpdk/chap3pu${$}/dpdk_telemetry.v2
ipk(){ python3 -I "$MG/chap_e_tools.py" tele "$RSOCK" /ethdev/stats,0 > "$O/tele_$1.json" 2>&1
       python3 -I -c "import json,sys;d=json.load(open(sys.argv[1]))['/ethdev/stats'];print(d['ipackets'],d['imissed'])" "$O/tele_$1.json" 2>/dev/null || echo "0 0"; }
read -r P0 M0 <<< "$(ipk a)"; T0=$(date +%s.%N); sleep 10; read -r P1 M1 <<< "$(ipk b)"; T1=$(date +%s.%N)
echo "stop" >&6; sleep 1; echo "quit" >&6; exec 6>&- 2>/dev/null; sleep 1
PPS=$(python3 -c "print(round(($P1-$P0)/($T1-$T0)))"); MPS=$(python3 -c "print(round(($M1-$M0)/($T1-$T0)))")
echo "PERF1 filter=$(sha256sum $W/c_filter.bpf.o | cut -c1-8) rx_pps=$PPS missed_pps=$MPS rxvec=${RXVEC:-0} [$BMODE] ($(grep -aoE "64-probe active-combo mask=0x[0-9a-f]+ \([0-9]+ active|opt3 probe_mask=0x[0-9a-f]+" $O/loader.log | tr '\n' ' '))" > "$O/perf1.txt"
mark perf1_rx_sample OPTIONAL INFO "$(cat $O/perf1.txt)"
final_verdict; cleanup; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0

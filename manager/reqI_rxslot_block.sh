# Chaperon Request I: which RX burst variant the PMD actually calls (sourced when RXSLOT_PROBE=1; exits).
# Counts sealed RX-dispatcher calls per slot pointer while 2000 packets arrive, maps the slot to the hooked
# function through dispatch.txt (slot table base, 384-byte slots) and the testpmd symbol offsets.
DSYM=_ZL16chap_dispatch_rxPK14chap_disp_slotmmmmmmRN7bpftime7pt_regsE
cat > "$O/rxslot.bt" <<EOB
uprobe:$W/agent.so:$DSYM /pid == $TPID/ { @slot[arg0] = count(); }
EOB
bpftrace "$O/rxslot.bt" > "$O/rxslot_bt.txt" 2>&1 & BTP=$!
for i in $(seq 1 40); do grep -q "Attaching" "$O/rxslot_bt.txt" && break; sleep 0.5; done; sleep 2
gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2
kill -INT $BTP 2>/dev/null; wait $BTP 2>/dev/null
TBASE=$(grep -aE "r-xp .*dpdk-testpmd" /proc/$TPID/maps | head -1 | cut -d- -f1)
: > "$O/rxslot.txt"
for s in $(grep -aoE "@slot\[[0-9]+\]: [0-9]+" "$O/rxslot_bt.txt" | sed -E 's/@slot\[([0-9]+)\]: ([0-9]+)/\1:\2/'); do
  a=$(printf "%x" ${s%%:*}); cnt=${s##*:}
  L=$(grep -a "^DISPATCH slot=" "$O/dispatch.txt" | grep "addr=0x$a ")
  idx=$(echo "$L" | grep -oE "slot=[0-9]+" | cut -d= -f2); fn=$(echo "$L" | grep -oE "func=0x[0-9a-f]+" | cut -d= -f2)
  off=$( [ -n "$fn" ] && printf "%x" $(( fn - 0x$TBASE + 0x27a000 )) )
  name=$(nm "$TESTPMD" | awk -v o="$off" '{x=$1; sub(/^0+/,"",x)} x==o {print $3; exit}')
  echo "slot=${idx:-?} addr=0x$a calls=$cnt func=${name:-unmapped}" >> "$O/rxslot.txt"
done
mark rx_variant_in_use OPTIONAL INFO "rx_vec_en=${RXVEC:-0}: $(tr '\n' ';' < $O/rxslot.txt)"
final_verdict; cleanup; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0

# Chaperon Request I: 64 mask-probe, representative cases on the real NIC (sourced by run_3plane_F.sh, WILD=1).
# Launch policy (pol.json) also carried three combos the 20-probe layout could not express or order:
#   W1 tenant {proto *, src_ip *, dst_ip MDIP, src_port *, dst_port 5555} ALLOW   (protocol wildcard)
#   W2 global {proto 17, src_ip *, dst_ip *, src_port *, dst_port 6666} ALLOW     (global rule)
#   W3 tenant {proto 17, src_ip 10.0.0.9, dst_ip *, src_port *, dst_port *} DROP  (src_ip exact + dst wildcard)
# Live:  W4 tenant {proto *, src_ip *, dst_ip *, src_port 1234, dst_port *} ALLOW  (new combo added at runtime)
wp(){ local a0 d0 a1 d1; a0=$(RXP|awk '{print $6+0}'); d0=$(RXP|awk '{print $5+0}')
      gen 2000 $1 $MDIP $2 $3 $4 none >/dev/null; sleep 2
      a1=$(RXP|awk '{print $6+0}'); d1=$(RXP|awk '{print $5+0}'); echo "$((a1-a0)) $((d1-d0))"; }
al(){ [ "$1" -ge 1900 ] && [ "$2" -le 100 ]; }; dr(){ [ "$2" -ge 1900 ] && [ "$1" -le 100 ]; }
LM=$(grep -aoE "64-probe active-combo mask=0x[0-9a-f]+ \([0-9]+ active" "$O/loader.log" | head -1)
read -r A1 D1 <<< "$(wp 10.0.0.5 1000 5555 udp)"
read -r A2 D2 <<< "$(wp 10.0.0.5 1000 5555 tcp)"
read -r A3 D3 <<< "$(wp 10.0.0.5 1000 6666 udp)"
read -r A4 D4 <<< "$(wp 10.0.0.9 1000 6666 udp)"
read -r A5 D5 <<< "$(wp 10.0.0.5 1000 6666 tcp)"
read -r A6 D6 <<< "$(wp 10.0.0.5 1234 7777 udp)"
"$W/policy_flip" "$CKID" 16384 "$CGID" 0.0.0.0 0.0.0.0 1234 0 0 0 >> "$O/flip.log" 2>&1; FL=$(tail -1 "$O/flip.log"); sleep 1
read -r A7 D7 <<< "$(wp 10.0.0.5 1234 7777 udp)"
read -r A8 D8 <<< "$(wp 10.0.0.5 1234 7777 tcp)"
read -r A9 D9 <<< "$(wp 10.0.0.5 1000 8888 udp)"
{ echo "WILD launch: $LM"
  echo "W1 proto*  udp->5555 allow=$A1 drop=$D1 | tcp->5555 allow=$A2 drop=$D2"
  echo "W2 global  udp->6666 from .5 allow=$A3 drop=$D3 | W3 tenant DROP beats global: udp->6666 from .9 allow=$A4 drop=$D4 | tcp->6666 (W2 is udp) allow=$A5 drop=$D5"
  echo "W4 live    sport 1234 before allow=$A6 drop=$D6 | after [$FL] udp allow=$A7 drop=$D7 tcp allow=$A8 drop=$D8"
  echo "default    udp->8888 allow=$A9 drop=$D9"; } > "$O/wild.txt"
{ al $A1 $D1 && al $A2 $D2 && al $A3 $D3 && dr $A4 $D4 && dr $A5 $D5 && dr $A9 $D9; } \
  && mark comm_wildcard64_launch REQUIRED PASS "$(sed -n 1p $O/wild.txt | cut -c1-80) ; proto-wildcard udp/tcp allow+=$A1/$A2 ; global allow+=$A3 ; tenant DROP over global drop+=$D4 ; proto-exact global misses tcp drop+=$D5 ; default drop+=$D9" \
  || mark comm_wildcard64_launch REQUIRED FAIL "$(sed -n 2,3p $O/wild.txt | tr '\n' ' ') $(sed -n 5p $O/wild.txt)"
{ dr $A6 $D6 && al $A7 $D7 && al $A8 $D8; } \
  && mark comm_wildcard64_live_new_combo REQUIRED PASS "new combo (proto*, sport exact, rest *) added live by the Manager (bit before rule): before drop+=$D6 ; after udp allow+=$A7 tcp allow+=$A8 ; $FL" \
  || mark comm_wildcard64_live_new_combo REQUIRED FAIL "$(sed -n 4p $O/wild.txt)"

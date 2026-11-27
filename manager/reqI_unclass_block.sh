# Chaperon Request I: unclassifiable packets take the default action DROP (sourced when UNCLASS_TEST=1).
# Loader flags from the harness: --frag-drop --malformed-drop --nonip-drop. 500 raw frames per kind from the
# generator VF's kernel netdev; per-kind deltas of the Filter counters (drop / allow / frag / malformed).
CVFDEV=$(ls /sys/bus/pci/devices/$CVF/net/ 2>/dev/null | head -1)
sysctl -qw net.ipv6.conf.$CVFDEV.disable_ipv6=1 2>/dev/null; ip link set $CVFDEV up 2>/dev/null; sleep 2
st(){ RXP | awk '{print $5+0, $6+0, $7+0, $8+0}'; }
: > "$O/unclass.txt"; UOK=1
for kind in arp ipv6 frag_first frag_later bad_version bad_ihl ok; do
  read -r d0 a0 f0 m0 <<< "$(st)"
  python3 -I "$CHAP_ROOT/tests/reqI/rawframes.py" $CVFDEV $SVFMAC $kind 500 >> "$O/unclass_send.txt" 2>&1; sleep 2
  read -r d1 a1 f1 m1 <<< "$(st)"
  dd=$((d1-d0)); da=$((a1-a0)); df=$((f1-f0)); dm=$((m1-m0))
  echo "$kind drop+=$dd allow+=$da frag+=$df malformed+=$dm" >> "$O/unclass.txt"
  case $kind in
    ok)                    [ $da -ge 480 ] && [ $dd -le 20 ] || UOK=0 ;;
    frag_first|frag_later) [ $dd -ge 480 ] && [ $df -ge 480 ] && [ $da -le 20 ] || UOK=0 ;;
    bad_version|bad_ihl)   [ $dd -ge 480 ] && [ $dm -ge 480 ] && [ $da -le 20 ] || UOK=0 ;;
    *)                     [ $dd -ge 480 ] && [ $da -le 20 ] || UOK=0 ;;
  esac
done
ip link set $CVFDEV down 2>/dev/null
[ "$UOK" = 1 ] && mark comm_unclassifiable_default_drop REQUIRED PASS "$(tr '\n' ';' < $O/unclass.txt)" \
               || mark comm_unclassifiable_default_drop REQUIRED FAIL "$(tr '\n' ';' < $O/unclass.txt)"

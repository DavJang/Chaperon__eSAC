# Chaperon Request I: Redis RESP payload policy on the real NIC (sourced by run_3plane_F.sh when RESP=1).
# Rules ($W/hs_rules.txt): evilmal (legacy deny) + allow tcp/6379 /^\*2\r\n\$3\r\nGET\r\n/ (Fig. policy,
# allow-listed service) + drop FLUSHALL (deny, any service). Each request is one packet (no TCP reassembly).
hexs(){ printf '%b' "$1" | od -An -tx1 | tr -d ' \n'; }
RGET=$(hexs '*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n'); RSET=$(hexs '*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$1\r\nv\r\n')
RINL=$(hexs 'GET key\r\n'); RFLU=$(hexs '*1\r\n$8\r\nFLUSHALL\r\n')
# incomplete / not inspectable on the allow-listed service: a 10-byte truncated RESP header (below the 12-byte
# content gate) and the continuation segment of a request split over two TCP segments (no reassembly)
RSHORT=$(hexs '*2\r\n$3\r\nGE'); RCONT=$(hexs 'yvalue123\r\n')
rs(){ local a0 d0 a1 d1; a0=$(RXP|awk '{print $6+0}'); d0=$(RXP|awk '{print $5+0}')
      gen 2000 $MSIP $MDIP $MSP $1 tcp "raw:$2" >/dev/null; sleep 2
      a1=$(RXP|awk '{print $6+0}'); d1=$(RXP|awk '{print $5+0}'); echo "$((a1-a0)) $((d1-d0))"; }
ok(){ [ "$1" -ge 1900 ] && [ "$2" -le 100 ]; }   # expected >=1900 of 2000, other side <=100
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" 6379 6 0 >> "$O/flip.log" 2>&1
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" 6380 6 0 >> "$O/flip.log" 2>&1; sleep 1
read -r G_A G_D <<< "$(rs 6379 "$RGET")"
read -r S_A S_D <<< "$(rs 6379 "$RSET")"
read -r I_A I_D <<< "$(rs 6379 "$RINL")"
read -r E_A E_D <<< "$(rs 6379 "")"
read -r T_A T_D <<< "$(rs 6379 "$RSHORT")"
read -r C_A C_D <<< "$(rs 6379 "$RCONT")"
read -r G2_A G2_D <<< "$(rs 6380 "$RGET")"
read -r F_A F_D <<< "$(rs 6380 "$RFLU")"
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" 6379 6 2 >> "$O/flip.log" 2>&1; sleep 1
read -r R_A R_D <<< "$(rs 6379 "$RGET")"
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" 6380 6 2 >> "$O/flip.log" 2>&1   # test keys back to DROP (99 would reset the whole table)
{ echo "RESP tcp/6379 (allow-listed): GET allow=$G_A drop=$G_D | SET allow=$S_A drop=$S_D | inline 'GET key' allow=$I_A drop=$I_D | no-payload allow=$E_A drop=$E_D | truncated-10B allow=$T_A drop=$T_D | continuation allow=$C_A drop=$C_D"
  echo "RESP tcp/6380 (deny-list only): GET allow=$G2_A drop=$G2_D | FLUSHALL allow=$F_A drop=$F_D"
  echo "RESP tcp/6379 L4=DROP: GET allow=$R_A drop=$R_D"; } > "$O/resp.txt"
{ ok $G_A $G_D && ok $S_D $S_A && ok $I_D $I_A && ok $E_A $E_D && ok $T_D $T_A && ok $C_D $C_A; } \
  && mark l7_resp_allowlist REQUIRED PASS "tcp/6379 allow-listed by 'allow tcp/6379 /^\*2\r\n\$3\r\nGET\r\n/': RESP GET allow+=$G_A (drop $G_D); RESP SET drop+=$S_D, inline GET drop+=$I_D, truncated 10-byte header drop+=$T_D, split-request continuation drop+=$C_D (unmatched/uninspectable -> DROP); payload-less TCP allow+=$E_A (not inspected)" \
  || mark l7_resp_allowlist REQUIRED FAIL "$(head -1 $O/resp.txt)"
{ ok $G2_A $G2_D && ok $F_D $F_A; } \
  && mark l7_denylist_unmatched_keeps_l4 REQUIRED PASS "tcp/6380 (no allow rule): RESP GET unmatched -> L4 ALLOW kept (allow+=$G2_A); RESP FLUSHALL matches 'drop FLUSHALL' -> drop+=$F_D" \
  || mark l7_denylist_unmatched_keeps_l4 REQUIRED FAIL "$(sed -n 2p $O/resp.txt)"
ok $R_D $R_A \
  && mark l7_resp_l4drop_not_revived REQUIRED PASS "L4 DROP on tcp/6379 + RESP GET (matches the allow rule) stays DROP+=$R_D (leak allow+=$R_A)" \
  || mark l7_resp_l4drop_not_revived REQUIRED FAIL "$(sed -n 3p $O/resp.txt)"

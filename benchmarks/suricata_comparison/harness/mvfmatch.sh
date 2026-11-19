#!/bin/bash
set +e
W=/home/sungwoo/suri_mt_test
SURI=/home/sungwoo/suri8/inst/bin/suricata
export LD_LIBRARY_PATH=/home/sungwoo/suri8/inst/lib:/usr/local/lib/x86_64-linux-gnu
TP=/home/sungwoo/dpdk22inst/bin/dpdk-testpmd; TPLD=/home/sungwoo/dpdk22inst/lib/x86_64-linux-gnu
PKT=${PKT:-1400}
setsplit(){ local NC=$1; tc filter del dev eth0 ingress 2>/dev/null
  if [ "$NC" = 1 ]; then tc filter add dev eth0 ingress protocol ip flower skip_sw src_ip 0.0.0.0/0 action mirred egress redirect dev eth1
  elif [ "$NC" = 2 ]; then tc filter add dev eth0 ingress protocol ip flower skip_sw src_ip 198.18.0.0/17 action mirred egress redirect dev eth1; tc filter add dev eth0 ingress protocol ip flower skip_sw src_ip 198.18.128.0/17 action mirred egress redirect dev eth2
  else tc filter add dev eth0 ingress protocol ip flower skip_sw src_ip 198.18.0.0/18 action mirred egress redirect dev eth1; tc filter add dev eth0 ingress protocol ip flower skip_sw src_ip 198.18.64.0/18 action mirred egress redirect dev eth2; tc filter add dev eth0 ingress protocol ip flower skip_sw src_ip 198.18.128.0/18 action mirred egress redirect dev eth3; tc filter add dev eth0 ingress protocol ip flower skip_sw src_ip 198.18.192.0/18 action mirred egress redirect dev eth4; fi
}
RES=$W/MVF_MATCH_${PKT}.txt; : > $RES
for NC in 1 2 4; do
  d=$W/mvfm_${NC}c_${PKT}; mkdir -p $d; rm -f $d/stats.log $d/eve.json
  pkill -9 dpdk-testpmd 2>/dev/null; pkill -9 suricata 2>/dev/null; sleep 1; rm -rf /var/run/dpdk/suri
  setsplit $NC
  env LD_LIBRARY_PATH=$LD_LIBRARY_PATH timeout 55 $SURI -c $W/mvfm_${NC}c.yaml --dpdk -l $d > $d/suri.log 2>&1 &
  for j in $(seq 1 40); do grep -qiE "Engine started" $d/suri.log && break; sleep 1; done
  wc=$(grep -oiE "Threads created -> W: [0-9]+" $d/suri.log|tail -1|grep -oE "[0-9]+$")
  ( echo "set txpkts $PKT"; echo start; sleep 15; echo stop; echo quit ) | env LD_LIBRARY_PATH=$TPLD timeout 28 $TP -l 10,11 -n 4 --socket-mem 2048,0 --file-prefix tpA -a 0000:3b:01.3 -- -i --forward-mode=txonly --txonly-multi-flow --txq=1 --rxq=1 --total-num-mbufs=131072 > $d/tpA.log 2>&1 &
  sleep 22
  pkill -9 dpdk-testpmd 2>/dev/null; sleep 1; kill -INT $(pgrep -f "suricata.*mvfm_${NC}c") 2>/dev/null; sleep 4; pkill -9 suricata 2>/dev/null; sleep 1
  last=$(grep -n "Date:" $d/stats.log|tail -1|cut -d: -f1); [ -z "$last" ] && last=1
  proc=$(sed -n "${last},\$p" $d/stats.log | grep -aE "decoder.pkts .*W#0" | awk '{s+=$NF} END{print s+0}')
  alerts=$(sed -n "${last},\$p" $d/stats.log | grep -aE "detect.alert .*(Total|W#0)" | awk '{s+=$NF} END{print s+0}')
  gbps=$(awk -v p=$proc -v pk=$PKT 'BEGIN{printf "%.1f", p*pk*8/15/1e9}')
  echo "PKT=${PKT} NC=$NC workers=$wc decoded=$proc pps=$((proc/15)) gbps=$gbps alerts=$alerts" | tee -a $RES
done
echo "===== MATCH ${PKT} DONE ====="; cat $RES

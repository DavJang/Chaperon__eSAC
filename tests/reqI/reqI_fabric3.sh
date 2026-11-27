#!/bin/bash
# Chaperon Request I two-tenant fabric: mlx5 PF 3b:00.1 in switchdev with 3 VFs
#   vf0 = tenant A (02:51:00:00:00:01), vf2 = tenant B (02:51:00:00:00:02), vf1 = traffic generator.
# HW tc on the generator representor steers by destination MAC; each tenant VF returns to the generator.
# Run as root. Prints VF_A / VF_B / VF_G / MAC_A / MAC_B / MAC_G.
set -u
PF1=${PF1:-0000:3b:00.1}; IF1=${IF1:-enp59s0f1np1}
MAC_A=02:51:00:00:00:01; MAC_B=02:51:00:00:00:02; MAC_G=3c:fd:fe:c4:93:38
rep_of1(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
if [ ! -e /sys/bus/pci/devices/$PF1/virtfn2 ]; then
  echo 0 > /sys/bus/pci/devices/$PF1/sriov_numvfs 2>/dev/null; sleep 2
  devlink dev eswitch set pci/$PF1 mode switchdev 2>/dev/null; sleep 1
  ethtool -K $IF1 hw-tc-offload on 2>/dev/null
  echo 3 > /sys/bus/pci/devices/$PF1/sriov_numvfs
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF1/virtfn2 ] && break; sleep 1; done; sleep 3
fi
ethtool -K $IF1 hw-tc-offload on 2>/dev/null; ip link set $IF1 up 2>/dev/null
VA=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn0)); VG=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn1)); VB=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn2))
ip link set $IF1 vf 0 mac $MAC_A; ip link set $IF1 vf 1 mac $MAC_G; ip link set $IF1 vf 2 mac $MAC_B
for v in 0 1 2; do ip link set $IF1 vf $v spoofchk off 2>/dev/null; ip link set $IF1 vf $v trust on 2>/dev/null; done
ra=$(rep_of1 0); rg=$(rep_of1 1); rb=$(rep_of1 2)
for r in $ra $rg $rb; do ip link set $r up; tc qdisc del dev $r ingress 2>/dev/null; tc qdisc add dev $r ingress; done
tc filter add dev $rg ingress protocol all flower skip_sw dst_mac $MAC_A action mirred egress redirect dev $ra
tc filter add dev $rg ingress protocol all flower skip_sw dst_mac $MAC_B action mirred egress redirect dev $rb
tc filter add dev $ra ingress protocol all flower skip_sw action mirred egress redirect dev $rg
tc filter add dev $rb ingress protocol all flower skip_sw action mirred egress redirect dev $rg
echo "VF_A=$VA"; echo "VF_B=$VB"; echo "VF_G=$VG"; echo "MAC_A=$MAC_A"; echo "MAC_B=$MAC_B"; echo "MAC_G=$MAC_G"
echo "FABRIC reps A=$ra B=$rb G=$rg in_hw=$(tc filter show dev $rg ingress | grep -c in_hw)/2 (generator) $(tc filter show dev $ra ingress | grep -c in_hw)/1 (A) $(tc filter show dev $rb ingress | grep -c in_hw)/1 (B)"

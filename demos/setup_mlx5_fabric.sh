#!/bin/bash
# eSAC demo fabric: bring up an mlx5 PF in switchdev with 2 VFs + a tc hairpin (SVF<->CVF),
# so a tenant on the server VF receives traffic a generator sends from the client VF.
# Idempotent. Echoes INTRA_SVF / INTRA_CVF (PCI BDFs). Edit PF1/IF1 for your NIC.
set -u
PF1=${PF1:-0000:3b:00.1}; IF1=${IF1:-enp59s0f1np1}
rep_of1(){ local n; for n in /sys/class/net/*; do [ "$(cat $n/phys_port_name 2>/dev/null)" = "pf1vf$1" ] && { basename "$n"; return; }; done; }
if [ ! -e /sys/bus/pci/devices/$PF1/virtfn1 ]; then
  sudo -n sh -c "echo 0 > /sys/bus/pci/devices/$PF1/sriov_numvfs" 2>/dev/null; sleep 2
  sudo -n devlink dev eswitch set pci/$PF1 mode switchdev 2>/dev/null; sleep 1
  sudo -n ethtool -K $IF1 hw-tc-offload on 2>/dev/null
  sudo -n sh -c "echo 2 > /sys/bus/pci/devices/$PF1/sriov_numvfs" 2>/dev/null
  for w in $(seq 1 60); do [ -e /sys/bus/pci/devices/$PF1/virtfn1 ] && break; sleep 1; done; sleep 3
fi
sudo -n ethtool -K $IF1 hw-tc-offload on 2>/dev/null   # always on (HW tc hairpin needs it)
sudo -n ip link set $IF1 up 2>/dev/null
SVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn0))
CVF=$(basename $(readlink -f /sys/bus/pci/devices/$PF1/virtfn1))
sudo -n ip link set $IF1 vf 0 mac 02:51:00:00:00:01 2>/dev/null
sudo -n ip link set $IF1 vf 1 mac 3c:fd:fe:c4:93:38 2>/dev/null
for v in 0 1; do sudo -n ip link set $IF1 vf $v spoofchk off 2>/dev/null; sudo -n ip link set $IF1 vf $v trust on 2>/dev/null; done
srep=$(rep_of1 0); crep=$(rep_of1 1)
sudo -n ip link set $srep up 2>/dev/null; sudo -n ip link set $crep up 2>/dev/null
# flush any stale hairpin filters first (avoid stacking across repeated runs), then re-add exactly one
sudo -n tc qdisc del dev $srep ingress 2>/dev/null; sudo -n tc qdisc del dev $crep ingress 2>/dev/null
sudo -n tc qdisc add dev $srep ingress 2>/dev/null; sudo -n tc qdisc add dev $crep ingress 2>/dev/null
sudo -n tc filter add dev $srep ingress protocol all flower skip_sw action mirred egress redirect dev $crep 2>/dev/null
sudo -n tc filter add dev $crep ingress protocol all flower skip_sw action mirred egress redirect dev $srep 2>/dev/null
hw=$(sudo -n tc filter show dev $srep ingress 2>/dev/null|grep -oE 'in_hw|not_in_hw'|head -1)
echo "INTRA_SVF=$SVF"; echo "INTRA_CVF=$CVF"; echo "SREP=$srep CREP=$crep TC=$hw"

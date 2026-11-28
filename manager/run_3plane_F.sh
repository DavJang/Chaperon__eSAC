#!/bin/bash
# Request F: + sealed hook->filter dispatch (SEALED_DISPATCH=1 default), full-RELRO agent, code-range
# registration, pre-exec library trust check, root-owned launch directory, merged range registration,
# monotonic launch timeline, DISPATCH_ATK=1 dispatch-pointer tamper test, TAMPER_TARGET=dispatch.
# Request E: same unified loader/runtime/provider, plus (item-1) immutable SHM routing view and (item-2)
# EXECUTION gate: trusted bootstrap runs from the __libc_start_main hook BEFORE the executable's
# DT_INIT_ARRAY/main; it seals everything and waits for the Manager's root-owned GO, which is written
# only after an independent /proc+bpftool check and full Tamper-Sentinel range registration.
# Chaperon FULL 3-PLANE via ONE UNIFIED bpftime loader (chaperon_loader) on ONE real non-root mlx5
# testpmd tenant, gated/fail-closed. chaperon_loader loads c_filter (COMM RX L4) AND r_precheck
# (RESOURCE override on rte_flow_create) in the SAME bpftime context. One multi-id broker serves
# comm_policy + resource_usage + resource_policy. INTEGRITY cgroup Sentinel protects the Agent hooks.
#
# JUDGMENT (review fix #1): every required check is judged PASS/FAIL/NOT_TESTED from the ACTUAL
# observed value. strace attachment is proven (its own marker) before a 0-count is trusted. Overall
# PASS prints ONLY if every REQUIRED check is PASS; the title states the completed scope. Each run
# uses a UNIQUE result dir (RUN_ID) and never overwrites another run's logs/map-IDs. A required
# component failure (map/reuse/freeze/attach/broker/mmap/seal/range) REFUSES, never READY.
#   Env: HARD (default 3); TAMPER=1 + SEAL_VERIFY=1 for the destructive checks (separate run);
#        FAIL_CHECK=<name> to intentionally fail one required check (negative self-test).
set -u
trap '' PIPE
MG=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); CHAP_ROOT=$(cd "$MG/.." && pwd)   # manager/ and the repository root
[ -f "$MG/chap_env.sh" ] && . "$MG/chap_env.sh"   # host-local paths (not in git; see chap_env.example.sh)
RK=$CHAP_ROOT/resource/kernel
RA=$CHAP_ROOT/resource/agent
IK=$CHAP_ROOT/integrity/kernel
AMB=${CHAP_AMBLAUNCH:-$MG/tools/amblaunch}
TESTPMD=$(command -v dpdk-testpmd)
GEN=${CHAP_GEN:-$CHAP_ROOT/tests/gen/esac_l47gen}
DPDKLIB=${CHAP_DPDK_LIBDIR:-}
DPDKRUN=${CHAP_DPDK_RUNDIR:-/var/tmp/chap_dpdkrun}   # XDG_RUNTIME_DIR of the non-root tenant
HARD=${HARD:-3}; PIND=${PIND:-/sys/fs/bpf/chap}; TLC=${TLC:-6,7}; TCPUS=${TCPUS:-6-7}
MT=$( [ -n "${MT_SVF:-}" ] && echo 1 || echo 0 )   # Request I two-tenant mode: this run only touches its own tenant
FC_OFF=0x119e2d0; CC_OFF=0x15edea0; DC_OFF=0x15e3680
CFILTER=${CFILTER:-$CHAP_ROOT/communication/combo/c_filter_hs_gate_excl.bpf.o}   # item-6 L7: L4+L7 combo (esac basename -> c_filter.rodata)
L7=${L7:-1}
# Request I: unclassifiable packets (fragments, malformed, non-IPv4) take the default action DROP (Design);
# UNCLASS_ALLOW=1 restores pass-through (e.g. an app that needs ARP)
UNCLASS="--frag-drop --malformed-drop --nonip-drop"; [ "${UNCLASS_ALLOW:-0}" = 1 ] && UNCLASS=""
# Request G failure injections: a protection step skipped by the bootstrap / a target missing from registration
[ "${FAIL_INJECT:-}" = "dispatch_unsealed" ] && SEALED_DISPATCH=0 && UNSAFE_CONTROL_LISTENER=0
# Request H: TEST-ONLY filter build whose inspection of RX window >= 2 fails (fail-closed check)
[ "${FAIL_INJECT:-}" = "rx_window_fail" ] && CFILTER=$CHAP_ROOT/communication/combo/c_filter_hs_gate_excl_TESTFAILRX2.bpf.o && RX_TEST=1
HSPROV=${HSPROV:-$CHAP_ROOT/communication/esac_hs_fullscan_enforce.chap.so}
RUN_ID=${RUN_ID:-$(date +%Y%m%d_%H%M%S)_$$}
W=/var/tmp/chap_3pu_$RUN_ID; rm -rf "$W"; mkdir -p "$W"; chmod 0755 "$W"; O="$W/run"; mkdir -p "$O"; chmod 0755 "$O"   # Request F: root-owned, NOT tenant-writable
SHM="chap3pu${$}"; SOCK="$W/brk.sock"; SVFMAC=${SVFMAC:-02:51:00:00:00:01}
say(){ echo "[3pu] $*"; }
mono(){ python3 -c "import time;print(time.monotonic_ns())"; }
tl(){ echo "t=$(mono) $*" >> "$O/timeline_mgr.txt"; }
STATUS_FILE="$O/CHECKS.tsv"; : > "$STATUS_FILE"
mark(){ local n="$1" req="$2" st="$3"; shift 3
  if [ "${FAIL_CHECK:-}" = "$n" ]; then st=FAIL; set -- "(forced FAIL via FAIL_CHECK=$n)"; fi
  printf '%s\t%s\t%s\t%s\n' "$n" "$req" "$st" "$*" >> "$STATUS_FILE"; say "CHECK[$req] $n = $st  :: $*"; }
refuse(){ mark "$1" REQUIRED FAIL "component init failure -> REFUSE launch (no untrusted workload)"; say "REFUSE: $1"; kill -9 ${TPID:-0} 2>/dev/null; cleanup
  sleep 1; local post="POST_REFUSE tenant_alive=$(kill -0 ${TPID:-0} 2>/dev/null && echo YES || echo NO) go_token=$( [ -e /var/lib/chap_gate/go_${TPID:-x} ] && echo PRESENT || echo absent) loader=$(pgrep -fc '[c]haperon_loader') sentinels=$(pgrep -fc '[r]s_sentinel_reuse|[i]nteg_sentinel_run') broker=$(pgrep -fc '[f]d_broker_multi') cgroup=$( [ -d /sys/fs/cgroup/chap_3pu_$RUN_ID ] && echo present || echo removed)"
  say "$post"; echo "$post" >> "${O:-/tmp}/refuse_post.txt" 2>/dev/null; final_verdict; exit 3; }
cleanup(){ pkill -9 -f "chap3pu${$}" 2>/dev/null; pkill -9 -f "file-prefix=peer${$}" 2>/dev/null; rm -f /var/lib/chap_gate/go_${TPID:-x} /dev/shm/*chap3pu${$}* 2>/dev/null; if [ "$MT" = 1 ]; then for p in ${LPID:-} ${SPID:-} ${IPID:-} ${BRPID:-}; do kill -9 $p 2>/dev/null; done; else pkill -9 -f 'esac_l47ge[n]' 2>/dev/null; pkill -9 -f "[c]haperon_loader" 2>/dev/null; pkill -9 -f "[r]s_sentinel_reuse" 2>/dev/null; pkill -9 -f "[i]nteg_sentinel_run" 2>/dev/null; pkill -9 -f "[f]d_broker_multi" 2>/dev/null; fi; rmdir /sys/fs/cgroup/chap_3pu_$RUN_ID 2>/dev/null; rm -f $PIND/* 2>/dev/null; [ -n "${TNS:-}" ] && ip netns del $TNS 2>/dev/null; }   # Request I: release pinned maps; Request Q: tenant netns
# Request G: a REQUIRED protection check that fails at the barrier refuses the launch: evidence snapshot while
# the tenant is still held at the barrier, no GO token, tenant killed, Manager helpers cleaned up.
refuse_at_barrier(){ local name="$1" det="$2" sn; sn=$(snap ${TPID:-0} 2>/dev/null); echo "$sn" > "$O/refuse_snapshot.txt"
  ls -l /proc/${TPID:-0}/fd > "$O/refuse_fds.txt" 2>&1; cp "$W/testpmd.log" "$O/refuse_testpmd.log" 2>/dev/null
  mark "$name" REQUIRED FAIL "$det | GO token: $( [ -e /var/lib/chap_gate/go_${TPID:-x} ] && echo PRESENT || echo 'not issued') | snapshot at refuse: $sn"
  refuse "$name"; }
final_verdict(){
  say ""; say "===== 3-PLANE JUDGMENT (RUN_ID=$RUN_ID; CFILTER=$(basename $CFILTER)) ====="
  column -t -s $'\t' "$STATUS_FILE" 2>/dev/null | sed 's/^/[3pu]   /' || cat "$STATUS_FILE"
  local reqfail nottested
  reqfail=$(awk -F'\t' '$2=="REQUIRED"&&$3=="FAIL"{c++}END{print c+0}' "$STATUS_FILE")
  nottested=$(awk -F'\t' '$2=="REQUIRED"&&$3=="NOT_TESTED"{c++}END{print c+0}' "$STATUS_FILE")
  local scope="full"; [ "${TAMPER:-0}" != "1" ] && scope="non-destructive (INTEGRITY tamper/W^X are a separate TAMPER=1 run)"
  if [ "$reqfail" -eq 0 ] && [ "$nottested" -eq 0 ]; then say "OVERALL: PASS  (all REQUIRED checks PASS; scope=$scope)";
  else say "OVERALL: NOT PASS  ($reqfail REQUIRED FAIL, $nottested REQUIRED NOT_TESTED; scope=$scope)"; fi
}

[ "$MT" = 1 ] || { pkill -9 -f "[c]haperon_loader" 2>/dev/null; pkill -9 -f "[r]s_sentinel_reuse" 2>/dev/null; pkill -9 -f "[i]nteg_sentinel_run" 2>/dev/null; pkill -9 -f "[f]d_broker_multi" 2>/dev/null; rm -f /dev/shm/*chap3pu* 2>/dev/null; }; rmdir /sys/fs/cgroup/chap_3pu_$RUN_ID 2>/dev/null; sleep 1
rm -f $PIND/resource_usage $PIND/resource_policy $PIND/cg_slot $PIND/last_cg $PIND/protected_cgroups $PIND/protected_ranges $PIND/integ_ctl 2>/dev/null; mkdir -p $PIND 2>/dev/null
BDFIX=${BDFIX:-${CHAP_RUNTIME_DIR:-$CHAP_ROOT/agent/build}}
if [ -f "$BDFIX/libbpftime-agent.so" ]; then cp "$BDFIX/libbpftime-agent.so" "$W/agent.so"; cp "$BDFIX/libbpftime-syscall-server.so" "$W/srv.so"; RT="FIXED:$BDFIX"; else echo "[3pu] FATAL: fixed runtime $BDFIX/libbpftime-agent.so absent -> REFUSE launch (no silent fallback to unmodified runtime)"; exit 2; fi
cp "$MG/chaperon_loader" "$W/chaperon_loader"; cp "$CFILTER" "$W/c_filter.bpf.o"; cp $CHAP_ROOT/integrity/esac_seal.so "$W/esac_seal.so"; cp $CHAP_ROOT/communication/chap_policy_flip "$W/policy_flip"; chmod 0755 "$W/policy_flip" 2>/dev/null
cp "$HSPROV" "$W/hsprov.so"; RULES="$W/hs_rules.txt"
if [ "${FAIL_INJECT:-}" = "l7_badpatterns" ]; then printf '(unterminated\n' > "$RULES"; else printf 'evilmal\n' > "$RULES"; fi; chmod 0644 "$RULES"
# Request I: RESP=1 adds the Fig. policy payload rule (allow-listed Redis service) and a RESP deny rule
[ "${RESP:-0}" = 1 ] && printf '%s\n' 'allow tcp/6379 /^\*2\r\n\$3\r\nGET\r\n/' 'drop FLUSHALL' >> "$RULES"
L7ALW=""; grep -q '^allow ' "$RULES" && L7ALW="--l7-allowlist"   # allow-listed services: every payload reaches the provider
cp "$MG/fabric/offsets.json" "$W/offsets.json"; chmod 0755 "$W"/*.so "$W/chaperon_loader" 2>/dev/null
AGENT="$W/agent.so"; SERVER="$W/srv.so"
MEMJ_LIB=""; [ -n "${MEMJ:-}" ] && { cp $CHAP_ROOT/tests/reqJ/chap_memapi_test.so "$W/memapi.so"; chmod 0755 "$W/memapi.so"; MEMJ_LIB="$W/memapi.so"; }   # Request J TEST-ONLY driver
[ -n "${NICJ:-}${NICQ:-}" ] && { cp $CHAP_ROOT/tests/reqP/chap_nicgate_test.so "$W/nicj.so"; chmod 0755 "$W/nicj.so"; MEMJ_LIB="${MEMJ_LIB:+$MEMJ_LIB:}$W/nicj.so"; }   # Request P/Q TEST-ONLY driver
mkdir -p "$DPDKRUN" 2>/dev/null; chmod 1777 "$DPDKRUN" 2>/dev/null

# Request I: Table tab:apis attach points. Agent pre-check = public API entries (bpftime override);
# Sentinel accounting = internal functions the Agent does not patch (kernel uprobes). Missing symbol => refuse.
RPOL=$CHAP_ROOT/resource/manager/chap_res_policy
RES_AGENT_SPEC="agent_flow_destroy:rte_flow_destroy,agent_flow_flush:rte_flow_flush,agent_dev_start:rte_eth_dev_start,agent_dev_stop:rte_eth_dev_stop,agent_promisc_en:rte_eth_promiscuous_enable,agent_promisc_dis:rte_eth_promiscuous_disable,agent_mc_addr:rte_eth_dev_set_mc_addr_list,agent_dev_configure:rte_eth_dev_configure,agent_rxq_setup:rte_eth_rx_queue_setup,agent_txq_setup:rte_eth_tx_queue_setup,agent_malloc:rte_malloc_socket,agent_memzone:rte_memzone_reserve_thread_safe,agent_mempool:rte_mempool_create,agent_pktmbuf_pool:rte_pktmbuf_pool_create,agent_eal_init:rte_eal_init,agent_remote_launch:rte_eal_remote_launch"
# TEST-ONLY bypass: RES_OMIT=<agent prog> leaves that pre-check out (the call then meets the kernel Sentinel)
# TEST-ONLY (Request J): RES_PASS=1 replaces the rte_malloc_socket pre-check by a pass-through (hook + boundary kept)
[ "${RES_PASS:-0}" = 1 ] && RES_AGENT_SPEC=$(echo "$RES_AGENT_SPEC" | sed 's/agent_malloc:rte_malloc_socket/agent_mem_pass:rte_malloc_socket/')
[ -n "${RES_OMIT:-}" ] && RES_AGENT_SPEC=$(echo "$RES_AGENT_SPEC" | tr ',' '\n' | grep -vE "^($(echo "$RES_OMIT" | tr '+' '|')):" | paste -sd, -)   # RES_OMIT: a+b+c
RS_SPEC="rs_flow_destroy_entry:mlx5_flow_destroy,rs_flow_flush_entry:mlx5_flow_flush,rs_flow_flush_ret:mlx5_flow_flush:ret,rs_dev_start:mlx5_dev_start,rs_dev_stop:mlx5_dev_stop,rs_promisc_en:mlx5_promiscuous_enable,rs_promisc_dis:mlx5_promiscuous_disable,rs_mc_addr:mlx5_set_mc_addr_list,rs_rxq_config:eth_dev_rx_queue_config,rs_txq_config:eth_dev_tx_queue_config,rs_rxq_setup:mlx5_rx_queue_setup,rs_txq_setup:mlx5_tx_queue_setup,rs_heap_alloc:malloc_heap_alloc,rs_heap_alloc_ret:malloc_heap_alloc:ret,rs_free:rte_free,rs_mz_free:rte_memzone_free,rs_pool_create:rte_pktmbuf_pool_create_by_ops,rs_pool_create_ret:rte_pktmbuf_pool_create_by_ops:ret,rs_pool_free:rte_mempool_free"
RES_APIS=$(python3 -I "$MG/chap_res_offsets.py" "$TESTPMD" "$RES_AGENT_SPEC" 2>"$O/res_offsets.err") && RS_ATTACH=$(python3 -I "$MG/chap_res_offsets.py" "$TESTPMD" "$RS_SPEC" 2>>"$O/res_offsets.err") \
  || { mark table_api_points REQUIRED FAIL "$(cat $O/res_offsets.err)"; final_verdict; exit 2; }
NRES_EXP=$(echo "$RES_APIS" | tr ',' '\n' | grep -c .); NRS_EXP=$(echo "$RS_ATTACH" | tr ',' '\n' | grep -c .)
# Request J: kernel boundary of admitted resource calls in agent.so (gate enter/exit) -> memory-API rate hard limit
GATE_ATTACH=$(python3 -I "$MG/chap_res_offsets.py" "$W/agent.so" "rs_gate_enter:chap_res_gate_enter,rs_gate_exit:chap_res_gate_exit" 2>>"$O/res_offsets.err") \
  || { mark gate_points REQUIRED FAIL "$(cat $O/res_offsets.err)"; final_verdict; exit 2; }
RS_ATTACH="$RS_ATTACH,$(echo "$GATE_ATTACH" | tr ',' '\n' | sed "s#\$#@$W/agent.so#" | paste -sd, -)"; NRS_EXP=$((NRS_EXP + 2))
GOFF=$(echo "$GATE_ATTACH" | tr ',' '\n' | grep '^rs_gate_enter:' | cut -d: -f2)   # TEST-ONLY driver (MEMJ=forge)
RS_OBJ=${RS_OBJ:-$RK/resource_sentinel.bpf.o}   # TEST-ONLY override: compare with an older Sentinel object
printf 'RES_APIS=%s\nRS_ATTACH=%s\n' "$RES_APIS" "$RS_ATTACH" > "$O/res_points.txt"

QJSON="$W/quota.json"; printf '{"max_socket_mem_mb":2048,"max_lcore_count":4}\n' > "$QJSON"
bash "$MG/chap_admit.sh" "$QJSON" -- /bin/true -l $TLC --socket-mem 1024,0 >"$W/admit.log" 2>&1 && mark admission REQUIRED PASS "$(grep -a ADMIT "$W/admit.log"|head -1)" || { mark admission REQUIRED FAIL "esac_admit DENY"; final_verdict; exit 2; }

if [ "$MT" = 1 ]; then INTRA_SVF=$MT_SVF; INTRA_CVF=$MT_CVF; else eval "$(bash "$MG/fabric/setup_mlx5_fabric.sh" | grep INTRA_)"; fi
SVF=${INTRA_SVF:-}; CVF=${INTRA_CVF:-}; CVFMAC=$(cat /sys/bus/pci/devices/${INTRA_CVF:-x}/net/*/address 2>/dev/null | head -1); [ -z "$SVF" ] && { mark fabric REQUIRED FAIL "no mlx5 VF"; final_verdict; exit 1; }
say "fabric SVF=$SVF CVF=$CVF SHM=$SHM RUN_ID=$RUN_ID"
# Request Q: the tenant runs in its own network namespace holding only lo and its VF netdev, kept DOWN (the mlx5 PMD
# needs the netdev for queries; its packets use the DevX queues, not the kernel netdev). The PF, the representors and
# every host interface are invisible to the tenant, and without CAP_NET_ADMIN it cannot bring the netdev up: no
# AF_PACKET / raw / UDP path to the NIC through the kernel network stack. /proc/bus/pci is masked in its mount namespace.
TNS=""; NSX=""
if [ "${TNETNS:-1}" = 1 ]; then
  SN=$(ls /sys/bus/pci/devices/$SVF/net/ 2>/dev/null | head -1); TNS=chapns${$}
  if [ -n "$SN" ] && ip netns add $TNS && ip link set "$SN" netns $TNS && ip netns exec $TNS ip link set "$SN" down && ip netns exec $TNS ip link set lo up; then
    NSX="$MG/tools/tenant_ns_exec.sh $TNS"
    mark tenant_netns REQUIRED PASS "netns $TNS: $(ip netns exec $TNS ip -br link | tr -s ' ' | tr '\n' ';') (VF netdev $SN DOWN; PF, representors, host interfaces not in the namespace); /proc/bus/pci masked in the tenant mount namespace"
  else mark tenant_netns REQUIRED FAIL "netns setup failed (SN=$SN)"; ip netns del $TNS 2>/dev/null; final_verdict; exit 3; fi
fi

FIFO=$W/cmd; mkfifo "$FIFO"; RP=$O/tpid; :>"$RP"; chmod 666 "$RP"
NICJ_IBDEV=$(ls /sys/bus/pci/devices/$SVF/infiniband/ 2>/dev/null | head -1)   # RDMA device of the tenant VF (Request P tests)
AENV="XDG_RUNTIME_DIR=$DPDKRUN $( [ -n "${NICJ:-}${NICQ:-}" ] && echo "CHAP_NICJ_TEST=1 CHAP_NICJ_DIR=$W/tenant_cwd CHAP_NICJ_IBDEV=$NICJ_IBDEV" ) BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=${TSPDLOG:-warn} BPFTIME_KERNEL_MAP_NAMES=comm_policy,resource_usage,resource_policy BPFTIME_KERNEL_MAP_RO=1 BPFTIME_FD_BROKER_SOCK=$SOCK BPFTIME_KERNEL_MAP_DROP_FD=1 ESAC_HS_PATTERNS=$W/hs_rules.txt ESAC_MATCH_ACT=2 CHAP_GATED_LAUNCH=1 $( [ "${FAIL_INJECT:-}" = view_unsealed ] || echo CHAP_IMM_VIEW=1 ) CHAP_L7_REQUIRED=1 CHAP_GO_TIMEOUT_S=90 CHAP_GO_DIR=/var/lib/chap_gate CHAP_LINK_REGISTRY=1 CHAP_TEST_ATK=$( [ "${PROGFN_ATK:-0}" = 1 -o "${DISPATCH_ATK:-0}" = 1 ] && echo 1 || echo 0 ) $( [ "${SEALED_DISPATCH:-1}" = 1 ] && echo CHAP_SEALED_DISPATCH=1 ) $( [ -n "${MEMJ:-}" ] && echo "CHAP_MEMAPI_TEST=1 CHAP_MEMAPI_DIR=$W/tenant_cwd CHAP_MEMAPI_GATE_OFF=$GOFF" ) LD_DEBUG=files LD_PRELOAD=$AGENT:$W/esac_seal.so:$W/hsprov.so${MEMJ_LIB:+:$MEMJ_LIB}"
# Request Q: dedicated tenant account from manager/chap_env.sh (CHAP_TENANT_USER): not root, no sudo rights, no
# administrative group. amblaunch drops to it (exported), with NO_NEW_PRIVS. The DPDK runtime dir belongs to it.
TUSER=${CHAP_TENANT_USER:-}
TACC=$(LC_ALL=C sudo -n -l -U "${TUSER:-root}" 2>&1 | head -1); TGR=$(id -nG "${TUSER:-root}" 2>/dev/null)
if [ -n "$TUSER" ] && [ "$(id -u "$TUSER" 2>/dev/null || echo 0)" != 0 ] && echo "$TACC" | grep -q "is not allowed to run sudo" \
   && ! echo " $TGR " | grep -qE " (sudo|admin|wheel|root|adm|libvirt|docker|lxd|kvm|disk) "; then
  mark tenant_account REQUIRED PASS "tenant=$TUSER uid=$(id -u $TUSER) groups=[$TGR] ; $TACC"
else mark tenant_account REQUIRED FAIL "tenant='$TUSER' groups=[$TGR] ; $TACC (set CHAP_TENANT_USER to a dedicated unprivileged account)"; cleanup; final_verdict; exit 3; fi
export CHAP_TENANT_USER="$TUSER"
mkdir -p "$DPDKRUN" && chown "$TUSER" "$DPDKRUN" && chmod 0700 "$DPDKRUN"
python3 -I "$MG/chap_e_tools.py" libtrust "$TUSER" "$TESTPMD" "$AGENT:$W/esac_seal.so:$W/hsprov.so${MEMJ_LIB:+:$MEMJ_LIB}" > "$O/lib_trust.txt" 2>&1; LTR=$?
LT="$(grep LIBTRUST_RESULT $O/lib_trust.txt)"
if [ "$LTR" = 0 ]; then mark pre_bootstrap_code_trust REQUIRED PASS "$LT; tenant=$TUSER; preloads + Manager artifacts in root-owned 0755 $W"
else mark pre_bootstrap_code_trust REQUIRED FAIL "$LT"; cleanup; final_verdict; exit 3; fi
python3 -I "$MG/chap_e_tools.py" exetrust "$TESTPMD" > "$O/exe_trust.txt" 2>&1 \
  && mark exe_no_prebarrier_code REQUIRED PASS "$(head -1 $O/exe_trust.txt)" \
  || { mark exe_no_prebarrier_code REQUIRED FAIL "$(cat $O/exe_trust.txt | tr '\n' ' ')"; cleanup; final_verdict; exit 3; }
TCWD=$W/tenant_cwd; mkdir -p "$TCWD"; chown "$TUSER" "$TCWD"; chmod 0700 "$TCWD"   # tenant working dir (PMD debug dumps land here, not in the repo)
TXMF=""; [ "${TX_TEST:-0}" = "1" ] && TXMF="--txonly-multi-flow"
setsid $NSX $AMB bash -c "echo \$\$>$RP; kill -STOP \$\$; cd $TCWD; exec stdbuf -oL env $AENV $TESTPMD -l $TLC -n4 --in-memory --socket-mem 1024,0 -a ${SVF},rx_vec_en=${RXVEC:-0} --file-prefix=chap3pu${$} -- -i --total-num-mbufs=4096 --tx-ip=10.0.0.2,10.0.0.1 --tx-udp=2222,1111 $TXMF" < "$FIFO" > "$W/testpmd.log" 2>&1 &
LJOB=$!
exec 3>"$FIFO"; sleep 1; TPID=$(cat "$RP")
say "tenant pid=$TPID (STOPPED) uid=$(awk '/^Uid:/{print $2}' /proc/$TPID/status 2>/dev/null)"
mkdir -p /sys/fs/cgroup/chap_3pu_$RUN_ID 2>/dev/null; echo "$TPID" > /sys/fs/cgroup/chap_3pu_$RUN_ID/cgroup.procs 2>/dev/null
CGID=$(stat -c %i /sys/fs/cgroup/chap_3pu_$RUN_ID); CGDIR=/sys/fs/cgroup/chap_3pu_$RUN_ID; say "tenant cgroup_id=$CGID"

MSIP=10.0.0.1; MDIP=10.0.0.2; MSP=1111; MDP=2222
# item-2 HARD gated launch: CLOSED (empty) policy -> fail-closed Filter DROPS all traffic until
# the Manager ARMS (installs ALLOW) AFTER seal + sentinels + range registration.
printf '{"rules":[{"layer":"L2","cgroup_id":%s,"src_ip":"%s","dst_ip":"%s","src_port":%s,"dst_port":%s,"proto":17,"action":"DROP"}]}\n' "$CGID" "$MSIP" "$MDIP" "$MSP" "$MDP" > "$W/pol.json"
# Request I (WILD=1): launch policy also carries combos of the 64 mask-probe layout (see reqI_wild_block.sh)
[ "${WILD:-0}" = 1 ] && python3 -I -c "import json,sys
p=json.load(open(sys.argv[1])); cg=int(sys.argv[2]); d=sys.argv[3]
p['rules'] += [dict(layer='L2',cgroup_id=cg,src_ip='0.0.0.0',dst_ip=d,src_port=0,dst_port=5555,proto=0,action='ALLOW'),
               dict(layer='L2',cgroup_id=0,src_ip='0.0.0.0',dst_ip='0.0.0.0',src_port=0,dst_port=6666,proto=17,action='ALLOW'),
               dict(layer='L2',cgroup_id=cg,src_ip='10.0.0.9',dst_ip='0.0.0.0',src_port=0,dst_port=0,proto=17,action='DROP')]
json.dump(p,open(sys.argv[1],'w'))" "$W/pol.json" "$CGID" "$MDIP"
env BPFTIME_GLOBAL_SHM_NAME=$SHM BPFTIME_KERNEL_MAP_NAMES=comm_policy,resource_usage,resource_policy \
    CHAP_RES_BPF="$RA/r_precheck_agent.bpf.o" CHAP_RFC_OFF=$FC_OFF CHAP_RES_APIS="$RES_APIS" \
    BPFTIME_LOG_OUTPUT=console SPDLOG_LEVEL=Info LD_PRELOAD="$SERVER" \
  "$W/chaperon_loader" --max-burst-inspect 128 --bpf "$W/c_filter.bpf.o" --lib "$TESTPMD" --pmd-lib "$TESTPMD" --offsets "$W/offsets.json" --policy "$W/pol.json" --no-pin --enforcement $UNCLASS $L7ALW --attach-pid "$TPID" -v > "$O/loader.log" 2>&1 &
LPID0=$!
for j in $(seq 1 60); do grep -qa 'resource Agent (r_precheck) attached' "$O/loader.log" && break; kill -0 $TPID 2>/dev/null||break; sleep 1; done
grep -qa 'attach summary: RX=OK' "$O/loader.log" || refuse "comm_c_filter_RX_attach"
grep -qa 'resource Agent (r_precheck) attached' "$O/loader.log" || refuse "resource_override_attach"
NAP=$(grep -aoE "resource Agent Request-I APIs attached=[0-9]+" "$O/loader.log" | grep -oE "[0-9]+$")
[ "${NAP:-x}" = "$NRES_EXP" ] || refuse "resource_agent_table_apis"
FEATS=$(grep -aoE "runtime_config: features=0x[0-9a-f]+" "$O/loader.log" | head -1 | grep -oE "0x[0-9a-f]+")
{ [ -n "$FEATS" ] && [ $(( (FEATS >> 6) & 1 )) = $( [ -n "$L7ALW" ] && echo 1 || echo 0 ) ]; } || refuse "l7_allowlist_consistent"
mark l7_rules_consistent REQUIRED PASS "rules: $(grep -c . $RULES) ($(grep -c '^allow ' $RULES) allow); filter features=$FEATS allow-list bit=$(( (FEATS >> 6) & 1 ))"
mark resource_agent_table_apis REQUIRED PASS "Agent pre-check on rte_flow_create + $NAP Table tab:apis entries (Launch/Memory/Port/NIC control)$( [ "${RES_PASS:-0}" = 1 ] && echo " ; TEST-ONLY: rte_malloc_socket pre-check replaced by agent_mem_pass")$( [ -n "${RES_OMIT:-}" ] && echo " ; TEST-ONLY bypass: $RES_OMIT omitted")"
chmod 0666 /dev/shm/*${SHM}* 2>/dev/null
CKID=$(bpftool map list 2>/dev/null | grep -B1 "name comm_policy" | grep -oE "^[0-9]+" | tail -1)
UID_=$(bpftool map list 2>/dev/null | grep -B1 "name resource_usage" | grep -oE "^[0-9]+" | tail -1)
PID_=$(bpftool map list 2>/dev/null | grep -B1 "name resource_policy" | grep -oE "^[0-9]+" | tail -1)
[ -z "$CKID" -o -z "$UID_" -o -z "$PID_" ] && refuse "kernel_maps_create"
LPID=$( [ "$MT" = 1 ] && echo $LPID0 || pgrep -f "[c]haperon_loader" | head -1)
mark unified_loader REQUIRED PASS "comm+resource one context; maps comm=$CKID usage=$UID_ policy=$PID_"
mark runtime_in_use REQUIRED PASS "$RT sha256(agent)=$(sha256sum "$W/agent.so"|cut -c1-16)"
mark components_in_use OPTIONAL INFO "loader=$(sha256sum "$W/chaperon_loader"|cut -c1-16) cfilter=$(sha256sum "$W/c_filter.bpf.o"|cut -c1-16) r_precheck=$(sha256sum "$RA/r_precheck_agent.bpf.o"|cut -c1-16) rsentinel=$(sha256sum "$RS_OBJ"|cut -c1-16) seal=$(sha256sum "$W/esac_seal.so"|cut -c1-16) hsprov=$(sha256sum "$W/hsprov.so"|cut -c1-16) policy_writer=$(sha256sum "$W/policy_flip"|cut -c1-16)"

CHAP_RS_ATTACH="$RS_ATTACH" "$RK/rs_sentinel_reuse" "$RS_OBJ" "$TPID" "$CGID" "$HARD" "$TESTPMD" "$CC_OFF" "$DC_OFF" "$UID_" "$PID_" "$PIND" > "$O/rsent.log" 2>&1 &
SPID0=$!
for i in $(seq 1 15); do grep -qa "READY REUSE" "$O/rsent.log" && break; sleep 1; done
grep -qa "READY REUSE" "$O/rsent.log" || refuse "resource_sentinel_reuse_attach"
grep -qa "freeze(resource_usage)=OK" "$O/rsent.log" || refuse "resource_usage_FREEZE"
SPID=$( [ "$MT" = 1 ] && echo $SPID0 || pgrep -f "[r]s_sentinel_reuse" | head -1); mark resource_kernel_sentinel REQUIRED PASS "READY REUSE + usage FROZEN"
NRS=$(grep -aoE "Request-I accounting points attached=[0-9]+" "$O/rsent.log" | grep -oE "[0-9]+$")
[ "${NRS:-x}" = "$NRS_EXP" ] || refuse "resource_sentinel_table_points"
grep -qa "attached rs_gate_thread_exit" "$O/rsent.log" || refuse "resource_sentinel_gate_thread_exit"
mark resource_sentinel_table_points REQUIRED PASS "kernel uprobes on $NRS points incl. the admitted-call boundary chap_res_gate_enter/exit in agent.so (Request J) + thread-exit tracepoint; internal accounting points (heap, mbuf pools, queues, flow destroy/flush, dev start/stop, promisc, mc list) + flow create/destroy"
# Request I: tenant resource policy (Fig. policy quota block) written by the Manager (root, pinned map; no tenant write handle)
"$RPOL" "$PIND/resource_policy" 0 lcores=$TLC max_lcores=4 max_hp_mb=2048 ${RESPOL_EXTRA:-} > "$O/respolicy.log" 2>&1 \
  && mark resource_policy_set REQUIRED PASS "$(tail -1 $O/respolicy.log)" || refuse "resource_policy_set"
# Launch class, kernel side: cgroup cpuset = admitted lcores; hugetlb 2MB (fault + reservation) = hugepage quota
HPB=$(( ${CG_HP_MB:-2048} * 1024 * 1024 ))
echo "$TCPUS" > $CGDIR/cpuset.cpus 2>/dev/null; echo $HPB > $CGDIR/hugetlb.2MB.max 2>/dev/null; echo $HPB > $CGDIR/hugetlb.2MB.rsvd.max 2>/dev/null
CPE=$(cat $CGDIR/cpuset.cpus.effective 2>/dev/null); HMX=$(cat $CGDIR/hugetlb.2MB.max 2>/dev/null); HRS=$(cat $CGDIR/hugetlb.2MB.rsvd.max 2>/dev/null)
{ [ "$CPE" = "$TCPUS" ] && [ "$HMX" = "$HPB" ] && [ "$HRS" = "$HPB" ]; } && mark launch_kernel_limits REQUIRED PASS "tenant cgroup cpuset.cpus.effective=$CPE hugetlb.2MB.max=$HMX rsvd.max=$HRS" || refuse "launch_kernel_limits"

"$IK/integ_sentinel_run" "$IK/integrity_sentinel.bpf.o" "$CGID" "$PIND" > "$O/integ.log" 2>&1 &
IPID=$!
for i in $(seq 1 15); do grep -qa "READY" "$O/integ.log" && break; sleep 1; done
grep -qa "READY" "$O/integ.log" || refuse "integrity_sentinel_attach"; mark integrity_sentinel REQUIRED PASS "cgroup-wide watcher READY"
# Request P: NIC gate (kernel functions through which the mlx5 PMD acquires/controls the NIC = the uverbs command
# interface) armed BEFORE the tenant is released: until the Manager registers it as a Sealed Process, any tenant-cgroup
# access to the operator-selected RDMA devices is denied in-kernel + SIGKILL. Missing hook or config => refuse.
NGA=$(grep -aoE "NICGATE attached=[0-9]+/[0-9]+" "$O/integ.log" | head -1)
{ [ "$NGA" = "NICGATE attached=8/8" ] && "$IK/chap_nicgate" cfg "$PIND" on "$NICJ_IBDEV" > "$O/nicgate_cfg.txt" 2>&1; } \
  && mark nic_gate_armed REQUIRED PASS "$NGA (fmod_ret security_file_open/ioctl/ioctl_compat/mmap_file/file_permission + sched fork/exec/exit) ; $(cat $O/nicgate_cfg.txt)" \
  || { mark nic_gate_armed REQUIRED FAIL "${NGA:-no NICGATE line} ; $(cat $O/nicgate_cfg.txt 2>/dev/null)"; refuse "nic_gate_arm"; }
tl SENTINELS_READY resource-kernel-sentinel+tamper-sentinel+nic-gate

# broker: authenticated (SO_PEERCRED -> tenant Tgid) + single-serve-per-map (reissue blocked). Socket
# stays tenant-accessible; authorization is by peer identity, not file perms.
BIDS="$CKID,$UID_,$PID_"; [ "${FAIL_INJECT:-}" = "broker_miss" ] && BIDS="$CKID,$PID_"   # omit resource_usage -> its agent init must fail
"$RA/fd_broker_multi" "$SOCK" "$BIDS" "$TPID" > "$O/broker.log" 2>&1 & BRPID=$!; sleep 1; chmod 0777 "$SOCK" 2>/dev/null
grep -qa "ready" "$O/broker.log" || refuse "fd_broker_start"

say "===== LAUNCH: Sentinels + broker READY -> release exec; trusted bootstrap runs to the LAUNCH BARRIER ====="
GOD=/var/lib/chap_gate; mkdir -p $GOD && chown root:root $GOD && chmod 0755 $GOD; { [ "$MT" = 1 ] && rm -f $GOD/go_$TPID $GOD/.go_$TPID 2>/dev/null || rm -f $GOD/go_* $GOD/.go_* 2>/dev/null; }
tl TENANT_EXEC_RELEASED
kill -CONT "$TPID" 2>/dev/null
BOOT=/tmp/chap_boot_$TPID
for w in $(seq 1 90); do grep -qaE "BARRIER_OK|BARRIER_FAIL|BARRIER_TIMEOUT" "$BOOT" 2>/dev/null && break; kill -0 $TPID 2>/dev/null || break; sleep 1; done
sleep 1
cp "$BOOT" "$O/chap_boot.log" 2>/dev/null; cp /tmp/chap_seal_targets_$TPID "$O/seal_targets.txt" 2>/dev/null; cp /tmp/chap_imm_view_$TPID "$O/imm_view.txt" 2>/dev/null
snap(){ local p=$1 api
  kill -USR1 $SPID 2>/dev/null; sleep 1; api=$(grep -aE 'USAGE api_calls' "$O/rsent.log"|tail -1|grep -oE "api_calls=[0-9]+"|grep -oE "[0-9]+")
  echo "state=$(awk '/^State:/{print $2}' /proc/$p/status 2>/dev/null) fd_bpfmap=$(ls -l /proc/$p/fd 2>/dev/null|grep -c bpf-map) fd_nic=$(ls -l /proc/$p/fd 2>/dev/null|grep -cE 'infiniband|vfio|uverbs') fd_huge=$(ls -l /proc/$p/fd 2>/dev/null|grep -cE 'hugepage|rtemap') maps_bpfmap=$(grep -c bpf-map /proc/$p/maps 2>/dev/null) maps_bpfmap_w=$(awk '/bpf-map/ && substr($2,2,1)=="w"' /proc/$p/maps 2>/dev/null|wc -l) rwx=$(awk 'substr($2,1,3)=="rwx"' /proc/$p/maps 2>/dev/null|wc -l) maps_huge=$(grep -cE 'hugepage|rtemap' /proc/$p/maps 2>/dev/null) EAL_lines=$(grep -ac 'EAL:' $W/testpmd.log) initialize_program=$(grep -ac 'initialize program:' $W/testpmd.log) rsrc_api_calls=${api:-NA}"; }
if ! grep -qa "BARRIER_OK" "$BOOT" 2>/dev/null; then
  WHY=$(grep -aoE "BARRIER_(FAIL|TIMEOUT) reason=[^ ]+" "$BOOT" 2>/dev/null | head -1)
  SN=$(snap $TPID); echo "$SN" > "$O/refuse_snapshot.txt"; ls -l /proc/$TPID/fd > "$O/refuse_fds.txt" 2>&1; cat /proc/$TPID/maps > "$O/refuse_maps.txt" 2>&1
  cp "$W/testpmd.log" "$O/refuse_testpmd.log" 2>/dev/null
  mark launch_barrier REQUIRED FAIL "${WHY:-no barrier record} | Manager snapshot (independent): $SN"
  refuse "launch_barrier"
fi
mark launch_barrier REQUIRED PASS "$(grep -aoE 'BARRIER_OK maps=[^ ]+ bpf_map_fds=[0-9]+ ro_map_mappings=[0-9]+ wx_sealed=[0-9]+' "$BOOT"|head -1)"
mark l7_init REQUIRED PASS "verified INSIDE the barrier (esac_hs_init_ok()==1, CHAP_L7_REQUIRED) provider=$(sha256sum "$W/hsprov.so"|cut -c1-16)"
SN=$(snap $TPID); echo "$SN" > "$O/barrier_snapshot.txt"; ls -l /proc/$TPID/fd > "$O/barrier_fds.txt" 2>&1; cat /proc/$TPID/maps > "$O/barrier_maps.txt" 2>&1
for kv in $SN; do eval "B_${kv%%=*}='${kv#*=}'"; done
RIDS=$(grep -aoE "maps=[^ ]+" "$BOOT"|head -1); IDOK=0
echo "$RIDS" | grep -q "comm_policy:$CKID," && echo "$RIDS" | grep -q "resource_usage:$UID_," && echo "$RIDS" | grep -q "resource_policy:$PID_," && IDOK=1
if [ "$IDOK" = 1 ] && [ "$B_fd_bpfmap" = 0 ] && [ "$B_fd_nic" = 0 ] && [ "$B_fd_huge" = 0 ] && [ "$B_maps_bpfmap" -ge 3 ] && [ "$B_maps_bpfmap_w" = 0 ] \
   && [ "$B_rwx" = 0 ] && [ "$B_maps_huge" = 0 ] && [ "$B_EAL_lines" = 0 ] && [ "$B_initialize_program" = 0 ] && [ "$B_rsrc_api_calls" = 0 ]; then
  mark launch_barrier_independent REQUIRED PASS "Manager /proc+bpftool at barrier: map ids comm=$CKID usage=$UID_ policy=$PID_ match; $SN"
else mark launch_barrier_independent REQUIRED FAIL "ids_match=$IDOK; $SN"; refuse "launch_barrier_independent"; fi
# Request Q: tenant privileges read from the kernel at the barrier (before any tenant code runs)
TST=/proc/$TPID/status; TU=$(id -u "$TUSER"); TCAP=0000000000022000
TPRIV="uid=[$(awk '/^Uid:/{print $2,$3,$4,$5}' $TST)] gid=[$(awk '/^Gid:/{print $2,$3,$4,$5}' $TST)] groups=[$(awk '/^Groups:/{$1="";print}' $TST | xargs)] NoNewPrivs=$(awk '/^NoNewPrivs:/{print $2}' $TST) Seccomp=$(awk '/^Seccomp:/{print $2}' $TST) CapPrm=$(awk '/^CapPrm:/{print $2}' $TST) CapEff=$(awk '/^CapEff:/{print $2}' $TST) CapAmb=$(awk '/^CapAmb:/{print $2}' $TST) netns=$(readlink /proc/$TPID/ns/net)"
{ echo "$TPRIV" | grep -q "uid=\[$TU $TU $TU $TU\]" && echo "$TPRIV" | grep -q "groups=\[\]" && echo "$TPRIV" | grep -q "NoNewPrivs=1 Seccomp=2 CapPrm=$TCAP CapEff=$TCAP CapAmb=$TCAP" \
  && { [ -z "$TNS" ] || [ "$(readlink /proc/$TPID/ns/net)" = "$(ip netns exec $TNS readlink /proc/self/ns/net)" ]; }; } \
  && mark tenant_privileges REQUIRED PASS "$TPRIV (caps = CAP_NET_RAW|CAP_SYS_RAWIO; seccomp denies iopl/ioperm)" \
  || refuse_at_barrier tenant_privileges "$TPRIV"
SLOG=/tmp/esac_seal_$TPID.log
SEALED=$(grep -ac "SEAL rwx->r-x" "$SLOG" 2>/dev/null); SFAIL=$(grep -a "SEAL_DONE" "$SLOG"|tail -1|grep -oE "fail=[0-9]+"|grep -oE "[0-9]+")
UFS=$(grep -ac "ENFSEAL ufunc_ctx verify direct_write=FAULTED" "$SLOG" 2>/dev/null)
{ [ "${SEALED:-0}" -ge 1 ] && [ "${SFAIL:-1}" = "0" ] && [ "${UFS:-0}" -ge 1 ]; } && mark code_and_ufunc_seal REQUIRED PASS "in trusted bootstrap: W^X $SEALED rwx->r-x fail=$SFAIL; ufunc table RO direct-write FAULTED" || refuse_at_barrier code_and_ufunc_seal "sealed=$SEALED fail=$SFAIL ufunc_fault=$UFS"
VS=$(grep -a VIEW_SEALED "$O/imm_view.txt"); SC=$(grep -a SEALCHECK "$O/imm_view.txt"); KR=$(grep -ac "mprotect(RW)=refused" "$O/imm_view.txt")
{ [ -n "$VS" ] && echo "$SC" | grep -q "selector_write=FAULTED view_write=FAULTED rodata_write=FAULTED" && [ "$KR" -ge 3 ]; } \
  && mark shm_routing_immutable_view REQUIRED PASS "$VS ; $SC ; kernel-map RO mappings non-upgradable x$KR" \
  || refuse_at_barrier shm_routing_immutable_view "VIEW='$VS' SEALCHECK='$SC' karray_refused=$KR"
cp /tmp/chap_dispatch_$TPID "$O/dispatch.txt" 2>/dev/null
if [ "${SEALED_DISPATCH:-1}" = 1 ]; then
  DS=$(grep -a DISPATCH_SEALED "$O/dispatch.txt"); NH=$(grep -ac "^DISPATCH slot=" "$O/dispatch.txt"); ND=$(grep -ac "direct->thunk" "$O/dispatch.txt")
  EXPH=$(( $(grep -ac "attached at DRIVER level" "$O/loader.log") + 1 + ${NAP:-0} )); CR=$(grep -a "CODE_RANGES registered" "$O/dispatch.txt")
  SCK=$(grep -a DISPATCH_SEALCHECK "$O/dispatch.txt")
  NTX=$(grep -ac "TX attached at DRIVER level" "$O/loader.log"); NEX=$(grep -ac "^DISPATCH slot=.* excl=1 " "$O/dispatch.txt")
  NRX=$(grep -ac "RX attached at DRIVER level" "$O/loader.log"); NRE=$(grep -ac "^DISPATCH slot=.* excl=2 " "$O/dispatch.txt")
  { [ -n "$DS" ] && [ "$NH" = "$EXPH" ] && [ "$NEX" = "$NTX" ] && [ "$NRE" = "$NRX" ] && echo "$SCK" | grep -q "table_write=FAULTED selector_write=FAULTED"; } && mark hook_dispatch_sealed REQUIRED PASS "$DS ; $SCK ; TX burst-exclusion slots=$NEX/$NTX ; RX window-exclusion slots=$NRE/$NRX ; hooks=$NH (=driver RX/TX $((EXPH-1-NAP)) + rte_flow_create + $NAP Table APIs) ; entry->thunk direct $ND/$NH ; $CR" \
    || refuse_at_barrier hook_dispatch_sealed "DS='$DS' hooks=$NH expected=$EXPH tx_excl=$NEX/$NTX SEALCHECK='$SCK'"
elif [ "${UNSAFE_CONTROL_LISTENER:-0}" = "1" ]; then
  mark unsafe_control_listener REQUIRED FAIL "TEST-ONLY control: hook dispatch deliberately NOT sealed (listener path); this run can never PASS"
else
  refuse_at_barrier hook_dispatch_sealed "hook dispatch NOT sealed by the bootstrap (no DISPATCH_SEALED; SEALED_DISPATCH=${SEALED_DISPATCH:-1}) and no explicit unsafe-control flag"
fi
CL=$(grep -aE "r-xp .*dpdk-testpmd" /proc/$TPID/maps 2>/dev/null | head -1)
CS=0x$(echo "$CL"|cut -d- -f1); CE=0x$(echo "$CL"|awk '{print $1}'|cut -d- -f2)
cat /tmp/esac_seal_ranges_$TPID.txt /tmp/chap_imm_ranges_$TPID > "$O/sealed_ranges.txt" 2>/dev/null
python3 -I "$MG/chap_e_tools.py" mergeranges "$O/sealed_ranges.txt" "$O/sealed_ranges_merged.txt" "$CS" "$CE" > "$O/merge.txt" 2>&1
NEXP=$(grep -c . "$O/sealed_ranges_merged.txt")
if [ "${FAIL_INJECT:-}" = "range_drop" ]; then   # drop the registered range that holds the sealed dispatch table
  python3 -I "$MG/chap_e_tools.py" droprange "$O/sealed_ranges_merged.txt" "$(grep -aoE 'table=\[0x[0-9a-f]+' "$O/dispatch.txt" | grep -oE '0x[0-9a-f]+')" > "$O/fail_inject.txt" 2>&1
  NEXP=$(grep -c . "$O/sealed_ranges_merged.txt")
fi
python3 -I "$MG/chap_e_tools.py" rangecheck "$TPID" "$O/sealed_ranges_merged.txt" > "$O/rangecheck.txt" 2>&1; RCOK=$?
BLOCK_EXEC=${BLOCK_EXEC:-0}   # Request P: exec allowed; a new program starts unsealed and the NIC gate stops its NIC access (BLOCK_EXEC=1 restores the legacy exec block)
if "$IK/integ_setranges" "$PIND/protected_ranges" "$PIND/integ_ctl" "$O/sealed_ranges_merged.txt" "$CS" "$CE" "$BLOCK_EXEC" >> "$O/integ.log" 2>&1; then   # block_exec=$BLOCK_EXEC from here on
  NR=$(grep -a 'TOTAL n_ranges' "$O/integ.log"|tail -1|grep -oE "n_ranges=[0-9]+"|grep -oE "[0-9]+"); tl RANGES_REGISTERED n=$NR
  { [ "$RCOK" = 0 ] && [ "${NR:-0}" = "$((NEXP+1))" ]; } && mark integrity_range_register REQUIRED PASS "n_ranges=$NR = $NEXP merged sealed ranges (W^X+ufunc+imm-view+selector+rodata+kernel-map-RO+HS+dispatch+agent/engine code) + hook code seg; $(cat $O/merge.txt); $(tail -1 $O/rangecheck.txt)" \
    || refuse_at_barrier integrity_range_register "n_ranges=$NR expected=$((NEXP+1)); $(tail -1 $O/rangecheck.txt)"
else refuse_at_barrier integrity_range_register "integ_setranges failed"; fi
ND=$( [ "${SEALED_DISPATCH:-1}" = 1 ] && echo 1 || echo 0 )
python3 -I "$MG/chap_e_tools.py" coverage "$TPID" "$O" "$PIND" "$CS" "$CE" "/tmp/esac_seal_$TPID.log" "$ND" > "$O/coverage.txt" 2>&1 \
  && mark protection_target_coverage REQUIRED PASS "$(tail -1 $O/coverage.txt) (each target read back from the Sentinel map)" \
  || refuse_at_barrier protection_target_coverage "$(grep -E 'MISSING|COVERAGE_RESULT' $O/coverage.txt | tr '\n' ' ')"
python3 -I "$MG/chap_e_tools.py" maptrust "$TUSER" "$TPID" > "$O/map_trust.txt" 2>&1 \
  && mark prebarrier_mapped_code_trust REQUIRED PASS "$(tail -1 $O/map_trust.txt) (live /proc maps at the barrier)" \
  || refuse_at_barrier prebarrier_mapped_code_trust "$(grep -E 'UNTRUSTED|MAPTRUST_RESULT' $O/map_trust.txt | tr '\n' ' ')"
# Request P: Sealed Process registration = the LAST step before GO (all protections above verified). Only the Manager
# (root, root-only bpffs pin) writes; identity = tgid + start time, so a reused PID never inherits the status.
if "$IK/chap_nicgate" seal "$PIND" "$TPID" > "$O/nicgate_seal.txt" 2>&1 && "$IK/chap_nicgate" dump "$PIND" > "$O/nicgate_seal_dump.txt" 2>&1 \
   && grep -q "^ENTRY pid=$TPID .*origin=1 " "$O/nicgate_seal_dump.txt"; then
  tl SEALED_REGISTERED pid=$TPID; mark sealed_process_registered REQUIRED PASS "$(cat $O/nicgate_seal.txt) ; $(grep "^ENTRY pid=$TPID " $O/nicgate_seal_dump.txt) ; $(tail -1 $O/nicgate_seal_dump.txt) ; block_exec=$BLOCK_EXEC"
else refuse_at_barrier sealed_process_registered "$(cat $O/nicgate_seal.txt $O/nicgate_seal_dump.txt 2>/dev/null | tr '\n' ' ')"; fi
NONCE=$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n'); tl GO_WRITE_BEGIN token=$NONCE
if printf 'GO %s\n' "$NONCE" > $GOD/.go_$TPID && chmod 0644 $GOD/.go_$TPID && mv -f $GOD/.go_$TPID $GOD/go_$TPID && grep -q "GO $NONCE" $GOD/go_$TPID; then
  tl GO_WRITTEN token=$NONCE; say "GO written (root-owned $GOD/go_$TPID token=$NONCE) after independent verification + full range registration"
else mark go_token_write REQUIRED FAIL "could not write root GO token in $GOD"; refuse "go_token_write"; fi
if [ -n "${RESLAUNCH:-}" ]; then   # Request I launch-time Table tab:apis checks: the over-policy tenant must not reach its prompt
  for w in $(seq 1 60); do kill -0 $TPID 2>/dev/null || break; grep -qaE "testpmd>" "$W/testpmd.log" && break; sleep 1; done
  sleep 1; A=$(kill -0 $TPID 2>/dev/null && echo YES || echo NO); TRC=NA; [ "$A" = NO ] && { wait $LJOB 2>/dev/null; TRC=$?; }
  kill -USR1 $SPID 2>/dev/null; sleep 1; RU2L=$(grep -a USAGE2 "$O/rsent.log" | tail -1); DN=$(echo "$RU2L" | grep -oE "denied2=[0-9]+" | cut -d= -f2)
  CAUSE=$(grep -aE "Cause:|Cannot init EAL|failed|Creation of mbuf pool" "$W/testpmd.log" | tail -2 | tr '\n' ' ')
  PROMPT=$(grep -qaE "testpmd>" "$W/testpmd.log" && echo YES || echo NO); HEV=$(cat $CGDIR/hugetlb.2MB.events 2>/dev/null | tr '\n' ' ')
  echo "RESLAUNCH=$RESLAUNCH policy='${RESPOL_EXTRA:-}' omit='${RES_OMIT:-}' cg_hp_mb=${CG_HP_MB:-2048} alive=$A rc=$TRC prompt=$PROMPT denied2=$DN cause='$CAUSE' hugetlb_events='$HEV' $RU2L" > "$O/reslaunch.txt"
  case "$RESLAUNCH" in
    agent)    [ "$PROMPT" = NO ] && [ "$A" = NO ] && [ "$TRC" != 137 ] && [ "${DN:-1}" = 0 ] && [ -n "$CAUSE" ] ;;
    sentinel) [ "$PROMPT" = NO ] && [ "$A" = NO ] && [ "${DN:-0}" -ge 1 ] ;;
    kernel)   [ "$PROMPT" = NO ] && [ "$A" = NO ] && [ "$TRC" != 137 ] && [ "${DN:-1}" = 0 ] ;;
    *) false ;;
  esac && mark reslaunch_$RESLAUNCH REQUIRED PASS "$(cat $O/reslaunch.txt)" || mark reslaunch_$RESLAUNCH REQUIRED FAIL "$(cat $O/reslaunch.txt)"
  final_verdict; cleanup; echo 0 > /sys/bus/pci/devices/0000:3b:00.1/sriov_numvfs 2>/dev/null; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0
fi
for w in $(seq 1 40); do grep -qaE "testpmd>" "$W/testpmd.log" && break; kill -0 $TPID 2>/dev/null || refuse "tenant_after_go"; sleep 1; done
grep -qaE "testpmd>" "$W/testpmd.log" || refuse "tenant_app_init_after_go"
say "tenant application initialized after GO"
python3 -I "$MG/chap_e_tools.py" order "$W/testpmd.log" > "$O/launch_order.txt" 2>&1; ORC=$?
GOT=$(grep -aoE "GO_RECEIVED token=GO [0-9a-f]+" "$W/testpmd.log"|head -1|awk '{print $NF}')
{ [ "$ORC" = 0 ] && [ "$GOT" = "$NONCE" ]; } && mark launch_order REQUIRED PASS "$(grep '^ORDER ' $O/launch_order.txt) ; GO token matches" || { mark launch_order REQUIRED FAIL "$(grep '^ORDER' $O/launch_order.txt|head -2|tr '\n' ' ') token=$GOT/$NONCE"; refuse launch_order; }

if [ "${MT_HOLD:-0}" = 1 ]; then   # Request I two-tenant: hand the running tenant to the orchestrator
  printf 'TPID=%s\nCGID=%s\nCGDIR=%s\nCKID=%s\nUID_=%s\nPID_=%s\nPIND=%s\nW=%s\nO=%s\nLPID=%s\nSPID=%s\nIPID=%s\nBRPID=%s\nSVFMAC=%s\nSVF=%s\nSOCK=%s\nTLC=%s\n' \
    "$TPID" "$CGID" "$CGDIR" "$CKID" "$UID_" "$PID_" "$PIND" "$W" "$O" "$LPID" "$SPID" "$IPID" "$BRPID" "$SVFMAC" "$SVF" "$SOCK" "$TLC" > "$O/tenant.env"
  touch "$O/HOLD_READY"; say "MT_HOLD: tenant handed to the orchestrator ($O/tenant.env)"
  for w in $(seq 1 1800); do [ -e "$O/HOLD_CONTINUE" ] && break; kill -0 $TPID 2>/dev/null || break; sleep 1; done
  echo "quit" >&3 2>/dev/null; exec 3>&- 2>/dev/null; sleep 3
  final_verdict; cleanup; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0
fi
echo "set fwd rxonly" >&3; echo "start" >&3; sleep 2
CLP=$LPID
RXP(){ kill -USR1 $CLP 2>/dev/null; sleep 1; grep -aE "^0 +0 +[0-9]" "$O/loader.log" | tail -1; }
gen(){ env LD_LIBRARY_PATH=$DPDKLIB timeout 12 "$GEN" -l 8,9 -n4 --in-memory --socket-mem 1024,0 -a "$CVF" --file-prefix=g${$} -- "$1" "$SVFMAC" "$2" "$3" "$4" "$5" "$6" "${7:-none}" > "$O/gen.log" 2>&1; grep -a "^L47GEN" "$O/gen.log"|tail -1; }
# ===== item-2 HARD gated-launch boundary: the tenant was loaded CLOSED; the fail-closed Filter DROPS
# every packet until the Manager ARMS it (installs ALLOW) AFTER seal + sentinels + range registration.
# This is a STRUCTURAL gate (fail-closed policy), not "we delayed sending traffic". =====
GA0=$(RXP|awk '{print $6+0}'); GD0=$(RXP|awk '{print $5+0}')
gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2                                   # probe BEFORE arm
GA1=$(RXP|awk '{print $6+0}'); GD1=$(RXP|awk '{print $5+0}')
PRE_ALLOW=$((GA1-GA0)); PRE_DROP=$((GD1-GD0))
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" "$MDP" 17 0 >> "$O/flip.log" 2>&1; sleep 1   # ARM
gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2                                   # probe AFTER arm
GA2=$(RXP|awk '{print $6+0}')
POST_ALLOW=$((GA2-GA1))
{ [ "$PRE_ALLOW" -lt 100 ] && [ "$PRE_DROP" -gt 1000 ] && [ "$POST_ALLOW" -gt 1000 ]; } \
  && mark gated_launch_hard_arm REQUIRED PASS "pre-arm allow+=$PRE_ALLOW drop+=$PRE_DROP (CLOSED until armed); post-arm allow+=$POST_ALLOW (opened only after seal+sentinels+register)" \
  || mark gated_launch_hard_arm REQUIRED FAIL "pre-arm allow+=$PRE_ALLOW drop+=$PRE_DROP post-arm allow+=$POST_ALLOW"
A0=$(RXP|awk '{print $6+0}'); D0=$(RXP|awk '{print $5+0}')
gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2
gen 2000 10.0.0.9 $MDIP $MSP $MDP udp >/dev/null; sleep 2
A1=$(RXP|awk '{print $6+0}'); D1=$(RXP|awk '{print $5+0}')
CA=$((A1-A0)); CD=$((D1-D0))
{ [ "$CA" -gt 1000 ] && [ "$CD" -gt 1000 ]; } && mark comm_L4_allow_drop REQUIRED PASS "match->allow+=$CA nomatch->drop+=$CD" || mark comm_L4_allow_drop REQUIRED FAIL "allow+=$CA drop+=$CD (expect both>1000)"

A2=$(RXP|awk '{print $6+0}'); D2=$(RXP|awk '{print $5+0}')
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" "$MDP" 17 2 >> "$O/flip.log" 2>&1; sleep 1
gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2
A3=$(RXP|awk '{print $6+0}'); D3=$(RXP|awk '{print $5+0}'); FDROP=$((D3-D2))
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" "$MDP" 17 0 >> "$O/flip.log" 2>&1; sleep 1
gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2
A4=$(RXP|awk '{print $6+0}'); D4=$(RXP|awk '{print $5+0}'); FALLOW=$((A4-A3))
{ [ "${FDROP:-0}" -gt 1000 ] && [ "${FALLOW:-0}" -gt 1000 ]; } && mark comm_live_flip REQUIRED PASS "ALLOW->DROP drop+=$FDROP ; DROP->ALLOW allow+=$FALLOW" || mark comm_live_flip REQUIRED FAIL "flipDROP=$FDROP flipALLOW=$FALLOW"

# ===== item-6 L7 in the SAME unified loader (combo c_filter+hs_gate + native HS ufunc); L4 ALLOWs the
# tuple now (live_flip ended ALLOW), so hs_gate inspects the payload. Resource + Integrity still active. =====
mark l7_combo_in_use REQUIRED PASS "bpf=$(basename $CFILTER) ufunc_provider=$(sha256sum $W/hsprov.so|cut -c1-16) runtime=$(sha256sum $W/agent.so|cut -c1-16)"
LB0=$(RXP|awk '{print $6+0}'); LD0=$(RXP|awk '{print $5+0}')
gen 2000 $MSIP $MDIP $MSP $MDP udp "dns:good.example.com" >/dev/null; sleep 2
LB1=$(RXP|awk '{print $6+0}'); LD1=$(RXP|awk '{print $5+0}'); L7_BEN_ALLOW=$((LB1-LB0))
gen 2000 $MSIP $MDIP $MSP $MDP udp "dns:evilmal.attacker.ru" >/dev/null; sleep 2
LB2=$(RXP|awk '{print $6+0}'); LD2=$(RXP|awk '{print $5+0}'); L7_MAL_DROP=$((LD2-LD1)); L7_MAL_ALLOW=$((LB2-LB1))
{ [ "$L7_BEN_ALLOW" -gt 1000 ] && [ "$L7_MAL_DROP" -gt 1000 ] && [ "$L7_MAL_ALLOW" -lt 200 ]; } \
  && mark l7_benign_allow_malicious_drop REQUIRED PASS "benign allow+=$L7_BEN_ALLOW ; malicious(evilmal) drop+=$L7_MAL_DROP (leak allow+=$L7_MAL_ALLOW)" \
  || mark l7_benign_allow_malicious_drop REQUIRED FAIL "benign allow+=$L7_BEN_ALLOW malicious drop+=$L7_MAL_DROP leak+=$L7_MAL_ALLOW"
# L4-DROP must NOT be revived by an L7-ALLOW (hs_gate escalate-only)
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" "$MDP" 17 2 >> "$O/flip.log" 2>&1; sleep 1
LB3=$(RXP|awk '{print $6+0}'); LD3=$(RXP|awk '{print $5+0}')
gen 2000 $MSIP $MDIP $MSP $MDP udp "dns:good.example.com" >/dev/null; sleep 2
LB4=$(RXP|awk '{print $6+0}'); LD4=$(RXP|awk '{print $5+0}'); L4DROP_STAY=$((LD4-LD3)); L4DROP_LEAK=$((LB4-LB3))
{ [ "$L4DROP_STAY" -gt 1000 ] && [ "$L4DROP_LEAK" -lt 200 ]; } \
  && mark l4drop_not_revived_by_l7 REQUIRED PASS "L4=DROP + benign payload stays DROP+=$L4DROP_STAY (L7-allow leak+=$L4DROP_LEAK)" \
  || mark l4drop_not_revived_by_l7 REQUIRED FAIL "stayDrop+=$L4DROP_STAY leak+=$L4DROP_LEAK"
"$W/policy_flip" "$CKID" 16384 "$CGID" "$MSIP" "$MDIP" "$MSP" "$MDP" 17 0 >> "$O/flip.log" 2>&1; sleep 1
if [ "${ALIAS:-0}" = "1" ]; then
  # item-1 backing-object test: a SECOND writable alias of the bpftime SHM (the /dev/shm file, written AS THE
  # TENANT UID) corrupts the SHM copies of RCFG.enabled and two routing handlers (comm_policy, rxburst_drv_pen).
  python3 -I "$MG/chap_e_tools.py" aliasops "$O/seal_targets.txt" > "$O/alias_ops.txt" 2>&1
  OPS=$(grep '^OPS ' "$O/alias_ops.txt" | cut -d' ' -f2-)
  runuser -u "$(stat -c %U /proc/$TPID)" -- python3 -I "$MG/chap_e_tools.py" alias "/dev/shm/$SHM" $OPS > "$O/alias_write.txt" 2>&1
  LANDED=$(grep -c "landed=True" "$O/alias_write.txt"); sleep 1
  AA0=$(RXP|awk '{print $6+0}'); AD0=$(RXP|awk '{print $5+0}')
  gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2
  AA1=$(RXP|awk '{print $6+0}'); AD1=$(RXP|awk '{print $5+0}')
  gen 2000 10.0.0.9 $MDIP $MSP $MDP udp >/dev/null; sleep 2
  AA2=$(RXP|awk '{print $6+0}'); AD2=$(RXP|awk '{print $5+0}')
  gen 2000 $MSIP $MDIP $MSP $MDP udp "dns:evilmal.attacker.ru" >/dev/null; sleep 2
  AA3=$(RXP|awk '{print $6+0}'); AD3=$(RXP|awk '{print $5+0}')
  M_ALLOW=$((AA1-AA0)); N_DROP=$((AD2-AD1)); L7_DROP=$((AD3-AD2)); L7_LEAK=$((AA3-AA2))
  ADESC="$(grep '^DESC' "$O/alias_ops.txt" | cut -d' ' -f2-)"
  if [ "${ALIAS_EXPECT:-protected}" = "protected" ]; then
    { [ "$LANDED" = 3 ] && [ "$M_ALLOW" -gt 1000 ] && [ "$N_DROP" -gt 1000 ] && [ "$L7_DROP" -gt 1000 ] && [ "$L7_LEAK" -lt 200 ]; } \
      && mark shm_alias_no_effect REQUIRED PASS "3 SHM-alias writes landed ($ADESC); enforcement unchanged: match allow+=$M_ALLOW nomatch drop+=$N_DROP L7 drop+=$L7_DROP leak+=$L7_LEAK" \
      || mark shm_alias_no_effect REQUIRED FAIL "landed=$LANDED match_allow=$M_ALLOW nomatch_drop=$N_DROP l7_drop=$L7_DROP l7_leak=$L7_LEAK"
  else
    mark shm_alias_prefix_control OPTIONAL INFO "PRE-FIX runtime: landed=$LANDED ($ADESC) -> match allow+=$M_ALLOW nomatch drop+=$N_DROP L7 drop+=$L7_DROP (decisions stop if all ~0)"
  fi
fi


if [ "${PROGFN_ATK:-0}" = "1" ]; then
  # Request F discriminating test: overwrite the heap pointer the LISTENER dispatch calls (bpftime_prog::fn)
  # with a function returning 0 (tenant-side, in-model), then re-check enforcement.
  kill -s RTMIN+11 "$TPID" 2>/dev/null; sleep 2
  PATK=$(grep -a "ATK_PROGFN" "$W/testpmd.log" | tail -1)
  PA0=$(RXP|awk '{print $6+0}'); PD0=$(RXP|awk '{print $5+0}')
  gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2
  PA1=$(RXP|awk '{print $6+0}'); PD1=$(RXP|awk '{print $5+0}')
  gen 2000 10.0.0.9 $MDIP $MSP $MDP udp >/dev/null; sleep 2
  PA2=$(RXP|awk '{print $6+0}'); PD2=$(RXP|awk '{print $5+0}')
  gen 2000 $MSIP $MDIP $MSP $MDP udp "dns:evilmal.attacker.ru" >/dev/null; sleep 2
  PA3=$(RXP|awk '{print $6+0}'); PD3=$(RXP|awk '{print $5+0}')
  PALV=$(kill -0 $TPID 2>/dev/null && echo YES || echo NO)
  PM=$((PA1-PA0)); PN=$((PD2-PD1)); PL=$((PD3-PD2)); PK=$((PA3-PA2))
  if [ "${SEALED_DISPATCH:-1}" = 1 ]; then
    { [ "$PALV" = YES ] && [ "$PM" -gt 1000 ] && [ "$PN" -gt 1000 ] && [ "$PL" -gt 1000 ] && [ "$PK" -lt 200 ] && echo "$PATK" | grep -qE "overwritten=[1-9]"; } \
      && mark progfn_tamper_no_effect REQUIRED PASS "$PATK ; tenant alive; enforcement unchanged (sealed table holds its own RO copy): match allow+=$PM nomatch drop+=$PN L7 drop+=$PL leak+=$PK" \
      || mark progfn_tamper_no_effect REQUIRED FAIL "$PATK ; alive=$PALV match allow+=$PM nomatch drop+=$PN L7 drop+=$PL leak+=$PK"
  else
    mark progfn_tamper_control OPTIONAL INFO "LISTENER dispatch (SEALED_DISPATCH=0): $PATK ; alive=$PALV ; match allow+=$PM nomatch drop+=$PN L7 drop+=$PL (filter decisions stop if ~0 = bypass)"
  fi
fi

if [ "${DISPATCH_ATK:-0}" = "1" ]; then
  # Request F: tenant-side overwrite of EVERY writable word pointing into anonymous executable code (JIT +
  # Frida slices) with a "return 0" function, then re-check enforcement.
  kill -s RTMIN+10 "$TPID" 2>/dev/null; AT0=$(date +%s)
  # the test-only handler scans every writable mapping (incl. hugepages) word by word: wait for its summary line
  for w in $(seq 1 300); do grep -qa "ATK_DISPATCH" "/tmp/esac_seal_$TPID.log" 2>/dev/null && break; kill -0 $TPID 2>/dev/null || break; sleep 1; done
  ATK="$(grep -a "ATK_DISPATCH" "/tmp/esac_seal_$TPID.log" | tail -1) (handler $(( $(date +%s) - AT0 )) s)"; cp "/tmp/esac_seal_$TPID.log" "$O/esac_seal_atk.log" 2>/dev/null
  XA0=$(RXP|awk '{print $6+0}'); XD0=$(RXP|awk '{print $5+0}')
  gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 2
  XA1=$(RXP|awk '{print $6+0}'); XD1=$(RXP|awk '{print $5+0}')
  gen 2000 10.0.0.9 $MDIP $MSP $MDP udp >/dev/null; sleep 2
  XA2=$(RXP|awk '{print $6+0}'); XD2=$(RXP|awk '{print $5+0}')
  gen 2000 $MSIP $MDIP $MSP $MDP udp "dns:evilmal.attacker.ru" >/dev/null; sleep 2
  XA3=$(RXP|awk '{print $6+0}'); XD3=$(RXP|awk '{print $5+0}')
  ALV=$(kill -0 $TPID 2>/dev/null && echo YES || echo NO)
  XM=$((XA1-XA0)); XN=$((XD2-XD1)); XL=$((XD3-XD2)); XK=$((XA3-XA2))
  if [ "${SEALED_DISPATCH:-1}" = 1 ]; then
    { [ "$ALV" = YES ] && [ "$XM" -gt 1000 ] && [ "$XN" -gt 1000 ] && [ "$XL" -gt 1000 ] && [ "$XK" -lt 200 ] && echo "$ATK" | grep -qE "overwritten=[1-9]"; } \
      && mark dispatch_ptr_tamper_no_effect REQUIRED PASS "$ATK ; tenant alive; enforcement unchanged: match allow+=$XM nomatch drop+=$XN L7 drop+=$XL leak+=$XK" \
      || mark dispatch_ptr_tamper_no_effect REQUIRED FAIL "$ATK ; alive=$ALV match allow+=$XM nomatch drop+=$XN L7 drop+=$XL leak+=$XK"
  else
    mark dispatch_ptr_tamper_control OPTIONAL INFO "LISTENER dispatch (SEALED_DISPATCH=0): $ATK ; alive=$ALV ; match allow+=$XM nomatch drop+=$XN L7 drop+=$XL (decisions stop if ~0)"
  fi
fi

if [ "${TX_TEST:-0}" = "1" ]; then
  # Request G: TX enforcement through the sealed dispatcher's burst exclusion. testpmd txonly with
  # --txonly-multi-flow: src = 10.0.v.8 (v = 0..255, +1 per packet), dst 10.0.0.1, udp 2222->1111.
  PF=$W/peer_cmd; mkfifo "$PF"; chmod 600 "$PF"
  env LD_LIBRARY_PATH=$DPDKLIB setsid stdbuf -oL "$TESTPMD" -l 10,11 -n4 --in-memory --socket-mem 1024,0 -a "$CVF" --file-prefix=peer${$} -- -i < "$PF" > "$O/peer_testpmd.log" 2>&1 &
  exec 4>"$PF"; for w in $(seq 1 30); do grep -qa "testpmd>" "$O/peer_testpmd.log" && break; sleep 1; done
  echo "set promisc all on" >&4; echo "set fwd rxonly" >&4; echo "start" >&4; sleep 1
  # per-source counters on the peer NIC: v=0 (10.0.0.8, allowed in MIXED) and v=1 (10.0.1.8, dropped in MIXED)
  echo "flow create 0 ingress pattern eth / ipv4 src is 10.0.0.8 / end actions count / queue index 0 / end" >&4; sleep 0.5
  echo "flow create 0 ingress pattern eth / ipv4 src is 10.0.1.8 / end actions count / queue index 0 / end" >&4; sleep 0.5
  PEERMAC=$(grep -aoE "Port 0: [0-9A-Fa-f:]{17}" "$O/peer_testpmd.log" | head -1 | awk '{print $3}')
  echo "set eth-peer 0 $PEERMAC" >&3; sleep 1; say "TX test: peer MAC=$PEERMAC"
  peer_rx(){ echo "show port stats 0" >&4; sleep 1; grep -a "RX-packets:" "$O/peer_testpmd.log" | tail -1 | awk '{print $2+0}'; }
  peer_cnt(){ echo "flow query 0 $1 count" >&4; sleep 0.7; awk '/^ *hits:/{v=$2} END{print v+0}' "$O/peer_testpmd.log"; }
  cap(){ local l0; l0=$(wc -l < "$W/testpmd.log"); echo "$2" >&3; sleep 1.5; tail -n +$((l0+1)) "$W/testpmd.log" > "$1"; }
  dumps(){ ls "$TCWD" 2>/dev/null | grep -c "^dpdk_mlx5_port_"; }
  ltid(){ for t in /proc/$TPID/task/*; do grep -qE "^(rte|lcore)-worker-7$" $t/comm 2>/dev/null && { echo ${t##*/}; return; }; done; }
  TSOCK=$DPDKRUN/dpdk/chap3pu${$}/dpdk_telemetry.v2
  tele(){ python3 -I "$MG/chap_e_tools.py" tele "$TSOCK" /ethdev/stats,0 /ethdev/xstats,0 > "$1" 2>&1; }
  opk(){ python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['/ethdev/stats']['opackets'])" "$1" 2>/dev/null || echo -1; }
  setv(){ local a=$1; shift; for v in "$@"; do "$W/policy_flip" "$CKID" 16384 "$CGID" 10.0.$v.8 10.0.0.1 2222 1111 17 $a >> "$O/flip.log" 2>&1; done; }
  ALLV=$(seq 0 255); ODDV=$(seq 1 2 255); EVENV=$(seq 0 2 254)
  echo "stop" >&3; sleep 1; echo "set fwd txonly" >&3; sleep 1; : > "$O/tx_phases.txt"
  txphase(){ local nm=$1 q0 q1 c00 c01 c10 c11 pb pa d0 d1 d2 tid
    pb=$(peer_rx); c00=$(peer_cnt 0); c10=$(peer_cnt 1); q0=$(RXP); d0=$(dumps); tele "$O/txm_${nm}_tele_before.json"
    echo "start" >&3; sleep 3; echo "stop" >&3; sleep 1                         # counting window (no tracer attached)
    pa=$(peer_rx); c01=$(peer_cnt 0); c11=$(peer_cnt 1); q1=$(RXP); d1=$(dumps); tele "$O/txm_${nm}_tele_after.json"
    echo "dump_mempool" >&3; sleep 0.5                                            # mbuf pool state (parsed after quit)
    echo "start" >&3; sleep 1; tid=$(ltid)                                        # syscall window: every syscall of the TX lcore
    timeout -s INT 2 strace -c -p "$tid" -o "$O/txm_${nm}_strace.txt" >/dev/null 2>"$O/txm_${nm}_strace.err"; echo "stop" >&3; sleep 1; d2=$(dumps)
    local f4 f5 f6 f11 ftx fdr fal txd sok sc pvw bpfc pmd
    f(){ echo "$1" | awk -v c=$2 '{print $c+0}'; }
    ftx=$(( $(f "$q1" 4) - $(f "$q0" 4) )); fdr=$(( $(f "$q1" 5) - $(f "$q0" 5) )); fal=$(( $(f "$q1" 6) - $(f "$q0" 6) )); txd=$(( $(f "$q1" 11) - $(f "$q0" 11) ))
    sok=$(grep -c "Process ${tid:-x} attached" "$O/txm_${nm}_strace.err" 2>/dev/null)   # attach evidence (summary is empty when 0 syscalls); sc=$(awk '/total$/{print $4+0}' "$O/txm_${nm}_strace.txt" 2>/dev/null)
    pvw=$(awk '/process_vm_writev$/{print $4+0}' "$O/txm_${nm}_strace.txt" 2>/dev/null); bpfc=$(awk '$NF=="bpf"{print $4+0}' "$O/txm_${nm}_strace.txt" 2>/dev/null)
    pmd=$(( $(opk "$O/txm_${nm}_tele_after.json") - $(opk "$O/txm_${nm}_tele_before.json") ))
    echo "TXPHASE $nm peer_rx=$((pa-pb)) peer_v0=$((c01-c00)) peer_v1=$((c11-c10)) filt_tx=$ftx filt_drop=$fdr filt_allow=$fal pmd_tx=$pmd app_ret=$((ftx-txd)) app_short_ret=$txd err_cqe_dumps=$((d1-d0)) err_cqe_dumps_tracewin=$((d2-d1)) strace_ok=${sok:-0} lcore_syscalls=${sc:-0} process_vm_writev=${pvw:-0} bpf=${bpfc:-0} strace_tid=${tid:-none}" | tee -a "$O/tx_phases.txt" | sed 's/^/[3pu] /'; }
  echo "dump_mempool" >&3; sleep 0.5                                              # baseline pool state (idx 0)
  txphase P1_ALL_DROP                                   # no rule for any v -> default DROP
  setv 0 $ALLV;  txphase P2_ALL_ALLOW
  setv 2 $ODDV;  txphase P3_MIXED                       # even v ALLOW, odd v DROP -> 16/16 inside every 32-packet burst
  setv 2 $EVENV; txphase P4_ALL_DROP_AGAIN
  setv 0 $ALLV;  txphase P5_ALLOW_AFTER_DROP
  setv 2 $ODDV; echo "set burst 64" >&3; sleep 0.5; txphase P6_MIXED_BURST64; echo "set burst 32" >&3; sleep 0.5   # 2 verdict windows per call
  echo "quit" >&4 2>/dev/null; exec 4>&- 2>/dev/null; sleep 2
  echo "set fwd rxonly" >&3; sleep 1; echo "start" >&3; sleep 1
fi

if [ "${RX_TEST:-0}" = "1" ]; then
  # Request H: RX enforcement in verdict windows of 32 across bursts of 32/64/128. Generator: peer testpmd txonly
  # --txonly-multi-flow, src 10.0.v.13 (v = 0..255, +1 per packet) -> 10.0.0.2, udp 1111->2222. Tenant: rxonly.
  RPF=$W/peer_rx_cmd; mkfifo "$RPF"; chmod 600 "$RPF"
  env LD_LIBRARY_PATH=$DPDKLIB setsid stdbuf -oL "$TESTPMD" -l 10,11 -n4 --in-memory --socket-mem 1024,0 -a "$CVF" --file-prefix=peer${$}rx -- -i --tx-ip=10.0.0.1,10.0.0.2 --tx-udp=1111,2222 --txonly-multi-flow < "$RPF" > "$O/peer_rx_gen.log" 2>&1 &
  exec 5>"$RPF"; for w in $(seq 1 30); do grep -qa "testpmd>" "$O/peer_rx_gen.log" && break; sleep 1; done
  echo "set fwd txonly" >&5; echo "set eth-peer 0 $SVFMAC" >&5; sleep 1
  gtx(){ echo "show port stats 0" >&5; sleep 1; grep -a "TX-packets:" "$O/peer_rx_gen.log" | tail -1 | awk '{print $2+0}'; }
  setr(){ local a=$1; shift; for v in "$@"; do "$W/policy_flip" "$CKID" 16384 "$CGID" 10.0.$v.13 10.0.0.2 1111 2222 17 $a >> "$O/flip.log" 2>&1; done; }
  RSOCK=$DPDKRUN/dpdk/chap3pu${$}/dpdk_telemetry.v2
  rtele(){ python3 -I "$MG/chap_e_tools.py" tele "$RSOCK" /ethdev/stats,0 > "$1" 2>&1; }
  rst(){ python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['/ethdev/stats'][sys.argv[2]])" "$1" "$2" 2>/dev/null || echo -1; }
  rtid(){ for t in /proc/$TPID/task/*; do grep -qE "^(rte|lcore)-worker-7$" $t/comm 2>/dev/null && { echo ${t##*/}; return; }; done; }
  RALLV=$(seq 0 255); RODDV=$(seq 1 2 255); REVENV=$(seq 0 2 254)
  echo "stop" >&3; sleep 1; echo "set fwd rxonly" >&3; echo "set record-burst-stats on" >&3; sleep 0.5; : > "$O/rx_phases.txt"
  rxphase(){ local nm=$1 b=$2 q0 q1 g0 g1 tid
    echo "set burst $b" >&3; sleep 0.3; echo "dump_mempool" >&3; sleep 0.3        # phase delimiter + pool state (parsed after quit)
    # app-visible result = return values of the sealed RX dispatcher (what rte_eth_rx_burst hands the app);
    # windows per call = RX verdicts per dispatcher call (one per 32 inspected packets)
    local DSYM=_ZL16chap_dispatch_rxPK14chap_disp_slotmmmmmmRN7bpftime7pt_regsE
    cat > "$O/rxm_${nm}.bt" <<EOB
uprobe:$W/agent.so:$DSYM /pid == $TPID/ { @w[tid] = 0; }
uprobe:$W/agent.so:bpftime_set_retval /pid == $TPID && (arg0 >> 48) == 0xc4aa/ { @w[tid] = @w[tid] + 1; @verdicts = count(); }
uretprobe:$W/agent.so:$DSYM /pid == $TPID/ { @app_rx = sum(retval & 0xffff); if (@w[tid] > 0) { @nonempty_calls = count(); @windows_per_call = lhist(@w[tid], 0, 8, 1); @kept_per_call = lhist(retval & 0xffff, 0, 136, 8); } }
EOB
    bpftrace "$O/rxm_${nm}.bt" > "$O/rxm_${nm}_bt.txt" 2>&1 & local BTP=$!
    for i in $(seq 1 40); do grep -q "Attaching" "$O/rxm_${nm}_bt.txt" && break; sleep 0.5; done; sleep 2
    q0=$(RXP); g0=$(gtx); rtele "$O/rxm_${nm}_tele_before.json"
    echo "start" >&3; sleep 0.5; echo "start" >&5; sleep 3; echo "stop" >&5; sleep 0.5; echo "stop" >&3; sleep 1
    q1=$(RXP); g1=$(gtx); rtele "$O/rxm_${nm}_tele_after.json"
    kill -INT $BTP 2>/dev/null; wait $BTP 2>/dev/null
    local apprx maxw; apprx=$(awk '/^@app_rx:/{print $2+0}' "$O/rxm_${nm}_bt.txt"); apprx=${apprx:-0}
    maxw=$(awk '/^@windows_per_call:/{f=1;next} f&&/^\[/{split($1,a,/[\[,)]/); if ($2+0>0) m=a[2]} f&&/^$/{f=0} END{print m+0}' "$O/rxm_${nm}_bt.txt")
    echo "start" >&3; sleep 0.5; echo "start" >&5; sleep 1; tid=$(rtid)          # syscall window: every syscall of the RX lcore
    timeout -s INT 2 strace -c -p "$tid" -o "$O/rxm_${nm}_strace.txt" >/dev/null 2>"$O/rxm_${nm}_strace.err"; echo "stop" >&5; sleep 0.5; echo "stop" >&3; sleep 1
    f(){ echo "$1" | awk -v c=$2 '{print $c+0}'; }
    local frx fdr fal ipk nomb imis sok sc pvw bpfc
    frx=$(( $(f "$q1" 3) - $(f "$q0" 3) )); fdr=$(( $(f "$q1" 5) - $(f "$q0" 5) )); fal=$(( $(f "$q1" 6) - $(f "$q0" 6) ))
    ipk=$(( $(rst "$O/rxm_${nm}_tele_after.json" ipackets) - $(rst "$O/rxm_${nm}_tele_before.json" ipackets) ))
    nomb=$(( $(rst "$O/rxm_${nm}_tele_after.json" rx_nombuf) - $(rst "$O/rxm_${nm}_tele_before.json" rx_nombuf) ))
    imis=$(( $(rst "$O/rxm_${nm}_tele_after.json" imissed) - $(rst "$O/rxm_${nm}_tele_before.json" imissed) ))
    sok=$(grep -c "Process ${tid:-x} attached" "$O/rxm_${nm}_strace.err" 2>/dev/null); sc=$(awk '/total$/{print $4+0}' "$O/rxm_${nm}_strace.txt" 2>/dev/null)
    pvw=$(awk '/process_vm_writev$/{print $4+0}' "$O/rxm_${nm}_strace.txt" 2>/dev/null); bpfc=$(awk '$NF=="bpf"{print $4+0}' "$O/rxm_${nm}_strace.txt" 2>/dev/null)
    echo "RXPHASE $nm burst=$b gen_tx=$((g1-g0)) pmd_rx=$ipk app_rx=$apprx max_windows_per_call=$maxw filt_rx=$frx filt_allow=$fal filt_drop=$fdr rx_nombuf=$nomb imissed=$imis strace_ok=${sok:-0} lcore_syscalls=${sc:-0} process_vm_writev=${pvw:-0} bpf=${bpfc:-0} strace_tid=${tid:-none}" | tee -a "$O/rx_phases.txt" | sed 's/^/[3pu] /'; }
  if [ "${FAIL_INJECT:-}" = "rx_window_fail" ]; then
    setr 0 $RALLV; echo "set burst 64" >&3; sleep 0.3
    echo "start" >&3; sleep 0.5; echo "start" >&5
    for i in $(seq 1 30); do kill -0 $TPID 2>/dev/null || break; sleep 0.5; done
    echo "stop" >&5; sleep 0.5
    RALIVE=$(kill -0 $TPID 2>/dev/null && echo YES || echo NO); KEV=$(grep -ai "ACT_KILL event" "$O/loader.log" | head -1)
    { [ "$RALIVE" = NO ] && [ -n "$KEV" ]; } \
      && mark rx_window_failclosed REQUIRED PASS "TEST-ONLY filter: inspection of RX window >= 2 fails -> window withheld from the app + KILL event -> tenant killed ; $KEV" \
      || mark rx_window_failclosed REQUIRED FAIL "alive=$RALIVE event='$KEV'"
    echo "quit" >&5 2>/dev/null; exec 5>&- 2>/dev/null; final_verdict; cleanup; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0
  fi
  rxphase R1_ALL_DROP 32                                   # no rule for any v -> default DROP
  setr 0 $RALLV;  rxphase R2_ALL_ALLOW 32
  setr 2 $RODDV;  rxphase R3_MIXED 32                     # even v ALLOW, odd v DROP (alternating inside every burst)
                  rxphase R4_MIXED 64
                  rxphase R5_MIXED 128                    # drop targets at positions > 32 in every burst
  setr 2 $REVENV; rxphase R6_ALL_DROP 128
  setr 0 $RALLV;  rxphase R7_ALL_ALLOW_AFTER_DROP 128
  echo "set burst 32" >&3; sleep 0.3; echo "dump_mempool" >&3; sleep 0.5        # final pool state
  echo "quit" >&5 2>/dev/null; exec 5>&- 2>/dev/null; sleep 1
  echo "set record-burst-stats off" >&3; echo "set fwd rxonly" >&3; sleep 0.5; echo "start" >&3; sleep 1
fi

[ "${RXSLOT_PROBE:-0}" = 1 ] && . "$MG/reqI_rxslot_block.sh"   # Request I: RX burst variant in use (exits)
[ "${PERF1:-0}" = 1 ] && . "$MG/reqI_perf1_block.sh"   # Request I: one representative RX sample (exits)
[ "${UNCLASS_TEST:-0}" = 1 ] && . "$MG/reqI_unclass_block.sh"   # Request I: non-IPv4 / fragment / malformed -> default DROP
[ "${WILD:-0}" = 1 ] && . "$MG/reqI_wild_block.sh"   # Request I: 64 mask-probe (NIC representative cases)
[ "${RESP:-0}" = 1 ] && . "$MG/reqI_resp_block.sh"   # Request I: Redis RESP payload policy
STR_OUT="$O/strace.out"; : > "$STR_OUT"
( strace -f -e trace=bpf -p "$TPID" -o "$STR_OUT" 2>"$O/strace.err" & STR=$!; sleep 1; gen 2000 $MSIP $MDIP $MSP $MDP udp >/dev/null; sleep 1; kill $STR 2>/dev/null; wait $STR 2>/dev/null ) 2>/dev/null
if grep -qaE "attached" "$O/strace.err" 2>/dev/null; then
  BPFSYS=$(grep -ac "bpf(" "$STR_OUT")
  [ "$BPFSYS" -eq 0 ] && mark comm_zero_bpf_syscall REQUIRED PASS "strace attached (strace.err evidence); bpf() during packet phase = 0" \
                      || mark comm_zero_bpf_syscall REQUIRED FAIL "strace attached; bpf() during packet phase = $BPFSYS (NOT zero-syscall)"
else
  mark comm_zero_bpf_syscall REQUIRED NOT_TESTED "strace did NOT attach (see strace.err) -> a 0 count would be meaningless"
fi

echo "stop" >&3; sleep 1
if [ -n "${RATE:-}" ]; then
  # RATE mode: hard_flows=10000 (non-binding), rate=1/s, burst=2 -> only ~burst pass the Agent (GCRA RO pre-check)
  "$RPOL" "$PIND/resource_policy" 0 hard_flows=10000 flow_rate=1 flow_burst=2 >> "$O/respolicy.log" 2>&1
  sleep 1
  tl RESOURCE_API_FIRST_CALL rate-mode; for i in $(seq 1 8); do kill -0 $TPID 2>/dev/null||break; echo "flow create 0 ingress pattern eth / end actions drop / end" >&3; done
  sleep 2; kill -USR1 $SPID 2>/dev/null; sleep 1
  ALIVE=$(kill -0 $TPID 2>/dev/null && echo YES || echo NO)
  RU=$(grep -aE 'USAGE api_calls' "$O/rsent.log"|tail -1); RAPI=$(echo "$RU"|grep -oE "api_calls=[0-9]+"|grep -oE "[0-9]+")
  { [ "$ALIVE" = "YES" ] && [ "${RAPI:-99}" -le 3 ]; } \
    && mark resource_agent_rate_predeny REQUIRED PASS "rate=1 burst=2: 8 rapid creates -> only $RAPI reached the kernel (GCRA); Agent gracefully pre-denied over-rate, tenant ALIVE=$ALIVE ($RU)" \
    || mark resource_agent_rate_predeny REQUIRED FAIL "api_calls=$RAPI alive=$ALIVE ($RU)"
else
  tl RESOURCE_API_FIRST_CALL quota-mode; for i in $(seq 1 $((HARD+3))); do kill -0 $TPID 2>/dev/null||break; echo "flow create 0 ingress pattern eth / end actions drop / end" >&3; sleep 0.4; done
  sleep 2; kill -USR1 $SPID 2>/dev/null; sleep 1
  RU=$(grep -aE 'USAGE api_calls' "$O/rsent.log"|tail -1); RAPI=$(echo "$RU"|grep -oE "api_calls=[0-9]+"|grep -oE "[0-9]+")
  [ "${RAPI:-0}" = "$HARD" ] && mark resource_agent_prededny REQUIRED PASS "api_calls=$RAPI==HARD (surplus pre-blocked; $RU)" || mark resource_agent_prededny REQUIRED FAIL "api_calls=${RAPI:-?} hard=$HARD ($RU)"
fi

[ -n "${MEMJ:-}" ] && . "$MG/reqJ_memrate_block.sh"   # Request J: memory-API rate at the sealed-dispatch boundary
[ -n "${NICJ:-}" ] && . "$MG/reqP_nicgate_block.sh"   # Request P: Sealed-Process NIC gate (TEST-ONLY driver)
[ -n "${NICQ:-}" ] && . "$MG/reqQ_nicgate_block.sh"   # Request Q: privileges, non-uverbs NIC paths, lifecycle (TEST-ONLY driver)
if [ "${RESAPI:-0}" = "1" ]; then   # Request I: Table tab:apis at runtime (live Manager policy updates)
  . "$MG/reqI_resapi_block.sh"
  [ -n "${RESAPI_BYPASS:-}" ] && { final_verdict; cleanup; echo 0 > /sys/bus/pci/devices/0000:3b:00.1/sriov_numvfs 2>/dev/null; say "3PU_DONE RUN_ID=$RUN_ID logs in $O"; exit 0; }
fi
if [ "${SEAL_VERIFY:-0}" = "1" ]; then
  kill -s RTMIN+7 "$TPID" 2>/dev/null; sleep 1
  grep -qa "direct_write=FAULTED" "$SLOG" 2>/dev/null && mark integrity_wx_seal OPTIONAL PASS "direct write to sealed hook page faulted (SIGSEGV)" || mark integrity_wx_seal OPTIONAL FAIL "no SIGSEGV on sealed-page write"
fi
if [ "${TAMPER:-0}" = "1" ]; then
  HK=$(head -1 "$O/sealed_ranges.txt" 2>/dev/null | awk '{print $1}'); [ -z "$HK" ] && HK=$(printf '0x%x' $((CS+0x1000)))
  [ "${TAMPER_TARGET:-}" = "selector" ] && HK=$(grep -aoE "selector=0x[0-9a-f]+" "$O/imm_view.txt" | head -1 | cut -d= -f2)
  [ "${TAMPER_TARGET:-}" = "dispatch" ] && HK=$(grep -aoE "table=\[0x[0-9a-f]+" "$O/dispatch.txt" | head -1 | cut -d[ -f2)
  [ "${TAMPER_TARGET:-}" = "agentcode" ] && HK=$(grep -aE "^CODE_RANGE 0x[0-9a-f]+-0x[0-9a-f]+ r-xp .*/agent\.so" "$O/dispatch.txt" | head -1 | awk '{print $2}' | cut -d- -f1)
  [ "${TAMPER_TARGET:-}" = "jit" ] && HK=$(grep -aoE "code_region 0x[0-9a-f]+-0x[0-9a-f]+ r-xp \[anon\]" "$O/seal_targets.txt" | head -1 | awk '{print $2}' | cut -d- -f1)
  say "TAMPER target=${TAMPER_TARGET:-first-sealed} addr=$HK"
  "$IK/tamper_child" "$CGDIR/cgroup.procs" "$HK" > "$O/tamper.log" 2>&1; TRC=$?
  ALIVE=$(kill -0 $TPID 2>/dev/null && echo YES || echo NO)
  if grep -qa TAMPER_SURVIVED "$O/tamper.log"; then mark integrity_tamper OPTIONAL FAIL "tamper SURVIVED (addr $HK)"
  elif [ $TRC -gt 128 ]; then mark integrity_tamper OPTIONAL PASS "tamper_child SIGKILLed rc=$TRC; tenant alive=$ALIVE"
  else mark integrity_tamper OPTIONAL FAIL "tamper rc=$TRC"; fi
fi

python3 -I "$MG/chap_e_tools.py" timeline "$O/timeline_mgr.txt" "$W/testpmd.log" "$W/testpmd.log" > "$O/timeline.txt" 2>&1; TLR=$?
[ "$TLR" = 0 ] && mark launch_timeline REQUIRED PASS "$(grep TIMELINE_RESULT $O/timeline.txt)" || mark launch_timeline REQUIRED FAIL "$(grep -E 'TIMELINE_RESULT|STREAM_ORDER' $O/timeline.txt | tr '\n' ' ')"
echo "quit" >&3 2>/dev/null; exec 3>&- 2>/dev/null; sleep 2
if [ -n "${NICJ:-}${NICQ:-}" ]; then   # Request P: the sealed entry disappears with the process (no stale status for a later PID)
  for w in $(seq 1 20); do kill -0 $TPID 2>/dev/null || break; sleep 0.5; done
  TA=$(kill -0 $TPID 2>/dev/null && echo YES || echo NO); "$IK/chap_nicgate" dump "$PIND" > "$O/nicgate_after_exit.txt" 2>&1
  { [ "$TA" = NO ] && ! grep -q "^ENTRY pid=$TPID " "$O/nicgate_after_exit.txt"; } \
    && mark nicj_exit_clears_entry REQUIRED PASS "tenant $TPID exited -> entry removed ; $(tail -1 $O/nicgate_after_exit.txt)" \
    || mark nicj_exit_clears_entry REQUIRED FAIL "alive=$TA $(tr '\n' ' ' < $O/nicgate_after_exit.txt)"
fi
CREATED=$(grep -ac "Flow rule #[0-9]* created" "$W/testpmd.log"); say "post-exit testpmd created=$CREATED"
if [ "${RX_TEST:-0}" = "1" ]; then   # judged after quit (fwd stats + pool dumps are buffered stdout)
  python3 -I "$MG/chap_e_tools.py" rxapp "$W/testpmd.log" >> "$O/rx_phases.txt"
  python3 -I "$MG/chap_e_tools.py" rxjudge "$O/rx_phases.txt" > "$O/rx_judge.txt" 2>&1; RXJ=$?
  if [ "${RX_CHARACTERIZE:-0}" = "1" ]; then mark rx_characterization OPTIONAL INFO "$(tail -1 $O/rx_judge.txt)"
  else
    [ "$RXJ" = 0 ] && mark rx_window_exclusion REQUIRED PASS "$(tail -1 $O/rx_judge.txt)" || mark rx_window_exclusion REQUIRED FAIL "$(grep -E 'FAIL|RXJUDGE' $O/rx_judge.txt | tr '\n' ' ')"
  fi
fi
if [ "${TX_TEST:-0}" = "1" ]; then   # judged after quit: the tenant's buffered stdout (dump_mempool) is flushed now
  python3 -I "$MG/chap_e_tools.py" txmem "$W/testpmd.log" >> "$O/tx_phases.txt"
  python3 -I "$MG/chap_e_tools.py" txjudge "$O/tx_phases.txt" > "$O/tx_judge.txt" 2>&1; TXJ=$?
  if [ "${TX_CHARACTERIZE:-0}" = "1" ]; then mark tx_characterization OPTIONAL INFO "$(tail -1 $O/tx_judge.txt)"
  else
    [ "$TXJ" = 0 ] && mark tx_burst_exclusion REQUIRED PASS "$(tail -1 $O/tx_judge.txt)" || mark tx_burst_exclusion REQUIRED FAIL "$(grep -E 'FAIL|TXJUDGE' $O/tx_judge.txt | tr '\n' ' ')"
  fi
fi
final_verdict
cleanup; echo 0 > /sys/bus/pci/devices/0000:3b:00.1/sriov_numvfs 2>/dev/null
say "3PU_DONE RUN_ID=$RUN_ID logs in $O"

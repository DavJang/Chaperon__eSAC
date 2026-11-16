#!/bin/bash
# Demo: eSAC Tamper Sentinel (2-vector). A tenant that tries to regain write access to its
# RO-mapped hook/policy pages via mprotect(PROT_WRITE) or openat(/proc/self/mem) is SIGKILLed;
# the out-of-scope vectors (ptrace, process_vm_writev) and a benign tenant SURVIVE.
# Portable: any Linux host with root + bpftrace. Run from the repo root:  sudo bash demos/demo_tamper.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
SELF="$ROOT/Tamper_Sentinel/tamper_sentinel_selftest"
[ -x "$SELF" ] || { echo "missing $SELF  (build from Tamper_Sentinel/src/tamper_sentinel_selftest.c)"; exit 1; }
command -v bpftrace >/dev/null || { echo "need bpftrace (apt install bpftrace)"; exit 1; }

T="$(mktemp -d)"
printf '\n%-10s %-9s %-9s %s\n' VECTOR OUTCOME EXPECT VERDICT
declare -A EXP=( [mprotect]=KILL [procmem]=KILL [ptrace]=SURVIVE [vmwritev]=SURVIVE [none]=SURVIVE )
pass=0; tot=0
for vec in mprotect procmem ptrace vmwritev none; do
  sudo pkill -9 -x bpftrace 2>/dev/null; sleep 1
  "$SELF" "$vec" 6 > "$T/$vec.log" 2>&1 & sp=$!
  # the FINAL 2-vector sentinel: ONLY mprotect(RW) + openat(/proc/self/mem) -> signal(9)
  setsid sudo bpftrace --unsafe -e \
"tracepoint:syscalls:sys_enter_mprotect /pid==$sp && (args->prot & 2)/ { printf(\"[EVWD] mprotect_rw\\n\"); signal(9); }
tracepoint:syscalls:sys_enter_openat /pid==$sp/ { \$fn=str(args->filename); if(\$fn==\"/proc/self/mem\"){ printf(\"[EVWD] procmem\\n\"); signal(9); } }" \
    > "$T/$vec.wd" 2>&1 & wd=$!
  for i in $(seq 1 30); do grep -q Attaching "$T/$vec.wd" 2>/dev/null && break; sleep 0.5; done
  sleep 8                                  # selftest fires its syscall at t=6s (> attach time)
  # outcome: did the sentinel actually fire? Its printf lands at line start ("[EVWD] mprotect_rw");
  # anchor ^ so we don't false-match bpftrace echoing its own program source (printf("[EVWD]...))
  # in an Addrspace warning.
  got=SURVIVE; grep -qE '^\[EVWD\] (mprotect_rw|procmem)' "$T/$vec.wd" 2>/dev/null && got=KILL
  v=FAIL; [ "$got" = "${EXP[$vec]}" ] && { v=PASS; pass=$((pass+1)); }; tot=$((tot+1))
  printf '%-10s %-9s %-9s %s\n' "$vec" "$got" "${EXP[$vec]}" "$v"
  sudo pkill -9 -x bpftrace 2>/dev/null; sudo kill -9 $sp 2>/dev/null; sleep 1
done
rm -rf "$T"
echo; echo "Tamper Sentinel demo: $pass/$tot as expected"

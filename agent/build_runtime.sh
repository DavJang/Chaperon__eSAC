#!/bin/bash
# Build the Chaperon Agent runtime: libbpftime-agent.so + libbpftime-syscall-server.so.
#
#   BPFTIME_SRC    bpftime source tree at upstream commit edcc8ec with agent/patches/*.patch applied
#   BPFTIME_BUILD  completed CMake build of BPFTIME_SRC (compile_commands.json, runtime/libruntime.a and the
#                  link.txt files of the agent and syscall-server targets are used)
#   OUT            output directory; must not exist yet (default: agent/build)
#
# The six Chaperon sources in agent/src are compiled with the exact compile commands of the upstream files they
# replace (taken from compile_commands.json), inserted into a COPY of libruntime.a, and the agent library is
# relinked with full RELRO (-z now -z relro). BPFTIME_SRC and BPFTIME_BUILD are not modified.
set -eu
A=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${BPFTIME_SRC:?set BPFTIME_SRC}"; : "${BPFTIME_BUILD:?set BPFTIME_BUILD}"
BPFTIME_SRC=$(cd "$BPFTIME_SRC" && pwd); BPFTIME_BUILD=$(cd "$BPFTIME_BUILD" && pwd)
OUT=${OUT:-$A/build}
[ -e "$OUT" ] && { echo "OUT=$OUT already exists; choose a new directory" >&2; exit 1; }
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)

python3 - "$BPFTIME_BUILD/compile_commands.json" "$OUT" <<'PY'
import json, sys
db = json.load(open(sys.argv[1])); out = sys.argv[2]
want = {"runtime/src/bpf_map/shared/array_map_kernel_user.cpp": "cc_array", "runtime/src/ufunc.cpp": "cc_ufunc",
        "runtime/src/bpf_helper.cpp": "cc_helper", "runtime/src/bpftime_shm.cpp": "cc_shm",
        "runtime/src/attach/bpf_attach_ctx.cpp": "cc_attachctx", "runtime/agent/agent.cpp": "cc_agent"}
got = set()
for e in db:
    for k, v in want.items():
        if e["file"].endswith(k):
            open(f"{out}/{v}.txt", "w").write(e["command"]); open(f"{out}/{v}.dir", "w").write(e["directory"]); got.add(v)
missing = sorted(set(want.values()) - got)
if missing: sys.exit("compile commands not found: %s" % missing)
PY

comp() {  # $1=command name  $2=upstream source (relative to BPFTIME_SRC)  $3=Chaperon source  $4=object  [$5=extra flags]
  local CMD DIR; CMD=$(cat "$OUT/$1.txt"); DIR=$(cat "$OUT/$1.dir")
  case "$CMD" in *"$BPFTIME_SRC/$2"*) ;; *) echo "compile command for $2 does not name $BPFTIME_SRC/$2" >&2; exit 1;; esac
  CMD=${CMD//$BPFTIME_SRC\/$2/$3}
  CMD=$(echo "$CMD" | sed -E "s# -o [^ ]+$4# -o $OUT/$4#")
  ( cd "$DIR" && eval "$CMD ${5:-}" ); echo "  $4 -> $(stat -c%s "$OUT/$4") bytes"
}
echo "== compile the six Chaperon sources"
comp cc_array     runtime/src/bpf_map/shared/array_map_kernel_user.cpp "$A/src/array_map_kernel_user.cpp" array_map_kernel_user.cpp.o
comp cc_ufunc     runtime/src/ufunc.cpp           "$A/src/ufunc.cpp"           ufunc.cpp.o
comp cc_helper    runtime/src/bpf_helper.cpp      "$A/src/bpf_helper.cpp"      bpf_helper.cpp.o
comp cc_shm       runtime/src/bpftime_shm.cpp     "$A/src/bpftime_shm.cpp"     bpftime_shm.cpp.o
comp cc_attachctx runtime/src/attach/bpf_attach_ctx.cpp "$A/src/bpf_attach_ctx.cpp" bpf_attach_ctx.cpp.o "-I$BPFTIME_SRC/attach/frida_uprobe_attach_impl/include"
comp cc_agent     runtime/agent/agent.cpp         "$A/src/agent.cpp"           agent.cpp.o

echo "== update a copy of libruntime.a"
cp "$BPFTIME_BUILD/runtime/libruntime.a" "$OUT/libruntime.a"
ar t "$OUT/libruntime.a" > "$OUT/libruntime.members"
grep -qx "bpf_attach_ctx.cpp.o" "$OUT/libruntime.members" || { echo "bpf_attach_ctx.cpp.o not in libruntime.a" >&2; exit 1; }
ar r "$OUT/libruntime.a" "$OUT/array_map_kernel_user.cpp.o" "$OUT/ufunc.cpp.o" "$OUT/bpf_helper.cpp.o" "$OUT/bpftime_shm.cpp.o" "$OUT/bpf_attach_ctx.cpp.o"

echo "== relink the agent (full RELRO) and the syscall-server"
LINK=$(cat "$BPFTIME_BUILD/runtime/agent/CMakeFiles/bpftime-agent.dir/link.txt")
LINK=${LINK//CMakeFiles\/bpftime-agent.dir\/agent.cpp.o/$OUT/agent.cpp.o}; LINK=${LINK//..\/libruntime.a/$OUT/libruntime.a}
LINK=$(echo "$LINK" | sed -E "s#-o libbpftime-agent.so#-o $OUT/libbpftime-agent.so#")
( cd "$BPFTIME_BUILD/runtime/agent" && eval "$LINK -Wl,-z,now -Wl,-z,relro" )
LINK=$(cat "$BPFTIME_BUILD/runtime/syscall-server/CMakeFiles/bpftime-syscall-server.dir/link.txt")
LINK=${LINK//..\/libruntime.a/$OUT/libruntime.a}
LINK=$(echo "$LINK" | sed -E "s#-o libbpftime-syscall-server.so#-o $OUT/libbpftime-syscall-server.so#")
( cd "$BPFTIME_BUILD/runtime/syscall-server" && eval "$LINK" )
readelf -d "$OUT/libbpftime-agent.so" | grep -E "FLAGS|BIND_NOW" || true
echo "RUNTIME_BUILD_DONE"
sha256sum "$OUT/libbpftime-agent.so" "$OUT/libbpftime-syscall-server.so"
